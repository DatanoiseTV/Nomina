//! Nomina — a split-horizon authoritative + forwarding DNS server with a web UI.

// The DB/web layers have a few functions with many positional parameters and
// boxed-trait-object query argument vectors; factoring these into structs/type
// aliases would add indirection without improving clarity.
#![allow(clippy::too_many_arguments, clippy::type_complexity)]

mod config;
mod db;
mod dns;
mod error;
mod filter;
mod geo;
mod models;
mod net;
mod privileges;
mod schema;
mod state;
mod stats;
mod store;
mod tls;
mod web;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

use crate::config::Config;
use crate::db::Db;
use crate::dns::handler::DnsHandler;
use crate::dns::upstream::Upstream;
use crate::filter::FilterSet;
use crate::state::{AppState, SharedState};
use crate::store::ZoneStore;

#[derive(Parser, Debug)]
#[command(
    name = "nomina",
    version,
    about = "Split-horizon DNS server for homelabs"
)]
struct Cli {
    /// Path to a TOML configuration file.
    #[arg(short, long, env = "NOMINA_CONFIG")]
    config: Option<PathBuf>,

    /// Data directory (database, generated TLS cert).
    #[arg(long, env = "NOMINA_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Plain DNS listen address (repeatable), e.g. 0.0.0.0:53.
    #[arg(long = "dns-listen")]
    dns_listen: Vec<SocketAddr>,

    /// DNS-over-TLS listen address (repeatable), e.g. 0.0.0.0:853.
    #[arg(long = "dot-listen")]
    dot_listen: Vec<SocketAddr>,

    /// DNS-over-HTTPS listen address (repeatable), e.g. 0.0.0.0:443.
    #[arg(long = "doh-listen")]
    doh_listen: Vec<SocketAddr>,

    /// DNS-over-QUIC listen address (repeatable), e.g. 0.0.0.0:853.
    #[arg(long = "doq-listen")]
    doq_listen: Vec<SocketAddr>,

    /// DNS-over-HTTP/3 listen address (repeatable), e.g. 0.0.0.0:443.
    #[arg(long = "doh3-listen")]
    doh3_listen: Vec<SocketAddr>,

    /// Management UI/API listen address, e.g. 0.0.0.0:8053.
    #[arg(long = "web-listen")]
    web_listen: Option<SocketAddr>,

    /// Serve the management interface over HTTPS.
    #[arg(long = "web-tls")]
    web_tls: bool,

    /// Hostname for the generated TLS certificate / DoH SNI.
    #[arg(long)]
    hostname: Option<String>,

    /// Log filter (e.g. "info", "nomina=debug").
    #[arg(long, env = "NOMINA_LOG")]
    log: Option<String>,
}

fn apply_overrides(mut config: Config, cli: &Cli) -> Config {
    if let Some(d) = &cli.data_dir {
        config.data_dir = d.clone();
    }
    if !cli.dns_listen.is_empty() {
        config.dns.listen = cli.dns_listen.clone();
    }
    if !cli.dot_listen.is_empty() {
        config.dns.dot_listen = cli.dot_listen.clone();
    }
    if !cli.doh_listen.is_empty() {
        config.dns.doh_listen = cli.doh_listen.clone();
    }
    if !cli.doq_listen.is_empty() {
        config.dns.doq_listen = cli.doq_listen.clone();
    }
    if !cli.doh3_listen.is_empty() {
        config.dns.doh3_listen = cli.doh3_listen.clone();
    }
    if let Some(w) = cli.web_listen {
        config.web.listen = w;
    }
    if cli.web_tls {
        config.web.tls = true;
    }
    if let Some(h) = &cli.hostname {
        config.tls.hostname = h.clone();
    }
    if let Some(l) = &cli.log {
        config.log = l.clone();
    }
    config
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = apply_overrides(Config::load(cli.config.as_deref())?, &cli);
    let config = Arc::new(config);

    init_tracing(&config.log);

    // One process-wide crypto provider (ring) for rustls — used by the web UI,
    // DoT, DoH, and any TLS upstream forwarders.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    std::fs::create_dir_all(&config.data_dir).ok();

    // Database + bootstrap.
    let db = Db::open(&config.database_path())?;
    let settings = db.with(|c| {
        Db::ensure_default_view(c)?;
        let s = Db::get_settings(c)?;
        Db::put_settings(c, &s)?; // persist defaults on first run
        Ok(s)
    })?;

    // In-memory authoritative store, upstream resolver, and filter set.
    let store = ZoneStore::load(&db)?;
    let upstream = match Upstream::build(&settings) {
        Ok(up) => up,
        Err(e) => {
            tracing::warn!("upstream resolution disabled: {e}");
            None
        }
    };
    let filter = FilterSet::load(&db, settings.blocking_enabled)?;
    let conditional = dns::conditional::ConditionalSet::load(&db, &settings)?;

    // Channel feeding the async query-log writer (bounded; drops under backpressure).
    let (qlog_tx, mut qlog_rx) = tokio::sync::mpsc::channel::<crate::stats::RecentQuery>(10_000);

    let state: SharedState = Arc::new(AppState::new(
        db,
        config.clone(),
        store,
        upstream,
        conditional,
        filter,
        settings.clone(),
        qlog_tx,
    ));

    // Background query-log writer: batch-insert and cap the table size.
    {
        let db = state.db.clone();
        tokio::spawn(async move {
            const MAX_ROWS: i64 = 500_000;
            let mut buf: Vec<crate::stats::RecentQuery> = Vec::new();
            loop {
                let n = qlog_rx.recv_many(&mut buf, 500).await;
                if n == 0 {
                    break;
                }
                let entries = std::mem::take(&mut buf);
                if let Err(e) = db.run_mut(move |c| Db::insert_queries(c, &entries)).await {
                    tracing::warn!("query-log write failed: {e}");
                }
                let _ = db.run(move |c| Db::prune_query_log(c, MAX_ROWS)).await;
            }
        });
    }

    // Periodically purge expired sessions.
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                tick.tick().await;
                let _ = state.db.run(Db::prune_sessions).await;
            }
        });
    }

    // Refresh secondary zones from their primaries on an SOA-driven schedule.
    tokio::spawn(dns::secondary::poll_loop(state.clone()));

    // TLS material (shared by web/DoT/DoH/DoQ) if any TLS listener is enabled.
    let (web_tls, dot_tls, doh_tls, doq_tls, doh3_tls) = if config.tls_required() {
        let material = tls::load_or_generate(&config)?;
        let web = if config.web.tls {
            Some(tls::server_config(&material, &[b"h2", b"http/1.1"])?)
        } else {
            None
        };
        let dot = if config.dns.dot_listen.is_empty() {
            None
        } else {
            Some(tls::server_config(&material, &[b"dot"])?)
        };
        let doh = if config.dns.doh_listen.is_empty() {
            None
        } else {
            // Our DoH endpoint serves both HTTP/2 and HTTP/1.1.
            Some(tls::server_config(&material, &[b"h2", b"http/1.1"])?)
        };
        let doq = if config.dns.doq_listen.is_empty() {
            None
        } else {
            // DNS-over-QUIC (RFC 9250) uses ALPN "doq".
            Some(tls::server_config(&material, &[b"doq"])?)
        };
        let doh3 = if config.dns.doh3_listen.is_empty() {
            None
        } else {
            // DNS-over-HTTP/3 uses ALPN "h3".
            Some(tls::server_config(&material, &[b"h3"])?)
        };
        (web, dot, doh, doq, doh3)
    } else {
        (None, None, None, None, None)
    };

    // ---- Bind all listeners while still privileged ----
    let dns_sockets = dns::server::bind(&config).await?;

    let web_listener = if config.web.disabled {
        None
    } else {
        Some(
            net::bind_tcp(config.web.listen)
                .map_err(|e| anyhow::anyhow!("binding web {}: {e}", config.web.listen))?,
        )
    };

    let mut doh_listeners = Vec::new();
    if doh_tls.is_some() {
        for addr in &config.dns.doh_listen {
            let listener =
                net::bind_tcp(*addr).map_err(|e| anyhow::anyhow!("binding DoH {addr}: {e}"))?;
            doh_listeners.push((*addr, listener));
        }
    }

    // ---- Drop privileges now that privileged sockets are bound ----
    privileges::drop_privileges(&config.privileges)?;

    // ---- Spawn servers ----
    let dns_handler = DnsHandler::new(state.clone());
    let dns_config = config.clone();
    let dns_task = tokio::spawn(async move {
        if let Err(e) = dns::server::run(
            dns_config,
            dns_handler,
            dns_sockets,
            dot_tls,
            doq_tls,
            doh3_tls,
        )
        .await
        {
            tracing::error!("DNS server stopped: {e}");
        }
    });

    if let Some(doh_cfg) = doh_tls {
        for (addr, listener) in doh_listeners {
            let router = dns::doh::router(state.clone());
            let cfg = doh_cfg.clone();
            tracing::info!("DNS-over-HTTPS listening on {addr}/dns-query");
            tokio::spawn(async move {
                if let Err(e) = web::serve_tls(listener, router, cfg).await {
                    tracing::error!("DoH server stopped on {addr}: {e}");
                }
            });
        }
    }

    let web_task = match web_listener {
        None => {
            tracing::info!("management interface disabled");
            None
        }
        Some(listener) => {
            let app = web::router(state.clone());
            let web_addr = config.web.listen;
            let scheme = if config.web.tls { "https" } else { "http" };
            tracing::info!("management interface on {scheme}://{web_addr}");
            Some(tokio::spawn(async move {
                let result = match web_tls {
                    Some(cfg) => web::serve_tls(listener, app, cfg).await,
                    None => web::serve_plain(listener, app).await,
                };
                if let Err(e) = result {
                    tracing::error!("web server stopped: {e}");
                }
            }))
        }
    };

    tracing::info!("Nomina {} started", env!("CARGO_PKG_VERSION"));

    // Run until a fatal task exit or Ctrl-C.
    tokio::select! {
        _ = dns_task => tracing::error!("DNS task exited"),
        _ = async {
            if let Some(t) = web_task {
                let _ = t.await;
            } else {
                std::future::pending::<()>().await
            }
        } => tracing::error!("web task exited"),
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
    }

    Ok(())
}

fn init_tracing(filter: &str) {
    use tracing_subscriber::EnvFilter;
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(filter))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .init();
}
