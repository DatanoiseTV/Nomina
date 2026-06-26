//! PicoNS — a split-horizon authoritative + forwarding DNS server with a web UI.

mod config;
mod db;
mod dns;
mod error;
mod filter;
mod models;
mod state;
mod stats;
mod store;
mod tls;
mod web;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;

use crate::config::Config;
use crate::db::Db;
use crate::dns::handler::DnsHandler;
use crate::dns::upstream::Upstream;
use crate::filter::FilterSet;
use crate::state::{AppState, SharedState};
use crate::store::ZoneStore;

#[derive(Parser, Debug)]
#[command(name = "picons", version, about = "Split-horizon DNS server for homelabs")]
struct Cli {
    /// Path to a TOML configuration file.
    #[arg(short, long, env = "PICONS_CONFIG")]
    config: Option<PathBuf>,

    /// Data directory (database, generated TLS cert).
    #[arg(long, env = "PICONS_DATA_DIR")]
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

    /// Management UI/API listen address, e.g. 0.0.0.0:8053.
    #[arg(long = "web-listen")]
    web_listen: Option<SocketAddr>,

    /// Serve the management interface over HTTPS.
    #[arg(long = "web-tls")]
    web_tls: bool,

    /// Hostname for the generated TLS certificate / DoH SNI.
    #[arg(long)]
    hostname: Option<String>,

    /// Log filter (e.g. "info", "picons=debug").
    #[arg(long, env = "PICONS_LOG")]
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

    let state: SharedState = Arc::new(AppState::new(
        db,
        config.clone(),
        store,
        upstream,
        filter,
        settings.clone(),
    ));

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

    // TLS material (shared by web/DoT/DoH) if any TLS listener is enabled.
    let (web_tls, dot_tls, doh_tls) = if config.tls_required() {
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
        (web, dot, doh)
    } else {
        (None, None, None)
    };

    // DNS server task (UDP/TCP + DoT).
    let dns_handler = DnsHandler::new(state.clone());
    let dns_config = config.clone();
    let dns_task = tokio::spawn(async move {
        if let Err(e) = dns::server::run(dns_config, dns_handler, dot_tls).await {
            tracing::error!("DNS server stopped: {e}");
        }
    });

    // DoH listeners (our own RFC 8484 endpoint, GET + POST).
    if let Some(doh_cfg) = doh_tls {
        for addr in &config.dns.doh_listen {
            let listener = TcpListener::bind(addr).await?;
            let router = dns::doh::router(state.clone());
            let cfg = doh_cfg.clone();
            let addr = *addr;
            tracing::info!("DNS-over-HTTPS listening on {addr}/dns-query");
            tokio::spawn(async move {
                if let Err(e) = web::serve_tls(listener, router, cfg).await {
                    tracing::error!("DoH server stopped on {addr}: {e}");
                }
            });
        }
    }

    // Web server task.
    let web_task = if config.web.disabled {
        tracing::info!("management interface disabled");
        None
    } else {
        let app = web::router(state.clone());
        let web_addr = config.web.listen;
        let scheme = if config.web.tls { "https" } else { "http" };
        let listener = TcpListener::bind(web_addr).await?;
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
    };

    tracing::info!("PicoNS {} started", env!("CARGO_PKG_VERSION"));

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
