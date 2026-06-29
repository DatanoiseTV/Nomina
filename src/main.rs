//! Nomina — a split-horizon authoritative + forwarding DNS server with a web UI.

// The DB/web layers have a few functions with many positional parameters and
// boxed-trait-object query argument vectors; factoring these into structs/type
// aliases would add indirection without improving clarity.
#![allow(clippy::too_many_arguments, clippy::type_complexity)]

mod config;
mod db;
mod dhcp;
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

/// Overlay UI-managed settings (stored in the DB) onto the config file. These
/// are bound/loaded at startup, so changing them in the UI takes effect on the
/// next restart. An empty/None setting leaves the config-file value untouched.
fn apply_settings_to_config(config: &mut Config, s: &models::Settings) {
    use std::net::SocketAddr;
    use std::path::PathBuf;
    fn addrs(v: &[String]) -> Vec<SocketAddr> {
        v.iter()
            .filter_map(|a| match a.trim().parse::<SocketAddr>() {
                Ok(sa) => Some(sa),
                Err(_) => {
                    tracing::warn!("ignoring invalid listen address {a:?}");
                    None
                }
            })
            .collect()
    }
    // Listeners
    if !s.dns_listen.is_empty() {
        config.dns.listen = addrs(&s.dns_listen);
    }
    if !s.dot_listen.is_empty() {
        config.dns.dot_listen = addrs(&s.dot_listen);
    }
    if !s.doh_listen.is_empty() {
        config.dns.doh_listen = addrs(&s.doh_listen);
    }
    if !s.doq_listen.is_empty() {
        config.dns.doq_listen = addrs(&s.doq_listen);
    }
    if !s.doh3_listen.is_empty() {
        config.dns.doh3_listen = addrs(&s.doh3_listen);
    }
    if !s.doh_path.trim().is_empty() {
        config.dns.doh_path = s.doh_path.trim().to_string();
    }
    if s.tcp_timeout_secs > 0 {
        config.dns.tcp_timeout_secs = s.tcp_timeout_secs as u64;
    }
    // TLS
    if !s.tls_hostname.trim().is_empty() {
        config.tls.hostname = s.tls_hostname.trim().to_string();
    }
    config.tls.acme = config.tls.acme || s.tls_acme;
    config.tls.acme_staging = config.tls.acme_staging || s.tls_acme_staging;
    if !s.tls_acme_domains.is_empty() {
        config.tls.acme_domains = s.tls_acme_domains.clone();
    }
    if !s.tls_acme_contact.trim().is_empty() {
        config.tls.acme_contact = Some(s.tls_acme_contact.trim().to_string());
    }
    if !s.tls_cert_path.trim().is_empty() {
        config.tls.cert_path = Some(PathBuf::from(s.tls_cert_path.trim()));
    }
    if !s.tls_key_path.trim().is_empty() {
        config.tls.key_path = Some(PathBuf::from(s.tls_key_path.trim()));
    }
    if let Some(v) = s.tls_auto_self_signed {
        config.tls.auto_self_signed = v;
    }
    // GeoIP
    if !s.geoip_db.trim().is_empty() {
        config.geo.geoip_db = Some(PathBuf::from(s.geoip_db.trim()));
    }
    if !s.asn_db.trim().is_empty() {
        config.geo.asn_db = Some(PathBuf::from(s.asn_db.trim()));
    }
    // Management allow-list
    if !s.web_allow_networks.is_empty() {
        config.web.allow_networks = s.web_allow_networks.clone();
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut config = apply_overrides(Config::load(cli.config.as_deref())?, &cli);

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

    // Settings managed in the web UI (listeners, TLS, GeoIP, allow-list) override
    // the config file. They bind sockets / load databases at startup, so changing
    // them in the UI takes effect on the next restart.
    apply_settings_to_config(&mut config, &settings);
    let config = Arc::new(config);

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
    // Channel feeding the blocked-domain geolocation worker (bounded; drops too).
    let (blocked_tx, mut blocked_rx) = tokio::sync::mpsc::channel::<String>(4096);

    let state: SharedState = Arc::new(AppState::new(
        db,
        config.clone(),
        store,
        upstream,
        conditional,
        filter,
        settings.clone(),
        qlog_tx,
        blocked_tx,
    ));

    // Background worker: resolve blocked domains (deduped, best-effort) just to
    // geolocate where the ad/tracker servers live, for the map's red layer. Only
    // runs when a GeoIP City database is loaded (otherwise the points are useless).
    {
        use hickory_proto::rr::{RData, RecordType};
        let state = state.clone();
        tokio::spawn(async move {
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            while let Some(domain) = blocked_rx.recv().await {
                if !state.geo().has_geoip() {
                    continue;
                }
                if seen.len() >= 8192 {
                    seen.clear(); // periodic reset so long-lived processes re-confirm
                }
                if !seen.insert(domain.clone()) {
                    continue; // already geolocated this domain
                }
                let Some(up) = state.upstream() else { continue };
                let Ok(name) = hickory_proto::rr::Name::from_ascii(format!("{domain}.")) else {
                    continue;
                };
                let r = up.resolve(&name, RecordType::A).await;
                for rec in &r.answers {
                    if let RData::A(a) = &rec.data {
                        state.stats.record_blocked_dest(std::net::IpAddr::V4(a.0));
                    }
                }
            }
        });
    }

    // Determine the server's own location (public IP -> GeoIP) for the
    // "distance travelled" counter. Best-effort; needs a GeoIP City database.
    {
        let state = state.clone();
        tokio::spawn(async move {
            if !state.geo().has_geoip() {
                return;
            }
            for attempt in 0..6u32 {
                if let Some(ip) = web::fetch::public_ip().await {
                    let g = state.geo().lookup(ip);
                    if let (Some(lat), Some(lon)) = (g.lat, g.lon) {
                        state.stats.set_origin(crate::stats::OriginGeo {
                            ip: ip.to_string(),
                            lat,
                            lon,
                            city: g.city.unwrap_or_default(),
                            country: g.country.unwrap_or_default(),
                        });
                        tracing::info!("server location for distance counter: {ip}");
                        return;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(15 * (attempt + 1) as u64)).await;
            }
        });
    }

    // Periodic blocklist auto-refresh (re-download enabled lists every N hours,
    // per the runtime setting; 0 = disabled). Re-reads the interval each cycle.
    {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                let hours = state.blocklist_refresh_hours();
                if hours == 0 {
                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                    continue;
                }
                tokio::time::sleep(std::time::Duration::from_secs(hours as u64 * 3600)).await;
                if state.blocklist_refresh_hours() > 0 {
                    tracing::info!("auto-refreshing blocklists");
                    web::api::refresh_all_lists(&state).await;
                }
            }
        });
    }

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

    // Restore the edge cache persisted at the last shutdown (warm start).
    let cache_path = config.data_dir.join("dns-cache.json");
    let restored = state.cache().load(&cache_path);
    if restored > 0 {
        tracing::info!(
            "restored {restored} cached answers from {}",
            cache_path.display()
        );
    }

    // ---- Bind all listeners while still privileged ----
    let dns_sockets = dns::server::bind(&config).await?;

    // DHCP sockets (ports 67/547 are privileged). No-op when unconfigured.
    // Gather the interfaces that enabled DHCPv4 scopes are pinned to, so the
    // server can bind a per-interface socket for directly-connected VLAN clients.
    let scope_interfaces: Vec<String> = {
        use crate::models::IpFamily;
        let scopes = state
            .db
            .run(db::Db::list_dhcp_scopes)
            .await
            .unwrap_or_default();
        let mut ifaces: Vec<String> = scopes
            .into_iter()
            .filter(|s| s.enabled && s.family == IpFamily::V4)
            .filter_map(|s| s.interface)
            .collect();
        ifaces.sort();
        ifaces.dedup();
        ifaces
    };
    let dhcp_sockets = dhcp::server::bind(&config, &scope_interfaces)?;

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

    // ---- mDNS discovery supervisor (starts/stops with the runtime setting;
    //      port 5353 is unprivileged) ----
    tokio::spawn(dns::mdns::supervise(state.clone()));

    // ---- DHCP server + lease sweeper (no-ops when unconfigured) ----
    if !dhcp_sockets.is_empty() {
        dhcp::server::run(state.clone(), dhcp_sockets).await;
        // Sweep expired leases on a one-minute cadence.
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                let now = time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default();
                if let Err(e) = state
                    .db
                    .run(move |c| Db::prune_expired_leases(c, &now))
                    .await
                {
                    tracing::warn!("DHCP lease sweep failed: {e}");
                }
            }
        });
    }

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
            let use_acme = config.tls.acme && config.web.tls;
            let scheme = if config.web.tls { "https" } else { "http" };
            if use_acme {
                let domains = if config.tls.acme_domains.is_empty() {
                    vec![config.tls.hostname.clone()]
                } else {
                    config.tls.acme_domains.clone()
                };
                let contact: Vec<String> = config
                    .tls
                    .acme_contact
                    .iter()
                    .map(|e| format!("mailto:{e}"))
                    .collect();
                let staging = config.tls.acme_staging;
                let cache_dir = config.data_dir.join("acme");
                tracing::info!(
                    "management interface on https://{web_addr} (ACME for {domains:?}{})",
                    if staging { ", staging" } else { "" }
                );
                Some(tokio::spawn(async move {
                    if let Err(e) =
                        web::serve_tls_acme(listener, app, domains, contact, staging, cache_dir)
                            .await
                    {
                        tracing::error!("web server stopped: {e}");
                    }
                }))
            } else {
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
        }
    };

    tracing::info!("Nomina {} started", env!("CARGO_PKG_VERSION"));

    // Run until a fatal task exit or a shutdown signal (SIGINT/SIGTERM).
    tokio::select! {
        _ = dns_task => tracing::error!("DNS task exited"),
        _ = async {
            if let Some(t) = web_task {
                let _ = t.await;
            } else {
                std::future::pending::<()>().await
            }
        } => tracing::error!("web task exited"),
        _ = shutdown_signal() => tracing::info!("shutdown signal received"),
    }

    // Best-effort graceful drain: flush the query-log buffer and checkpoint the
    // database before exit so a SIGTERM (systemd/Docker/k8s) doesn't lose state.
    tracing::info!("draining and shutting down");
    match state.cache().save(&cache_path) {
        Ok(n) => tracing::info!("persisted {n} cached answers to {}", cache_path.display()),
        Err(e) => tracing::warn!("could not persist cache: {e}"),
    }
    let _ = state.db.with(|c| {
        use diesel::connection::SimpleConnection;
        c.batch_execute("PRAGMA wal_checkpoint(TRUNCATE);").ok();
        Ok(())
    });
    Ok(())
}

/// Resolve when the process is asked to stop: Ctrl-C (SIGINT) on any platform,
/// or SIGTERM on Unix (how systemd, Docker, and Kubernetes request shutdown).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
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
