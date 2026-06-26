//! Binds the DNS listeners (UDP/TCP, DoT, DoH) and drives the hickory server.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use hickory_server::Server;
use rustls::ServerConfig;
use tokio::net::{TcpListener, UdpSocket};

use crate::config::Config;
use crate::dns::handler::DnsHandler;

/// Describes one active listener for the status API.
#[derive(Clone, serde::Serialize)]
pub struct ListenerInfo {
    pub kind: String,
    pub addr: String,
    pub enabled: bool,
}

/// Bind all configured DNS listeners and run until the process stops.
/// `dot_config`/`doh_config` are the TLS configs for the encrypted transports.
pub async fn run(
    config: Arc<Config>,
    handler: DnsHandler,
    dot_config: Option<Arc<ServerConfig>>,
    doh_config: Option<Arc<ServerConfig>>,
) -> anyhow::Result<()> {
    let timeout = Duration::from_secs(config.dns.tcp_timeout_secs);
    let mut server = Server::new(handler);

    for addr in &config.dns.listen {
        let udp = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("binding UDP {addr}"))?;
        server.register_socket(udp);

        let tcp = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding TCP {addr}"))?;
        server.register_listener(tcp, timeout, 100);
        tracing::info!("DNS listening on {addr} (UDP+TCP)");
    }

    if let Some(tls) = &dot_config {
        for addr in &config.dns.dot_listen {
            let tcp = TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding DoT {addr}"))?;
            server
                .register_tls_listener_with_tls_config(tcp, timeout, tls.clone())
                .with_context(|| format!("registering DoT {addr}"))?;
            tracing::info!("DNS-over-TLS listening on {addr}");
        }
    }

    if let Some(tls) = &doh_config {
        for addr in &config.dns.doh_listen {
            let tcp = TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding DoH {addr}"))?;
            server
                .register_https_listener_with_tls_config(
                    tcp,
                    timeout,
                    tls.clone(),
                    Some(config.tls.hostname.clone()),
                    config.dns.doh_path.clone(),
                )
                .with_context(|| format!("registering DoH {addr}"))?;
            tracing::info!(
                "DNS-over-HTTPS listening on {addr}{}",
                config.dns.doh_path
            );
        }
    }

    server.block_until_done().await.context("DNS server failed")?;
    Ok(())
}

/// Enumerate configured listeners for the status endpoint.
pub fn listener_infos(config: &Config) -> Vec<ListenerInfo> {
    let mut out = Vec::new();
    for addr in &config.dns.listen {
        out.push(ListenerInfo {
            kind: "udp".into(),
            addr: addr.to_string(),
            enabled: true,
        });
        out.push(ListenerInfo {
            kind: "tcp".into(),
            addr: addr.to_string(),
            enabled: true,
        });
    }
    for addr in &config.dns.dot_listen {
        out.push(ListenerInfo {
            kind: "dot".into(),
            addr: addr.to_string(),
            enabled: true,
        });
    }
    for addr in &config.dns.doh_listen {
        out.push(ListenerInfo {
            kind: "doh".into(),
            addr: addr.to_string(),
            enabled: true,
        });
    }
    out
}
