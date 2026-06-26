//! Binds the DNS listeners (UDP/TCP, DoT, DoH) and drives the hickory server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use hickory_server::Server;
use rustls::ServerConfig;
use tokio::net::{TcpListener, UdpSocket};

use crate::config::Config;
use crate::dns::handler::DnsHandler;

/// Pre-bound DNS sockets. Binding happens while still privileged; running
/// happens after privileges are dropped.
pub struct DnsSockets {
    plain: Vec<(SocketAddr, UdpSocket, TcpListener)>,
    dot: Vec<(SocketAddr, TcpListener)>,
}

/// Bind all plain (UDP/TCP) and DoT sockets. Call this before dropping privileges.
pub async fn bind(config: &Config) -> anyhow::Result<DnsSockets> {
    let mut plain = Vec::new();
    for addr in &config.dns.listen {
        let udp = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("binding UDP {addr}"))?;
        let tcp = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding TCP {addr}"))?;
        plain.push((*addr, udp, tcp));
    }
    let mut dot = Vec::new();
    for addr in &config.dns.dot_listen {
        let tcp = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding DoT {addr}"))?;
        dot.push((*addr, tcp));
    }
    Ok(DnsSockets { plain, dot })
}

/// Describes one active listener for the status API.
#[derive(Clone, serde::Serialize)]
pub struct ListenerInfo {
    pub kind: String,
    pub addr: String,
    pub enabled: bool,
}

/// Run the DNS server on pre-bound sockets until the process stops. DoH is
/// served separately by the axum-based [`crate::dns::doh`] endpoint.
pub async fn run(
    config: Arc<Config>,
    handler: DnsHandler,
    sockets: DnsSockets,
    dot_config: Option<Arc<ServerConfig>>,
) -> anyhow::Result<()> {
    let timeout = Duration::from_secs(config.dns.tcp_timeout_secs);
    let mut server = Server::new(handler);

    for (addr, udp, tcp) in sockets.plain {
        server.register_socket(udp);
        server.register_listener(tcp, timeout, 100);
        tracing::info!("DNS listening on {addr} (UDP+TCP)");
    }

    match &dot_config {
        Some(tls) => {
            for (addr, tcp) in sockets.dot {
                server
                    .register_tls_listener_with_tls_config(tcp, timeout, tls.clone())
                    .with_context(|| format!("registering DoT {addr}"))?;
                tracing::info!("DNS-over-TLS listening on {addr}");
            }
        }
        None if !sockets.dot.is_empty() => {
            tracing::warn!("DoT listeners configured but no TLS material; skipping");
        }
        None => {}
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
