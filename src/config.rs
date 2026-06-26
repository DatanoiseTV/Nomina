//! Startup configuration: a TOML file plus CLI/env overrides.
//!
//! Listen sockets and TLS material are startup config (changing them needs a
//! restart); zones, records, views and forwarders are managed at runtime via the
//! API and stored in the database.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Directory for the database, generated TLS cert, etc.
    pub data_dir: PathBuf,
    /// Explicit database path; defaults to `<data_dir>/picons.db`.
    pub database_path: Option<PathBuf>,
    /// `tracing` env-filter string.
    pub log: String,
    pub dns: DnsConfig,
    pub web: WebConfig,
    pub tls: TlsConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    /// Addresses to serve plain DNS on (both UDP and TCP).
    pub listen: Vec<SocketAddr>,
    /// DNS-over-TLS listen addresses (requires TLS material).
    pub dot_listen: Vec<SocketAddr>,
    /// DNS-over-HTTPS listen addresses (requires TLS material).
    pub doh_listen: Vec<SocketAddr>,
    /// HTTP path the DoH endpoint answers on.
    pub doh_path: String,
    /// Idle timeout for TCP/DoT connections, seconds.
    pub tcp_timeout_secs: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebConfig {
    /// Management UI/API listen address.
    pub listen: SocketAddr,
    /// Serve the management interface over HTTPS (recommended).
    pub tls: bool,
    /// Disable the management interface entirely.
    pub disabled: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM certificate chain path. If unset and TLS is needed, a self-signed
    /// certificate is generated under `data_dir`.
    pub cert_path: Option<PathBuf>,
    /// PEM private key path.
    pub key_path: Option<PathBuf>,
    /// Hostname used for the generated certificate and DoH SNI.
    pub hostname: String,
    /// Auto-generate a self-signed certificate when none is configured.
    pub auto_self_signed: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            database_path: None,
            log: "info".into(),
            dns: DnsConfig::default(),
            web: WebConfig::default(),
            tls: TlsConfig::default(),
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            listen: vec!["0.0.0.0:53".parse().unwrap()],
            dot_listen: vec![],
            doh_listen: vec![],
            doh_path: "/dns-query".into(),
            tcp_timeout_secs: 10,
        }
    }
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8053".parse().unwrap(),
            tls: false,
            disabled: false,
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            hostname: "picons.local".into(),
            auto_self_signed: true,
        }
    }
}

impl Config {
    /// Load configuration from an optional TOML file, falling back to defaults.
    pub fn load(path: Option<&std::path::Path>) -> anyhow::Result<Self> {
        match path {
            Some(p) => {
                let text = std::fs::read_to_string(p)
                    .map_err(|e| anyhow::anyhow!("reading config {}: {e}", p.display()))?;
                let cfg: Config = toml::from_str(&text)
                    .map_err(|e| anyhow::anyhow!("parsing config {}: {e}", p.display()))?;
                Ok(cfg)
            }
            None => Ok(Config::default()),
        }
    }

    /// Resolve the effective database path.
    pub fn database_path(&self) -> PathBuf {
        self.database_path
            .clone()
            .unwrap_or_else(|| self.data_dir.join("picons.db"))
    }

    /// Whether any TLS-requiring listener is configured.
    pub fn tls_required(&self) -> bool {
        self.web.tls || !self.dns.dot_listen.is_empty() || !self.dns.doh_listen.is_empty()
    }
}
