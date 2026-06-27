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
    /// Explicit database path; defaults to `<data_dir>/nomina.db`.
    pub database_path: Option<PathBuf>,
    /// `tracing` env-filter string.
    pub log: String,
    pub dns: DnsConfig,
    pub web: WebConfig,
    pub tls: TlsConfig,
    pub privileges: PrivilegesConfig,
    pub geo: GeoConfig,
    pub dhcp: DhcpConfig,
}

/// DHCP server listeners. Empty lists disable the corresponding family — by
/// default the DHCP server is off entirely. Binding the well-known ports (67 for
/// DHCPv4, 547 for the DHCPv6 server) requires root or `CAP_NET_BIND_SERVICE`;
/// sockets are bound while privileged and the server runs after privilege drop.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DhcpConfig {
    /// DHCPv4 listen addresses (UDP, broadcast-capable), e.g. `["0.0.0.0:67"]`.
    pub v4_listen: Vec<SocketAddr>,
    /// DHCPv6 server listen addresses (UDP, IPv6-only), e.g. `["[::]:547"]`.
    pub v6_listen: Vec<SocketAddr>,
}

/// Optional MaxMind GeoLite2 databases for geo-targeted views and ASN blocking.
/// Both are user-supplied (MaxMind's license forbids redistribution).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeoConfig {
    /// Path to a GeoLite2 Country or City `.mmdb` (for country/continent/city).
    pub geoip_db: Option<PathBuf>,
    /// Path to a GeoLite2 ASN `.mmdb` (for ASN-based views and blocking).
    pub asn_db: Option<PathBuf>,
}

/// Drop to an unprivileged user/group after binding privileged sockets.
/// Only effective when the process starts as root on a Unix system.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivilegesConfig {
    /// Username to drop to (e.g. "nomina" or "nobody").
    pub user: Option<String>,
    /// Group to drop to. Defaults to the user's primary group if unset.
    pub group: Option<String>,
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
    /// DNS-over-QUIC listen addresses (UDP; requires TLS material).
    pub doq_listen: Vec<SocketAddr>,
    /// DNS-over-HTTP/3 listen addresses (UDP; requires TLS material).
    pub doh3_listen: Vec<SocketAddr>,
    /// HTTP path the DoH endpoint answers on.
    pub doh_path: String,
    /// Idle timeout for TCP/DoT connections, seconds.
    pub tcp_timeout_secs: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebConfig {
    /// Management UI/API listen address. Bind to a specific IP (e.g.
    /// `127.0.0.1:8053` or a LAN address) to limit reachability.
    pub listen: SocketAddr,
    /// Serve the management interface over HTTPS (recommended).
    pub tls: bool,
    /// Disable the management interface entirely.
    pub disabled: bool,
    /// Optional CIDR allow-list for the management server. When non-empty, only
    /// clients in these networks may reach it (defense-in-depth on top of the
    /// bind address). Note: this also covers DoH if served on this port; use a
    /// dedicated `doh_listen` for public DoH.
    pub allow_networks: Vec<String>,
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
            privileges: PrivilegesConfig::default(),
            geo: GeoConfig::default(),
            dhcp: DhcpConfig::default(),
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            listen: vec!["0.0.0.0:53".parse().unwrap()],
            dot_listen: vec![],
            doh_listen: vec![],
            doq_listen: vec![],
            doh3_listen: vec![],
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
            allow_networks: Vec::new(),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            hostname: "nomina.local".into(),
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
            .unwrap_or_else(|| self.data_dir.join("nomina.db"))
    }

    /// Whether any TLS-requiring listener is configured.
    pub fn tls_required(&self) -> bool {
        self.web.tls
            || !self.dns.dot_listen.is_empty()
            || !self.dns.doh_listen.is_empty()
            || !self.dns.doq_listen.is_empty()
            || !self.dns.doh3_listen.is_empty()
    }
}
