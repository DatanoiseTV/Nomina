//! Serde-facing domain types shared by the database, store, and web API, plus
//! the DNS record-data parsing/validation helpers.

use hickory_proto::rr::{Name, RData, RecordType};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

// ---------------------------------------------------------------------------
// User
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub must_change_password: bool,
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// View (split-horizon)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct View {
    pub id: i64,
    pub name: String,
    pub networks: Vec<String>,
    /// Geo matchers (require a GeoLite2 database). A client matches the view if
    /// its IP is in `networks` OR its country/continent/ASN is listed here.
    #[serde(default)]
    pub countries: Vec<String>,
    #[serde(default)]
    pub continents: Vec<String>,
    #[serde(default)]
    pub asns: Vec<u32>,
    pub priority: i64,
    pub is_default: bool,
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// Zone + SOA
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Soa {
    pub primary_ns: String,
    pub admin_email: String,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: u32,
}

impl Soa {
    /// A sensible default SOA for a freshly created zone.
    pub fn default_for(zone: &str) -> Self {
        Self {
            primary_ns: format!("ns1.{zone}."),
            admin_email: format!("hostmaster.{zone}."),
            refresh: 3600,
            retry: 600,
            expire: 604800,
            minimum: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Zone {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub soa: Soa,
    pub default_ttl: u32,
    pub serial: u32,
    pub record_count: i64,
    /// Set when this zone is a secondary replicated from a primary.
    pub is_secondary: bool,
    pub primary_addr: Option<String>,
    pub last_check: Option<String>,
    pub last_error: Option<String>,
    /// Set when the zone is DNSSEC-signed.
    pub dnssec: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecondaryZone {
    pub zone_id: i64,
    pub name: String,
    pub primary_addr: String,
    pub refresh_secs: i64,
    pub serial: u32,
    pub record_count: i64,
    pub last_check: Option<String>,
    pub last_error: Option<String>,
    pub tsig_key: Option<String>,
}

// ---------------------------------------------------------------------------
// Record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct DnsRecord {
    pub id: i64,
    pub zone_id: i64,
    pub view_id: Option<i64>,
    pub name: String,
    pub fqdn: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub ttl: Option<u32>,
    pub data: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// Settings / forwarders
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ForwardProtocol {
    Udp,
    Tcp,
    Tls,
    Https,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Forwarder {
    pub addr: String,
    pub protocol: ForwardProtocol,
    pub port: u16,
    #[serde(default)]
    pub tls_name: Option<String>,
}

/// How Nomina resolves names it is not authoritative for.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum ResolutionMode {
    /// Forward to the configured upstream resolvers.
    #[default]
    Forward,
    /// Resolve recursively starting from the root servers (no upstream).
    Recursive,
    /// Authoritative-only: refuse anything outside local zones.
    Off,
}

/// How to order multiple address records in an answer (simple load balancing).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalance {
    /// Return records in their stored order.
    #[default]
    Off,
    /// Rotate the address records on each query (round-robin).
    RoundRobin,
    /// Shuffle the address records on each query.
    Random,
}

/// What to return for a blocked name. Serialized values match the API contract.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum BlockMode {
    /// Answer NXDOMAIN. `nx_domain` is accepted for backward compatibility with
    /// settings persisted by earlier builds.
    #[serde(rename = "nxdomain", alias = "nx_domain")]
    #[default]
    NxDomain,
    /// Answer 0.0.0.0 / :: (a sinkhole address).
    #[serde(rename = "zero_ip")]
    ZeroIp,
    /// Answer REFUSED.
    #[serde(rename = "refused")]
    Refused,
}

/// Protection against IDN homograph / lookalike domains (e.g. a Cyrillic «а» in
/// `аpple.com`, served on the wire as a `xn--` punycode label).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum HomographMode {
    /// No IDN filtering.
    #[default]
    Off,
    /// Block internationalized names whose labels mix scripts (e.g. Latin +
    /// Cyrillic) — the classic homograph attack. Legitimate single-script IDNs
    /// (e.g. `münchen`) are allowed.
    Mixed,
    /// Block all internationalized (punycode) names.
    AllIdn,
}

/// How much per-query detail to retain for the dashboard. Privacy-aware: `off`
/// keeps only aggregate, non-identifying counters (the default).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum QueryLog {
    /// Aggregate counters only. No client IPs, names, or recent-query list.
    #[default]
    Off,
    /// Record recent queries and top domains, but anonymize client IPs
    /// (IPv4 → /24, IPv6 → /48).
    Anonymized,
    /// Record full client IPs and names. Opt-in.
    Full,
}

/// A TSIG key (RFC 8945) for authenticating zone transfers. `secret` is the
/// base64-encoded HMAC key; `algorithm` is e.g. `hmac-sha256`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsigKey {
    pub name: String,
    pub algorithm: String,
    pub secret: String,
}

/// A DynDNS update credential (public view — never carries the secret hash).
/// `hostnames` is the set of FQDNs this token is permitted to repoint.
#[derive(Debug, Clone, Serialize)]
pub struct DynDnsToken {
    pub id: i64,
    pub label: String,
    pub username: String,
    pub hostnames: Vec<String>,
    pub view_id: Option<i64>,
    pub ttl: u32,
    pub enabled: bool,
    pub last_update_at: Option<String>,
    pub last_ip: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Upstream resolvers used when `resolution_mode` is `forward`.
    pub forwarders: Vec<Forwarder>,
    /// Resolution strategy for non-authoritative names.
    #[serde(default)]
    pub resolution_mode: ResolutionMode,
    /// Response style for blocked names.
    #[serde(default)]
    pub block_mode: BlockMode,
    /// Enable blocklist filtering of non-authoritative names.
    #[serde(default = "default_true")]
    pub blocking_enabled: bool,
    /// Privacy-aware query logging level for the dashboard.
    #[serde(default)]
    pub query_log: QueryLog,
    /// IDN homograph / lookalike-domain protection.
    #[serde(default)]
    pub homograph_protection: HomographMode,
    pub cache_size: u64,
    pub cache_min_ttl: u32,
    pub cache_max_ttl: u32,
    #[serde(default)]
    pub dnssec_validate_upstream: bool,
    /// CIDRs allowed to request AXFR zone transfers (acting as a primary for
    /// secondary nameservers). Empty disables zone transfers.
    #[serde(default)]
    pub allow_axfr_from: Vec<String>,
    /// TSIG keys for authenticating zone transfers.
    #[serde(default)]
    pub tsig_keys: Vec<TsigKey>,
    /// Require a valid TSIG signature on incoming AXFR requests.
    #[serde(default)]
    pub axfr_require_tsig: bool,
    /// Load-balancing strategy for multi-address answers.
    #[serde(default)]
    pub load_balance: LoadBalance,
    /// Autonomous System numbers to reject queries from (requires a GeoLite2 ASN
    /// database to be configured). Empty disables ASN blocking.
    #[serde(default)]
    pub blocked_asns: Vec<u32>,
    /// Discover LAN hosts via mDNS and republish them under `mdns_zone`.
    #[serde(default)]
    pub mdns_enabled: bool,
    /// Suffix discovered `*.local` hosts are published under (e.g. `lan`).
    /// Empty disables publishing even when discovery is on.
    #[serde(default)]
    pub mdns_zone: String,
    /// TTL (seconds) for republished mDNS records. Low by design.
    #[serde(default = "default_mdns_ttl")]
    pub mdns_ttl: u32,
    /// Also publish globally-routable (public) IPv6/IPv4 addresses, not just
    /// LAN-scoped ones. Off by default — a device's public address normally has
    /// no business being served under a local name.
    #[serde(default)]
    pub mdns_publish_public: bool,

    // ----- Listeners (DB-managed; merged over the config file at startup, so
    //       changes need a restart to rebind). Empty = use the config file. -----
    /// Plain DNS listen addresses (UDP+TCP), e.g. `["0.0.0.0:53"]`.
    #[serde(default)]
    pub dns_listen: Vec<String>,
    /// DNS-over-TLS listen addresses.
    #[serde(default)]
    pub dot_listen: Vec<String>,
    /// DNS-over-HTTPS listen addresses.
    #[serde(default)]
    pub doh_listen: Vec<String>,
    /// DNS-over-QUIC listen addresses.
    #[serde(default)]
    pub doq_listen: Vec<String>,
    /// DNS-over-HTTP/3 listen addresses.
    #[serde(default)]
    pub doh3_listen: Vec<String>,
    /// HTTP path the DoH endpoint answers on. Empty = config file / default.
    #[serde(default)]
    pub doh_path: String,
    /// Idle timeout for TCP/DoT connections, seconds. 0 = config file / default.
    #[serde(default)]
    pub tcp_timeout_secs: u32,

    // ----- TLS (restart to apply). Empty/None = use the config file. -----
    /// Hostname for the generated certificate and DoH SNI.
    #[serde(default)]
    pub tls_hostname: String,
    /// Obtain a real certificate from Let's Encrypt via ACME.
    #[serde(default)]
    pub tls_acme: bool,
    /// Domains to request the ACME certificate for (defaults to `[hostname]`).
    #[serde(default)]
    pub tls_acme_domains: Vec<String>,
    /// Contact email for the ACME account.
    #[serde(default)]
    pub tls_acme_contact: String,
    /// Use the Let's Encrypt staging environment (testing; untrusted certs).
    #[serde(default)]
    pub tls_acme_staging: bool,
    /// PEM certificate chain path (empty = generated self-signed).
    #[serde(default)]
    pub tls_cert_path: String,
    /// PEM private key path.
    #[serde(default)]
    pub tls_key_path: String,
    /// Auto-generate a self-signed certificate when none is configured.
    /// `None` = use the config file.
    #[serde(default)]
    pub tls_auto_self_signed: Option<bool>,

    // ----- GeoIP (restart to apply). Empty = use the config file. -----
    /// Path to a GeoLite2/DB-IP City `.mmdb`.
    #[serde(default)]
    pub geoip_db: String,
    /// Path to a GeoLite2/DB-IP ASN `.mmdb`.
    #[serde(default)]
    pub asn_db: String,

    // ----- Management server -----
    /// CIDR allow-list for the management UI/API. Empty = no restriction.
    #[serde(default)]
    pub web_allow_networks: Vec<String>,

    /// Re-download enabled blocklists every N hours in the background. 0 = off.
    #[serde(default)]
    pub blocklist_refresh_hours: u32,
}

fn default_true() -> bool {
    true
}

fn default_mdns_ttl() -> u32 {
    120
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            forwarders: vec![
                Forwarder {
                    addr: "1.1.1.1".into(),
                    protocol: ForwardProtocol::Udp,
                    port: 53,
                    tls_name: None,
                },
                Forwarder {
                    addr: "9.9.9.9".into(),
                    protocol: ForwardProtocol::Udp,
                    port: 53,
                    tls_name: None,
                },
            ],
            resolution_mode: ResolutionMode::Forward,
            block_mode: BlockMode::NxDomain,
            blocking_enabled: true,
            query_log: QueryLog::Off,
            homograph_protection: HomographMode::Off,
            cache_size: 1024,
            cache_min_ttl: 0,
            cache_max_ttl: 86400,
            dnssec_validate_upstream: false,
            allow_axfr_from: Vec::new(),
            tsig_keys: Vec::new(),
            axfr_require_tsig: false,
            load_balance: LoadBalance::Off,
            blocked_asns: Vec::new(),
            mdns_enabled: false,
            mdns_zone: String::new(),
            mdns_ttl: 120,
            mdns_publish_public: false,
            dns_listen: Vec::new(),
            dot_listen: Vec::new(),
            doh_listen: Vec::new(),
            doq_listen: Vec::new(),
            doh3_listen: Vec::new(),
            doh_path: String::new(),
            tcp_timeout_secs: 0,
            tls_hostname: String::new(),
            tls_acme: false,
            tls_acme_domains: Vec::new(),
            tls_acme_contact: String::new(),
            tls_acme_staging: false,
            tls_cert_path: String::new(),
            tls_key_path: String::new(),
            tls_auto_self_signed: None,
            geoip_db: String::new(),
            asn_db: String::new(),
            web_allow_networks: Vec::new(),
            blocklist_refresh_hours: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Blocklists (Pi-hole style filtering)
// ---------------------------------------------------------------------------

/// Format of a remote blocklist source.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum BlocklistFormat {
    /// `hosts` file: `0.0.0.0 domain` or `127.0.0.1 domain` lines.
    #[default]
    Hosts,
    /// Plain domain list, one domain per line.
    Domains,
}

#[derive(Debug, Clone, Serialize)]
pub struct Blocklist {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub format: BlocklistFormat,
    pub enabled: bool,
    pub entry_count: i64,
    pub last_updated: Option<String>,
    pub last_error: Option<String>,
    pub created_at: String,
}

/// A manual allow/deny rule that overrides the downloaded lists.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// Block this domain (and its subdomains).
    Deny,
    /// Always allow this domain even if a blocklist contains it.
    Allow,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockRule {
    pub id: i64,
    pub domain: String,
    pub action: RuleAction,
    pub comment: Option<String>,
    pub created_at: String,
}

/// A DNS rewrite: answer a fixed IP (A/AAAA) or CNAME target for a domain
/// (and its subdomains), regardless of upstream. Works even in
/// authoritative-only mode.
#[derive(Debug, Clone, Serialize)]
pub struct Rewrite {
    pub id: i64,
    pub domain: String,
    pub target: String,
    pub enabled: bool,
    pub comment: Option<String>,
    pub created_at: String,
}

/// A conditional forwarder: queries under `domain` (and its subdomains) are
/// forwarded to a dedicated set of upstreams instead of the global resolver.
/// e.g. `corp.internal` -> 10.0.0.1, `consul` -> 127.0.0.1:8600.
#[derive(Debug, Clone, Serialize)]
pub struct ConditionalForward {
    pub id: i64,
    pub domain: String,
    pub forwarders: Vec<Forwarder>,
    pub enabled: bool,
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// DHCP
// ---------------------------------------------------------------------------

/// IP family a DHCP scope serves.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub enum IpFamily {
    V4,
    V6,
}

/// Lifecycle state of a DHCP lease.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub enum LeaseState {
    /// Offered in a DHCPOFFER / ADVERTISE but not yet confirmed.
    Offered,
    /// Confirmed and in use (REQUEST/ACK granted).
    Active,
    /// The client declined the address (DHCPDECLINE) — keep out of the pool.
    Declined,
    /// The client released the address (DHCPRELEASE).
    Released,
    /// Past its expiry; reclaimable.
    Expired,
}

/// The typed encoding of a user-entered DHCP option value. Determines how the
/// human-readable `value` string in [`DhcpOption`] is turned into wire bytes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum DhcpOptionKind {
    /// A single IP address (4 bytes for v4, 16 for v6).
    Ip,
    /// A list of IP addresses, concatenated on the wire.
    IpList,
    /// An unsigned 8-bit integer.
    U8,
    /// An unsigned 16-bit integer (big-endian).
    U16,
    /// An unsigned 32-bit integer (big-endian).
    U32,
    /// A boolean, encoded as a single 0/1 byte.
    Bool,
    /// A UTF-8 text string.
    Text,
    /// Raw bytes entered as a hex string (colons/spaces ignored).
    Hex,
}

/// A user-addable DHCP option. Any `code` is permitted; well-known codes get a
/// display `name` and `kind` from the option registry, but arbitrary codes can
/// be added with an explicit `kind`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[allow(dead_code)]
pub struct DhcpOption {
    /// Option code. 0-255 for DHCPv4; the wider 16-bit space for DHCPv6.
    pub code: u16,
    /// Display name (informational only; never affects encoding).
    #[serde(default)]
    pub name: Option<String>,
    /// The human-entered value, interpreted per `kind`.
    pub value: String,
    /// How `value` is encoded to wire bytes.
    pub kind: DhcpOptionKind,
}

/// A DHCP address pool plus its served options.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct DhcpScope {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub family: IpFamily,
    /// The served subnet in CIDR form (e.g. `192.168.1.0/24`).
    pub subnet: String,
    /// First address of the dynamic pool (inclusive).
    pub range_start: String,
    /// Last address of the dynamic pool (inclusive).
    pub range_end: String,
    /// Default lease duration in seconds.
    pub lease_secs: u32,
    /// Whether granted leases should register A/AAAA + PTR records in DNS.
    pub dns_register: bool,
    /// Zone leases register into when `dns_register` is set.
    pub dns_zone: Option<String>,
    /// The DHCP server's own IPv4 address on this subnet, sent as option 54
    /// (server identifier) in OFFER/ACK. Required for DHCPv4 serving; ignored
    /// for IPv6 scopes (which derive a server DUID instead).
    pub server_id: Option<String>,
    /// Network interface this scope serves directly (e.g. a VLAN sub-interface
    /// like `eth0.20`). When set, directly-connected (non-relayed) requests
    /// arriving on that interface select this scope. `None` = any interface
    /// (relay/giaddr selection, or single-LAN fallback).
    pub interface: Option<String>,
    /// Options served to clients of this scope.
    pub options: Vec<DhcpOption>,
    pub created_at: String,
}

/// A fixed address assignment keyed by client identifier (MAC for v4, DUID for
/// v6). `identifier` is normalized lowercase.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct DhcpReservation {
    pub id: i64,
    pub scope_id: i64,
    /// MAC (v4) or DUID hex (v6), normalized lowercase.
    pub identifier: String,
    pub ip: String,
    pub hostname: Option<String>,
    /// Per-reservation option overrides (merged over the scope's options).
    pub options: Vec<DhcpOption>,
    pub created_at: String,
}

/// A dynamically allocated lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct DhcpLease {
    pub id: i64,
    pub scope_id: i64,
    pub family: IpFamily,
    pub ip: String,
    /// MAC (v4) or DUID hex (v6), normalized lowercase.
    pub identifier: String,
    pub hostname: Option<String>,
    /// RFC3339 timestamp the lease was granted.
    pub starts_at: String,
    /// RFC3339 timestamp the lease expires.
    pub expires_at: String,
    pub state: LeaseState,
    pub created_at: String,
}

/// Does `pattern` (a domain, optionally `*.`-prefixed) cover `name`? Matches the
/// domain itself and all subdomains. Both inputs must be lowercase, no trailing
/// dot.
pub fn domain_covers(pattern: &str, name: &str) -> bool {
    let p = pattern.strip_prefix("*.").unwrap_or(pattern);
    name == p || name.ends_with(&format!(".{p}"))
}

/// The IPv4 + IPv6 root server addresses, used for recursive resolution.
pub const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4",
    "170.247.170.2",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
    "2001:503:ba3e::2:30",
    "2801:1b8:10::b",
    "2001:500:2::c",
    "2001:500:2d::d",
    "2001:500:a8::e",
    "2001:500:2f::f",
    "2001:500:12::d0d",
    "2001:500:1::53",
    "2001:7fe::53",
    "2001:503:c27::2:30",
    "2001:7fd::1",
    "2001:500:9f::42",
    "2001:dc3::35",
];

// ---------------------------------------------------------------------------
// DNS helpers
// ---------------------------------------------------------------------------

/// Record types Nomina lets users manage. `SOA` is excluded (managed via the
/// zone) as are DNSSEC/transfer pseudo-types.
pub const SUPPORTED_RECORD_TYPES: &[&str] = &[
    "A",
    "AAAA",
    "ANAME",
    "CAA",
    "CERT",
    "CNAME",
    "CSYNC",
    "HINFO",
    "HTTPS",
    "MX",
    "NAPTR",
    "NS",
    "OPENPGPKEY",
    "PTR",
    "SMIMEA",
    "SRV",
    "SSHFP",
    "SVCB",
    "TLSA",
    "TXT",
];

/// Parse a textual record type into the hickory enum, restricted to the
/// supported set.
pub fn parse_record_type(s: &str) -> Result<RecordType, String> {
    let up = s.trim().to_ascii_uppercase();
    if !SUPPORTED_RECORD_TYPES.contains(&up.as_str()) {
        return Err(format!("unsupported record type: {s}"));
    }
    RecordType::from_str(&up).map_err(|_| format!("invalid record type: {s}"))
}

/// Validate a zone name and return the canonical form (lowercase, no trailing
/// dot).
pub fn canonical_zone_name(name: &str) -> Result<String, String> {
    let trimmed = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err("zone name must not be empty".into());
    }
    // Validate by parsing as a DNS name.
    Name::from_utf8(format!("{trimmed}.")).map_err(|e| format!("invalid zone name: {e}"))?;
    Ok(trimmed)
}

/// Build the absolute [`Name`] for a record given its relative `name` within a
/// zone. `"@"` and empty mean the zone apex.
pub fn record_fqdn_name(record_name: &str, zone: &str) -> Result<Name, String> {
    let rec = record_name.trim().trim_end_matches('.');
    let fqdn = if rec.is_empty() || rec == "@" {
        format!("{zone}.")
    } else {
        format!("{rec}.{zone}.")
    };
    let mut name = Name::from_utf8(&fqdn).map_err(|e| format!("invalid record name: {e}"))?;
    name.set_fqdn(true);
    Ok(name)
}

/// Human-readable FQDN string (lowercase, no trailing dot) for API responses.
pub fn record_fqdn_string(record_name: &str, zone: &str) -> String {
    let rec = record_name.trim().trim_end_matches('.');
    if rec.is_empty() || rec == "@" {
        zone.to_ascii_lowercase()
    } else {
        format!("{}.{}", rec.to_ascii_lowercase(), zone.to_ascii_lowercase())
    }
}

/// Qualify any relative name token inside `data` to the zone origin, so that a
/// user can write either `mail` or `mail.home.lan.` for name-valued records.
/// Tokens that already end with `.` are treated as absolute and left untouched.
fn prequalify_data(rtype: RecordType, data: &str, zone: &str) -> String {
    let qualify = |tok: &str| -> String {
        let t = tok.trim();
        if t.is_empty() || t == "@" {
            // The zone apex.
            format!("{zone}.")
        } else if t.ends_with('.') {
            // Already fully qualified.
            t.to_string()
        } else if t.contains('.') {
            // Multi-label without a trailing dot: treat as a FQDN (e.g. a user
            // typing `mail.google.com` for a CNAME target), not relative.
            format!("{t}.")
        } else {
            // Single label: relative to the zone (e.g. `nas` -> `nas.<zone>.`).
            format!("{t}.{zone}.")
        }
    };

    match rtype {
        RecordType::CNAME | RecordType::NS | RecordType::PTR => qualify(data),
        RecordType::MX => {
            // "<pref> <exchange>"
            let parts: Vec<&str> = data.split_whitespace().collect();
            if parts.len() == 2 {
                format!("{} {}", parts[0], qualify(parts[1]))
            } else {
                data.to_string()
            }
        }
        RecordType::SRV => {
            // "<prio> <weight> <port> <target>"
            let parts: Vec<&str> = data.split_whitespace().collect();
            if parts.len() == 4 {
                format!(
                    "{} {} {} {}",
                    parts[0],
                    parts[1],
                    parts[2],
                    qualify(parts[3])
                )
            } else {
                data.to_string()
            }
        }
        _ => data.to_string(),
    }
}

/// Parse and validate record data into hickory [`RData`], qualifying relative
/// names to the zone origin. Used both when loading the store and when
/// validating an API write.
pub fn parse_rdata(rtype: RecordType, data: &str, zone: &str) -> Result<RData, String> {
    let prepared = prequalify_data(rtype, data, zone);
    RData::try_from_str(rtype, &prepared).map_err(|e| format!("invalid {rtype} data: {e}"))
}

/// Convert an email-style admin address (`hostmaster@home.lan`) or zone-file
/// style (`hostmaster.home.lan.`) into a DNS [`Name`] suitable for the SOA
/// RNAME field.
pub fn soa_rname(admin: &str) -> Result<Name, String> {
    let s = admin.trim();
    let dns = if let Some((local, domain)) = s.split_once('@') {
        format!("{}.{}", local.replace('.', "\\."), domain)
    } else {
        s.to_string()
    };
    let dns = if dns.ends_with('.') {
        dns
    } else {
        format!("{dns}.")
    };
    let mut name = Name::from_utf8(&dns).map_err(|e| format!("invalid admin email: {e}"))?;
    name.set_fqdn(true);
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_types() {
        assert!(parse_rdata(RecordType::A, "10.0.0.5", "home.lan").is_ok());
        assert!(parse_rdata(RecordType::AAAA, "fd00::5", "home.lan").is_ok());
        assert!(parse_rdata(RecordType::TXT, "v=spf1 -all", "home.lan").is_ok());
        assert!(parse_rdata(RecordType::A, "not-an-ip", "home.lan").is_err());
    }

    #[test]
    fn qualifies_relative_names() {
        // A relative MX exchange should gain the zone origin.
        let mx = parse_rdata(RecordType::MX, "10 mail", "home.lan").unwrap();
        assert_eq!(mx.to_string(), "10 mail.home.lan.");

        // An absolute target is left untouched.
        let cname = parse_rdata(RecordType::CNAME, "host.example.com.", "home.lan").unwrap();
        assert_eq!(cname.to_string(), "host.example.com.");

        let srv = parse_rdata(RecordType::SRV, "0 5 5060 sip", "home.lan").unwrap();
        assert_eq!(srv.to_string(), "0 5 5060 sip.home.lan.");
    }

    #[test]
    fn parses_caa() {
        assert!(parse_rdata(RecordType::CAA, "0 issue \"letsencrypt.org\"", "home.lan").is_ok());
    }

    #[test]
    fn unsupported_type_rejected() {
        assert!(parse_record_type("DNSKEY").is_err());
        assert!(parse_record_type("A").is_ok());
    }

    #[test]
    fn zone_name_canonicalization() {
        assert_eq!(canonical_zone_name("Home.Lan.").unwrap(), "home.lan");
        assert!(canonical_zone_name("").is_err());
    }

    #[test]
    fn domain_coverage() {
        // A plain domain covers itself and all subdomains.
        assert!(domain_covers("example.com", "example.com"));
        assert!(domain_covers("example.com", "ads.example.com"));
        assert!(domain_covers("example.com", "a.b.example.com"));
        assert!(!domain_covers("example.com", "notexample.com"));
        assert!(!domain_covers("example.com", "example.com.evil.com"));
        // A wildcard prefix behaves the same for subdomain matching.
        assert!(domain_covers("*.example.com", "x.example.com"));
        assert!(domain_covers("*.example.com", "example.com"));
    }

    #[test]
    fn all_supported_types_parse() {
        // A representative, valid presentation-format sample for every type in
        // SUPPORTED_RECORD_TYPES. Verified against hickory's RData::try_from_str
        // so the API never advertises a type it can't actually store.
        let cases: &[(&str, &str)] = &[
            ("A", "203.0.113.10"),
            ("AAAA", "2001:db8::1"),
            ("ANAME", "target.example.com."),
            ("CAA", "0 issue \"letsencrypt.org\""),
            ("CERT", "1 12345 8 aGVsbG8="),
            ("CNAME", "host.example.com."),
            ("CSYNC", "123 3 A NS AAAA"),
            ("HINFO", "\"Intel\" \"Linux\""),
            ("HTTPS", "1 . alpn=\"h2\""),
            ("MX", "10 mail.example.com."),
            (
                "NAPTR",
                "100 10 \"U\" \"E2U+sip\" \"!^.*$!sip:info@example.com!\" .",
            ),
            ("NS", "ns1.example.com."),
            ("OPENPGPKEY", "aGVsbG8gd29ybGQ="),
            ("PTR", "host.example.com."),
            ("SMIMEA", "3 0 0 aabbccdd"),
            ("SRV", "0 5 5060 sip.example.com."),
            ("SSHFP", "2 1 123456789abcdef67890123456789abcdef67890"),
            ("SVCB", "1 . alpn=\"h2\""),
            ("TLSA", "3 0 1 aabbccdd"),
            ("TXT", "v=spf1 -all"),
        ];
        // Every advertised type has a tested sample, and vice versa.
        assert_eq!(cases.len(), SUPPORTED_RECORD_TYPES.len());
        for (t, d) in cases {
            assert!(
                SUPPORTED_RECORD_TYPES.contains(t),
                "{t} sampled but not advertised"
            );
            let rt = parse_record_type(t).unwrap_or_else(|e| panic!("{t}: {e}"));
            parse_rdata(rt, d, "example.com").unwrap_or_else(|e| panic!("{t}: {e}"));
        }
    }
}
