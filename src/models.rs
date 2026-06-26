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

/// How PicoNS resolves names it is not authoritative for.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ResolutionMode {
    /// Forward to the configured upstream resolvers.
    Forward,
    /// Resolve recursively starting from the root servers (no upstream).
    Recursive,
    /// Authoritative-only: refuse anything outside local zones.
    Off,
}

impl Default for ResolutionMode {
    fn default() -> Self {
        ResolutionMode::Forward
    }
}

/// What to return for a blocked name. Serialized values match the API contract.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BlockMode {
    /// Answer NXDOMAIN.
    #[serde(rename = "nxdomain")]
    NxDomain,
    /// Answer 0.0.0.0 / :: (a sinkhole address).
    #[serde(rename = "zero_ip")]
    ZeroIp,
    /// Answer REFUSED.
    #[serde(rename = "refused")]
    Refused,
}

impl Default for BlockMode {
    fn default() -> Self {
        BlockMode::NxDomain
    }
}

/// How much per-query detail to retain for the dashboard. Privacy-aware: `off`
/// keeps only aggregate, non-identifying counters (the default).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QueryLog {
    /// Aggregate counters only. No client IPs, names, or recent-query list.
    Off,
    /// Record recent queries and top domains, but anonymize client IPs
    /// (IPv4 → /24, IPv6 → /48).
    Anonymized,
    /// Record full client IPs and names. Opt-in.
    Full,
}

impl Default for QueryLog {
    fn default() -> Self {
        QueryLog::Off
    }
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
    pub cache_size: u64,
    pub cache_min_ttl: u32,
    pub cache_max_ttl: u32,
    #[serde(default)]
    pub dnssec_validate_upstream: bool,
    /// CIDRs allowed to request AXFR zone transfers (acting as a primary for
    /// secondary nameservers). Empty disables zone transfers.
    #[serde(default)]
    pub allow_axfr_from: Vec<String>,
}

fn default_true() -> bool {
    true
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
            cache_size: 1024,
            cache_min_ttl: 0,
            cache_max_ttl: 86400,
            dnssec_validate_upstream: false,
            allow_axfr_from: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Blocklists (Pi-hole style filtering)
// ---------------------------------------------------------------------------

/// Format of a remote blocklist source.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistFormat {
    /// `hosts` file: `0.0.0.0 domain` or `127.0.0.1 domain` lines.
    Hosts,
    /// Plain domain list, one domain per line.
    Domains,
}

impl Default for BlocklistFormat {
    fn default() -> Self {
        BlocklistFormat::Hosts
    }
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

/// Record types PicoNS lets users manage. `SOA` is excluded (managed via the
/// zone) as are DNSSEC/transfer pseudo-types.
pub const SUPPORTED_RECORD_TYPES: &[&str] =
    &["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "PTR", "CAA"];

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
    Name::from_utf8(format!("{trimmed}."))
        .map_err(|e| format!("invalid zone name: {e}"))?;
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
            format!("{zone}.")
        } else if t.ends_with('.') {
            t.to_string()
        } else {
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
                format!("{} {} {} {}", parts[0], parts[1], parts[2], qualify(parts[3]))
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
    let dns = if dns.ends_with('.') { dns } else { format!("{dns}.") };
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
}
