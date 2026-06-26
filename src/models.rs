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
    pub created_at: String,
    pub updated_at: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub forwarders: Vec<Forwarder>,
    pub forward_enabled: bool,
    pub cache_size: u64,
    pub cache_min_ttl: u32,
    pub cache_max_ttl: u32,
    #[serde(default)]
    pub dnssec_validate_upstream: bool,
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
            forward_enabled: true,
            cache_size: 1024,
            cache_min_ttl: 0,
            cache_max_ttl: 86400,
            dnssec_validate_upstream: false,
        }
    }
}

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
}
