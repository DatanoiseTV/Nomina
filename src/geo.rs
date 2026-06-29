//! Optional GeoIP / ASN lookups backed by MaxMind GeoLite2 databases.
//!
//! Both databases are optional and user-supplied (MaxMind's license prohibits
//! redistribution). When configured, the resolver can select records by client
//! country/continent (geo-targeted views) and reject queries from blocked ASNs.

use std::net::IpAddr;
use std::path::Path;

use maxminddb::{Reader, path};

/// The geo attributes of a client IP, as far as the loaded databases know.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClientGeo {
    /// ISO 3166-1 alpha-2 country code, uppercase (e.g. `DE`).
    pub country: Option<String>,
    /// Continent code, uppercase (e.g. `EU`).
    pub continent: Option<String>,
    /// City name (English), when a City database is loaded.
    pub city: Option<String>,
    /// Latitude / longitude, when a City database is loaded.
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    /// Autonomous System number.
    pub asn: Option<u32>,
}

/// Loaded MaxMind databases. Either or both may be absent.
#[derive(Default)]
pub struct GeoDb {
    geoip: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
}

impl GeoDb {
    /// Load the configured databases, logging and skipping any that fail to open.
    pub fn load(geoip: Option<&Path>, asn: Option<&Path>) -> Self {
        fn open(p: &Path, kind: &str) -> Option<Reader<Vec<u8>>> {
            match Reader::open_readfile(p) {
                Ok(r) => {
                    tracing::info!("loaded {kind} database from {}", p.display());
                    Some(r)
                }
                Err(e) => {
                    tracing::warn!("failed to load {kind} database {}: {e}", p.display());
                    None
                }
            }
        }
        Self {
            geoip: geoip.and_then(|p| open(p, "GeoIP")),
            asn: asn.and_then(|p| open(p, "ASN")),
        }
    }

    pub fn enabled(&self) -> bool {
        self.geoip.is_some() || self.asn.is_some()
    }

    pub fn has_geoip(&self) -> bool {
        self.geoip.is_some()
    }

    pub fn has_asn(&self) -> bool {
        self.asn.is_some()
    }

    /// Full geo attributes for an IP (empty fields when no database covers it).
    pub fn lookup(&self, ip: IpAddr) -> ClientGeo {
        let mut g = ClientGeo::default();
        if let Some(r) = &self.geoip {
            if let Ok(res) = r.lookup(ip) {
                g.country = res
                    .decode_path::<String>(&path!["country", "iso_code"])
                    .ok()
                    .flatten()
                    .map(|s| s.to_uppercase());
                g.continent = res
                    .decode_path::<String>(&path!["continent", "code"])
                    .ok()
                    .flatten()
                    .map(|s| s.to_uppercase());
                g.city = res
                    .decode_path::<String>(&path!["city", "names", "en"])
                    .ok()
                    .flatten();
                g.lat = res
                    .decode_path::<f64>(&path!["location", "latitude"])
                    .ok()
                    .flatten();
                g.lon = res
                    .decode_path::<f64>(&path!["location", "longitude"])
                    .ok()
                    .flatten();
            }
        }
        if let Some(r) = &self.asn {
            if let Ok(res) = r.lookup(ip) {
                g.asn = res
                    .decode_path::<u32>(&path!["autonomous_system_number"])
                    .ok()
                    .flatten();
            }
        }
        g
    }
}
