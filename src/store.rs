//! In-memory authoritative store — the DNS query hot path.
//!
//! Records are pre-parsed into hickory [`RData`] at load time so the query path
//! does no string parsing and never touches the database. The whole store is
//! rebuilt from the database and atomically swapped in after any admin change.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use ipnet::IpNet;
use tracing::warn;

use crate::db::Db;
use crate::dns::dnssec::ZoneSigner;
use crate::models::{parse_rdata, record_fqdn_name, soa_rname};

/// A resolved split-horizon view with its parsed CIDR set.
pub struct ViewMatch {
    pub id: i64,
    pub name: String,
    pub nets: Vec<IpNet>,
    pub priority: i64,
}

impl ViewMatch {
    fn matches(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(&ip))
    }
}

/// A single pre-parsed record ready to serve.
struct StoredRecord {
    rtype: RecordType,
    ttl: u32,
    view_id: Option<i64>,
    rdata: RData,
}

/// One authoritative zone with its records indexed by owner FQDN.
pub struct StoredZone {
    pub apex: Name,
    pub label_count: usize,
    soa: SOA,
    soa_ttl: u32,
    /// Owner FQDN (lowercase, no trailing dot) -> records at that name.
    records: HashMap<String, Vec<StoredRecord>>,
    /// Present when the zone is DNSSEC-signed.
    signer: Option<Arc<ZoneSigner>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Authoritative,
    NxDomain,
    NoData,
    NotAuthoritative,
}

/// The result of an authoritative lookup.
pub struct LookupResult {
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub rcode: ResponseCode,
    pub outcome: Outcome,
    pub view_name: Option<String>,
}

#[derive(Default)]
pub struct ZoneStore {
    views: Vec<ViewMatch>,
    zones: Vec<StoredZone>,
}

/// Lowercase, trailing-dot-stripped key for a name.
fn name_key(name: &Name) -> String {
    name.to_string().trim_end_matches('.').to_ascii_lowercase()
}

impl ZoneStore {
    /// Build the store fresh from the database. Bad records are logged and
    /// skipped rather than failing the whole load.
    pub fn load(db: &Db) -> anyhow::Result<Self> {
        db.with(|conn| Ok(Self::build_from(conn)))
            .map_err(Into::into)
    }

    fn build_from(conn: &rusqlite::Connection) -> Self {
        let mut store = ZoneStore::default();

        // Views, sorted by priority ascending (lowest number wins first).
        let views = Db::list_views(conn).unwrap_or_default();
        for v in views {
            let mut nets = Vec::new();
            for n in &v.networks {
                match n.parse::<IpNet>() {
                    Ok(net) => nets.push(net),
                    Err(e) => warn!(view = %v.name, net = %n, "skipping invalid CIDR: {e}"),
                }
            }
            store.views.push(ViewMatch {
                id: v.id,
                name: v.name,
                nets,
                priority: v.priority,
            });
        }
        store.views.sort_by_key(|v| v.priority);

        // Zones + records.
        let zones = Db::list_zones(conn).unwrap_or_default();
        for z in zones {
            if !z.enabled {
                continue;
            }
            let apex = match record_fqdn_name("@", &z.name) {
                Ok(n) => n,
                Err(e) => {
                    warn!(zone = %z.name, "skipping zone with invalid apex: {e}");
                    continue;
                }
            };

            // Build the SOA rdata.
            let mname = match record_fqdn_name(z.soa.primary_ns.trim_end_matches('.'), "") {
                Ok(n) => n,
                Err(_) => apex.clone(),
            };
            let rname = soa_rname(&z.soa.admin_email).unwrap_or_else(|_| apex.clone());
            let soa = SOA::new(
                mname,
                rname,
                z.serial,
                z.soa.refresh,
                z.soa.retry,
                z.soa.expire,
                z.soa.minimum,
            );

            let signer = match Db::dnssec_secret(conn, z.id) {
                Ok(Some(secret)) => match ZoneSigner::build(apex.clone(), z.default_ttl, &secret) {
                    Ok(s) => Some(Arc::new(s)),
                    Err(e) => {
                        warn!(zone = %z.name, "DNSSEC disabled (key error): {e}");
                        None
                    }
                },
                _ => None,
            };

            let mut zone = StoredZone {
                label_count: apex.num_labels() as usize,
                apex,
                soa_ttl: z.soa.minimum.max(1),
                soa,
                records: HashMap::new(),
                signer,
            };

            let records = Db::list_records(conn, z.id).unwrap_or_default();
            for r in records {
                if !r.enabled {
                    continue;
                }
                let rtype = match crate::models::parse_record_type(&r.rtype) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(record = r.id, "skipping record: {e}");
                        continue;
                    }
                };
                let rdata = match parse_rdata(rtype, &r.data, &z.name) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(record = r.id, "skipping unparsable record: {e}");
                        continue;
                    }
                };
                let key = name_key(&match record_fqdn_name(&r.name, &z.name) {
                    Ok(n) => n,
                    Err(_) => continue,
                });
                zone.records.entry(key).or_default().push(StoredRecord {
                    rtype,
                    ttl: r.ttl.unwrap_or(z.default_ttl),
                    view_id: r.view_id,
                    rdata,
                });
            }

            store.zones.push(zone);
        }

        // Longest apex first for longest-suffix matching.
        store.zones.sort_by(|a, b| b.label_count.cmp(&a.label_count));
        store
    }

    /// Determine the view id (and name) for a client IP.
    fn view_for(&self, ip: IpAddr) -> Option<(i64, &str)> {
        self.views
            .iter()
            .find(|v| v.matches(ip))
            .map(|v| (v.id, v.name.as_str()))
    }

    /// The authoritative zone whose apex is the longest suffix of `qname`.
    fn zone_for(&self, qname: &Name) -> Option<&StoredZone> {
        self.zones.iter().find(|z| z.apex.zone_of(qname))
    }

    /// Resolve records at one owner name for a view and type, applying
    /// split-horizon override (view-specific hides all-views).
    fn resolve<'a>(
        recs: &'a [StoredRecord],
        view_id: i64,
        rtype: RecordType,
    ) -> Vec<&'a StoredRecord> {
        let specific: Vec<&StoredRecord> = recs
            .iter()
            .filter(|r| r.rtype == rtype && r.view_id == Some(view_id))
            .collect();
        if !specific.is_empty() {
            return specific;
        }
        recs.iter()
            .filter(|r| r.rtype == rtype && r.view_id.is_none())
            .collect()
    }

    /// Find the records at `key`, honoring wildcards (`*.parent`).
    fn records_at<'a>(zone: &'a StoredZone, key: &str) -> Option<&'a Vec<StoredRecord>> {
        if let Some(v) = zone.records.get(key) {
            return Some(v);
        }
        // Wildcard: strip the leftmost label and try `*.rest`, walking upward.
        let labels: Vec<&str> = key.split('.').collect();
        for i in 1..labels.len() {
            let wildcard = format!("*.{}", labels[i..].join("."));
            if let Some(v) = zone.records.get(&wildcard) {
                return Some(v);
            }
        }
        None
    }

    /// Perform an authoritative lookup. Returns [`Outcome::NotAuthoritative`]
    /// when no local zone covers the name (the caller should forward).
    pub fn lookup(&self, qname: &Name, qtype: RecordType, client: IpAddr) -> LookupResult {
        let (view_id, view_name) = match self.view_for(client) {
            Some((id, name)) => (id, Some(name.to_string())),
            None => (i64::MIN, None), // no view -> only all-views records apply
        };

        let Some(zone) = self.zone_for(qname) else {
            return LookupResult {
                answers: vec![],
                authority: vec![],
                rcode: ResponseCode::NoError,
                outcome: Outcome::NotAuthoritative,
                view_name,
            };
        };

        let soa_record = Record::from_rdata(
            zone.apex.clone(),
            zone.soa_ttl,
            RData::SOA(zone.soa.clone()),
        );

        // SOA at the apex is answered from the managed zone SOA.
        if qtype == RecordType::SOA && name_key(qname) == name_key(&zone.apex) {
            return Self::ok(vec![soa_record], view_name);
        }

        let key = name_key(qname);
        let Some(recs) = Self::records_at(zone, &key) else {
            // Name does not exist in the zone.
            return LookupResult {
                answers: vec![],
                authority: vec![soa_record],
                rcode: ResponseCode::NXDomain,
                outcome: Outcome::NxDomain,
                view_name,
            };
        };

        let mut answers = Vec::new();

        if qtype == RecordType::ANY {
            // Return everything visible at this name.
            let mut seen_types = std::collections::BTreeSet::new();
            for r in recs.iter() {
                seen_types.insert(r.rtype);
            }
            for t in seen_types {
                for r in Self::resolve(recs, view_id, t) {
                    answers.push(Record::from_rdata(qname.clone(), r.ttl, r.rdata.clone()));
                }
            }
            if answers.is_empty() {
                return Self::nodata(soa_record, view_name);
            }
            return Self::ok(answers, view_name);
        }

        // Direct type match.
        let direct = Self::resolve(recs, view_id, qtype);
        if !direct.is_empty() {
            for r in direct {
                answers.push(Record::from_rdata(qname.clone(), r.ttl, r.rdata.clone()));
            }
            return Self::ok(answers, view_name);
        }

        // CNAME indirection.
        let cnames = Self::resolve(recs, view_id, RecordType::CNAME);
        if !cnames.is_empty() {
            let mut current = qname.clone();
            let mut depth = 0;
            // Emit the chain, chasing within our authoritative data.
            let mut chase = cnames;
            loop {
                let mut next_target: Option<Name> = None;
                for r in &chase {
                    answers.push(Record::from_rdata(current.clone(), r.ttl, r.rdata.clone()));
                    if let RData::CNAME(cn) = &r.rdata {
                        next_target = Some(cn.0.clone());
                    }
                }
                depth += 1;
                let Some(target) = next_target else { break };
                if depth > 8 {
                    break;
                }
                // Only chase if the target is inside this same zone.
                if !zone.apex.zone_of(&target) {
                    break;
                }
                let tkey = name_key(&target);
                let Some(trecs) = Self::records_at(zone, &tkey) else { break };
                let direct = Self::resolve(trecs, view_id, qtype);
                if !direct.is_empty() {
                    for r in direct {
                        answers.push(Record::from_rdata(target.clone(), r.ttl, r.rdata.clone()));
                    }
                    break;
                }
                let nextc = Self::resolve(trecs, view_id, RecordType::CNAME);
                if nextc.is_empty() {
                    break;
                }
                current = target;
                chase = nextc;
            }
            return Self::ok(answers, view_name);
        }

        // Name exists but no record of the requested type: NODATA.
        Self::nodata(soa_record, view_name)
    }

    fn ok(answers: Vec<Record>, view_name: Option<String>) -> LookupResult {
        LookupResult {
            answers,
            authority: vec![],
            rcode: ResponseCode::NoError,
            outcome: Outcome::Authoritative,
            view_name,
        }
    }

    fn nodata(soa: Record, view_name: Option<String>) -> LookupResult {
        LookupResult {
            answers: vec![],
            authority: vec![soa],
            rcode: ResponseCode::NoError,
            outcome: Outcome::NoData,
            view_name,
        }
    }

    /// Build a full AXFR record stream for the zone at `qname` (must be the
    /// apex), from the requesting client's split-horizon view. The stream is
    /// bracketed by the SOA per RFC 5936. Returns `None` if no such zone.
    pub fn axfr(&self, qname: &Name, client: IpAddr) -> Option<Vec<Record>> {
        let zone = self
            .zones
            .iter()
            .find(|z| name_key(&z.apex) == name_key(qname))?;
        let view_id = self.view_for(client).map(|(id, _)| id).unwrap_or(i64::MIN);

        let soa = Record::from_rdata(
            zone.apex.clone(),
            zone.soa_ttl,
            RData::SOA(zone.soa.clone()),
        );
        let mut out = vec![soa.clone()];

        for (key, recs) in &zone.records {
            let owner = match Name::from_utf8(format!("{key}.")) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let mut types = std::collections::BTreeSet::new();
            for r in recs {
                types.insert(r.rtype);
            }
            for t in types {
                for r in Self::resolve(recs, view_id, t) {
                    out.push(Record::from_rdata(owner.clone(), r.ttl, r.rdata.clone()));
                }
            }
        }

        out.push(soa);
        Some(out)
    }

    /// The DNSSEC signer for the zone covering `qname`, if signed.
    pub fn signer_for(&self, qname: &Name) -> Option<Arc<ZoneSigner>> {
        self.zone_for(qname).and_then(|z| z.signer.clone())
    }

    /// Distinct record types present at `qname` (for the NSEC type bitmap).
    pub fn present_types(&self, qname: &Name) -> Vec<RecordType> {
        let Some(zone) = self.zone_for(qname) else {
            return vec![];
        };
        let key = name_key(qname);
        let mut types = std::collections::BTreeSet::new();
        if let Some(recs) = Self::records_at(zone, &key) {
            for r in recs {
                types.insert(r.rtype);
            }
        }
        types.into_iter().collect()
    }

    pub fn zone_count(&self) -> usize {
        self.zones.len()
    }

    pub fn view_count(&self) -> usize {
        self.views.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::models::Soa;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn qname(s: &str) -> Name {
        Name::from_utf8(s).unwrap()
    }

    fn setup() -> ZoneStore {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            Db::ensure_default_view(c)?;
            let internal = Db::create_view(
                c,
                "internal",
                &["10.0.0.0/8".into(), "192.168.0.0/16".into()],
                10,
            )?;
            let zid = Db::create_zone(c, "home.lan", &Soa::default_for("home.lan"), 300)?;
            Db::create_record(c, zid, None, "@", "NS", None, "ns1.home.lan.")?;
            // Split-horizon A record for nas.
            Db::create_record(c, zid, None, "nas", "A", None, "203.0.113.5")?;
            Db::create_record(c, zid, Some(internal), "nas", "A", None, "10.0.0.5")?;
            // CNAME using a relative target (should qualify to the zone).
            Db::create_record(c, zid, None, "www", "CNAME", None, "nas")?;
            // Wildcard.
            Db::create_record(c, zid, None, "*.dyn", "A", None, "10.9.9.9")?;
            // TXT for NODATA test.
            Db::create_record(c, zid, None, "info", "TXT", None, "hello world")?;
            Ok(())
        })
        .unwrap();
        ZoneStore::load(&db).unwrap()
    }

    #[test]
    fn split_horizon_picks_view_specific_record() {
        let s = setup();
        let internal = s.lookup(&qname("nas.home.lan."), RecordType::A, ip("10.0.0.50"));
        assert_eq!(internal.outcome, Outcome::Authoritative);
        assert_eq!(internal.answers.len(), 1);
        assert_eq!(internal.answers[0].data.to_string(), "10.0.0.5");

        let external = s.lookup(&qname("nas.home.lan."), RecordType::A, ip("8.8.8.8"));
        assert_eq!(external.outcome, Outcome::Authoritative);
        assert_eq!(external.answers[0].data.to_string(), "203.0.113.5");
        assert_eq!(external.view_name.as_deref(), Some("default"));
    }

    #[test]
    fn nxdomain_vs_nodata() {
        let s = setup();
        let nx = s.lookup(&qname("missing.home.lan."), RecordType::A, ip("8.8.8.8"));
        assert_eq!(nx.outcome, Outcome::NxDomain);
        assert_eq!(nx.rcode, ResponseCode::NXDomain);
        assert_eq!(nx.authority.len(), 1, "NXDOMAIN carries SOA");

        // info exists as TXT, so AAAA is NODATA (NOERROR, empty answer + SOA).
        let nodata = s.lookup(&qname("info.home.lan."), RecordType::AAAA, ip("8.8.8.8"));
        assert_eq!(nodata.outcome, Outcome::NoData);
        assert_eq!(nodata.rcode, ResponseCode::NoError);
        assert!(nodata.answers.is_empty());
        assert_eq!(nodata.authority.len(), 1);
    }

    #[test]
    fn outside_zone_is_not_authoritative() {
        let s = setup();
        let r = s.lookup(&qname("example.com."), RecordType::A, ip("8.8.8.8"));
        assert_eq!(r.outcome, Outcome::NotAuthoritative);
    }

    #[test]
    fn cname_chase_within_zone() {
        let s = setup();
        let r = s.lookup(&qname("www.home.lan."), RecordType::A, ip("8.8.8.8"));
        assert_eq!(r.outcome, Outcome::Authoritative);
        // Expect the CNAME plus the chased A record.
        let has_cname = r.answers.iter().any(|a| a.record_type() == RecordType::CNAME);
        let has_a = r
            .answers
            .iter()
            .any(|a| a.record_type() == RecordType::A && a.data.to_string() == "203.0.113.5");
        assert!(has_cname, "answer should contain the CNAME");
        assert!(has_a, "answer should contain the chased A record");
    }

    #[test]
    fn relative_cname_target_is_qualified() {
        let s = setup();
        let r = s.lookup(&qname("www.home.lan."), RecordType::CNAME, ip("8.8.8.8"));
        assert_eq!(r.answers[0].data.to_string(), "nas.home.lan.");
    }

    #[test]
    fn wildcard_matches_and_uses_query_name() {
        let s = setup();
        let r = s.lookup(&qname("anything.dyn.home.lan."), RecordType::A, ip("8.8.8.8"));
        assert_eq!(r.outcome, Outcome::Authoritative);
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].data.to_string(), "10.9.9.9");
        assert_eq!(
            r.answers[0].name.to_string(),
            "anything.dyn.home.lan.",
            "wildcard answer must use the queried name as owner"
        );
    }

    #[test]
    fn soa_at_apex() {
        let s = setup();
        let r = s.lookup(&qname("home.lan."), RecordType::SOA, ip("8.8.8.8"));
        assert_eq!(r.outcome, Outcome::Authoritative);
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].record_type(), RecordType::SOA);
    }
}
