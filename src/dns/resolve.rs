//! The transport-independent resolution core. Plain DNS, DoT, and DoH all funnel
//! through [`resolve_query`], which applies, in order: authoritative local
//! zones, DNS rewrites, blocklist filtering, then upstream
//! forwarding/recursion (or REFUSED in authoritative-only mode).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use rand::seq::SliceRandom;

use crate::dns::dnssec::ZoneSigner;
use crate::filter::{Decision, RewriteTarget};
use crate::models::{BlockMode, LoadBalance};
use crate::state::AppState;
use crate::stats::QueryOutcome;
use crate::store::{Outcome, ZoneStore};

const SINKHOLE_TTL: u32 = 60;
const REWRITE_TTL: u32 = 300;

pub struct ResolveOutput {
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub rcode: ResponseCode,
    pub authoritative: bool,
    pub recursion_available: bool,
}

/// Resolve a single query and record statistics. `dnssec_ok` reflects the
/// client's EDNS DO bit; when set on a signed zone the response is signed.
pub async fn resolve_query(
    state: &AppState,
    qname: &Name,
    qtype: RecordType,
    client: IpAddr,
    dnssec_ok: bool,
) -> ResolveOutput {
    let started = std::time::Instant::now();
    let recursion_available = state.upstream().is_some();
    let store = state.store();

    // Resolve the client's geo attributes once (cheap no-op when no database is
    // configured); used for geo-targeted views and ASN blocking.
    let geo = state.geo().lookup(client);

    // ASN blocking: reject queries from blocked autonomous systems outright.
    let blocked_asns = state.blocked_asns();
    if !blocked_asns.is_empty() {
        if let Some(asn) = geo.asn {
            if blocked_asns.contains(&asn) {
                let out = block_answer(state.block_mode(), qname, qtype, recursion_available);
                record_stat(
                    state,
                    client,
                    None,
                    qname,
                    qtype,
                    QueryOutcome::Blocked,
                    &out,
                );
                state.stats.record_latency(started.elapsed());
                return out;
            }
        }
    }

    // Apex DNSKEY is synthesized from the zone's signing key, not stored.
    if dnssec_ok && qtype == RecordType::DNSKEY {
        if let Some(signer) = store.signer_for(qname) {
            if same_name(qname, &signer.apex) {
                let out = ResolveOutput {
                    answers: signer.dnskey_rrset(),
                    authority: vec![],
                    rcode: ResponseCode::NoError,
                    authoritative: true,
                    recursion_available,
                };
                record_stat(
                    state,
                    client,
                    None,
                    qname,
                    qtype,
                    QueryOutcome::Authoritative,
                    &out,
                );
                return out;
            }
        }
    }

    // Apex NSEC3PARAM is synthesized from the zone's NSEC3 parameters.
    if dnssec_ok && qtype == RecordType::NSEC3PARAM {
        if let Some(signer) = store.signer_for(qname) {
            if signer.uses_nsec3() && same_name(qname, &signer.apex) {
                let out = ResolveOutput {
                    answers: signer.nsec3param_rrset(),
                    authority: vec![],
                    rcode: ResponseCode::NoError,
                    authoritative: true,
                    recursion_available,
                };
                record_stat(
                    state,
                    client,
                    None,
                    qname,
                    qtype,
                    QueryOutcome::Authoritative,
                    &out,
                );
                return out;
            }
        }
    }

    let result = store.lookup(qname, qtype, client, &geo);
    let view = result.view_name.clone();
    let outcome = result.outcome;

    let (mut out, stat) = match outcome {
        Outcome::Authoritative | Outcome::NoData => (
            ResolveOutput {
                answers: result.answers,
                authority: result.authority,
                rcode: result.rcode,
                authoritative: true,
                recursion_available,
            },
            QueryOutcome::Authoritative,
        ),
        Outcome::NxDomain => (
            ResolveOutput {
                answers: result.answers,
                authority: result.authority,
                rcode: ResponseCode::NXDomain,
                authoritative: true,
                recursion_available,
            },
            QueryOutcome::NxDomain,
        ),
        Outcome::NotAuthoritative => {
            resolve_external(state, qname, qtype, recursion_available).await
        }
    };

    // DNSSEC: sign authoritative answers / prove denials on signed zones.
    if dnssec_ok && outcome != Outcome::NotAuthoritative {
        if let Some(signer) = store.signer_for(qname) {
            apply_dnssec(&signer, &store, qname, outcome, &mut out);
        }
    }

    // Spread multi-address answers per the load-balancing setting.
    apply_load_balance(&mut out.answers, state.load_balance(), || {
        state.next_rotation()
    });

    // Track public answer IPs for the geo map.
    state
        .stats
        .record_resolved(out.answers.iter().filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        }));

    if let Some(entry) = state.stats.record(
        state.query_log(),
        client,
        view,
        qname.to_string().trim_end_matches('.').to_string(),
        qtype.to_string(),
        stat,
        format!("{:?}", out.rcode).to_uppercase(),
    ) {
        state.log_query(entry);
    }
    state.stats.record_latency(started.elapsed());
    out
}

/// Reorder the address records (A and AAAA, each among themselves) of an answer
/// set per the load-balancing strategy. `rotation` supplies the round-robin
/// offset and is only called when needed.
fn apply_load_balance(answers: &mut [Record], mode: LoadBalance, rotation: impl Fn() -> u64) {
    if mode == LoadBalance::Off || answers.len() < 2 {
        return;
    }
    let offset = if mode == LoadBalance::RoundRobin {
        rotation() as usize
    } else {
        0
    };
    for rtype in [RecordType::A, RecordType::AAAA] {
        let idxs: Vec<usize> = answers
            .iter()
            .enumerate()
            .filter(|(_, r)| r.record_type() == rtype)
            .map(|(i, _)| i)
            .collect();
        if idxs.len() < 2 {
            continue;
        }
        let mut group: Vec<Record> = idxs.iter().map(|&i| answers[i].clone()).collect();
        let len = group.len();
        match mode {
            LoadBalance::RoundRobin => group.rotate_left(offset % len),
            LoadBalance::Random => group.shuffle(&mut rand::thread_rng()),
            LoadBalance::Off => {}
        }
        for (slot, &i) in idxs.iter().enumerate() {
            answers[i] = group[slot].clone();
        }
    }
}

fn same_name(a: &Name, b: &Name) -> bool {
    a.to_string()
        .trim_end_matches('.')
        .eq_ignore_ascii_case(b.to_string().trim_end_matches('.'))
}

fn record_stat(
    state: &AppState,
    client: IpAddr,
    view: Option<String>,
    qname: &Name,
    qtype: RecordType,
    stat: QueryOutcome,
    out: &ResolveOutput,
) {
    if let Some(entry) = state.stats.record(
        state.query_log(),
        client,
        view,
        qname.to_string().trim_end_matches('.').to_string(),
        qtype.to_string(),
        stat,
        format!("{:?}", out.rcode).to_uppercase(),
    ) {
        state.log_query(entry);
    }
}

/// A signed denial proof for `owner`, using NSEC3 when the zone enables it.
fn denial(signer: &ZoneSigner, owner: &Name, present: &[RecordType], ttl: u32) -> Vec<Record> {
    if signer.uses_nsec3() {
        signer.nsec3_records(owner, present, ttl)
    } else {
        signer.nsec_records(owner, present, ttl)
    }
}

/// Sign authoritative answers, or prove a denial (NSEC/NSEC3), on a signed zone.
fn apply_dnssec(
    signer: &ZoneSigner,
    store: &ZoneStore,
    qname: &Name,
    outcome: Outcome,
    out: &mut ResolveOutput,
) {
    match outcome {
        Outcome::Authoritative => signer.sign_records(&mut out.answers),
        Outcome::NoData => {
            let ttl = out.authority.first().map(|r| r.ttl).unwrap_or(60);
            signer.sign_records(&mut out.authority);
            let present = store.present_types(qname);
            out.authority.extend(denial(signer, qname, &present, ttl));
        }
        Outcome::NxDomain => {
            // Black lie: return NOERROR with a signed NSEC/NSEC3 denying the name.
            out.rcode = ResponseCode::NoError;
            let ttl = out.authority.first().map(|r| r.ttl).unwrap_or(60);
            signer.sign_records(&mut out.authority);
            out.authority.extend(denial(signer, qname, &[], ttl));
        }
        Outcome::NotAuthoritative => {}
    }
}

/// Names not covered by a local zone: apply rewrites/blocklist, then upstream.
async fn resolve_external(
    state: &AppState,
    qname: &Name,
    qtype: RecordType,
    recursion_available: bool,
) -> (ResolveOutput, QueryOutcome) {
    let key = qname.to_string().trim_end_matches('.').to_ascii_lowercase();

    let filter = state.filter();
    match filter.decide(&key) {
        Decision::Rewrite(target) => {
            return rewrite_answer(state, qname, qtype, target, recursion_available).await;
        }
        Decision::Block => {
            // Attribute the block to its source blocklist (if not a deny rule).
            if let Some(id) = filter.blocklist_hit(&key) {
                state.stats.record_blocklist_hit(id);
            }
            return (
                block_answer(state.block_mode(), qname, qtype, recursion_available),
                QueryOutcome::Blocked,
            );
        }
        // An explicit allow rule exempts the name from homograph filtering too.
        Decision::Allow => {}
        Decision::Pass => {
            if crate::dns::homograph::is_suspicious(&key, state.homograph_mode()) {
                return (
                    block_answer(state.block_mode(), qname, qtype, recursion_available),
                    QueryOutcome::Dangerous,
                );
            }
        }
    }

    // Conditional forwarding: a per-domain upstream takes precedence over the
    // global resolver (and works even in authoritative-only mode).
    if let Some(up) = state.conditional().match_for(&key) {
        let r = up.resolve(qname, qtype).await;
        if r.rcode == ResponseCode::ServFail && state.dnssec_validate_upstream() {
            state.stats.record_dnssec_failure();
        }
        let stat = match r.rcode {
            ResponseCode::NXDomain => QueryOutcome::NxDomain,
            ResponseCode::ServFail => QueryOutcome::ServFail,
            _ => QueryOutcome::Forwarded,
        };
        return (
            ResolveOutput {
                answers: r.answers,
                authority: r.authority,
                rcode: r.rcode,
                authoritative: false,
                recursion_available: true,
            },
            stat,
        );
    }

    match state.upstream() {
        Some(up) => {
            let cache = state.cache();
            let now = std::time::Instant::now();
            // Serve hot names from the edge cache, skipping the upstream round-trip.
            if let Some(c) = cache.get(qname, qtype, now) {
                return (
                    ResolveOutput {
                        answers: c.answers,
                        authority: c.authority,
                        rcode: c.rcode,
                        authoritative: false,
                        recursion_available,
                    },
                    QueryOutcome::Cached,
                );
            }
            let r = up.resolve(qname, qtype).await;
            // A SERVFAIL while validation is enabled is, in practice, the
            // resolver rejecting a bogus answer (validation fails closed).
            if r.rcode == ResponseCode::ServFail && state.dnssec_validate_upstream() {
                state.stats.record_dnssec_failure();
            }
            cache.put(qname, qtype, &r.answers, &r.authority, r.rcode, now);
            let stat = match r.rcode {
                ResponseCode::NXDomain => QueryOutcome::NxDomain,
                ResponseCode::ServFail => QueryOutcome::ServFail,
                _ => QueryOutcome::Forwarded,
            };
            (
                ResolveOutput {
                    answers: r.answers,
                    authority: r.authority,
                    rcode: r.rcode,
                    authoritative: false,
                    recursion_available,
                },
                stat,
            )
        }
        // Authoritative-only mode: refuse anything we don't own.
        None => (
            ResolveOutput {
                answers: vec![],
                authority: vec![],
                rcode: ResponseCode::Refused,
                authoritative: false,
                recursion_available,
            },
            QueryOutcome::Refused,
        ),
    }
}

fn block_answer(
    mode: BlockMode,
    qname: &Name,
    qtype: RecordType,
    recursion_available: bool,
) -> ResolveOutput {
    let base = |answers, rcode, authoritative| ResolveOutput {
        answers,
        authority: vec![],
        rcode,
        authoritative,
        recursion_available,
    };
    match mode {
        BlockMode::NxDomain => base(vec![], ResponseCode::NXDomain, true),
        BlockMode::Refused => base(vec![], ResponseCode::Refused, false),
        BlockMode::ZeroIp => {
            let mut answers = Vec::new();
            if matches!(qtype, RecordType::A | RecordType::ANY) {
                answers.push(Record::from_rdata(
                    qname.clone(),
                    SINKHOLE_TTL,
                    RData::A(A(Ipv4Addr::UNSPECIFIED)),
                ));
            }
            if matches!(qtype, RecordType::AAAA | RecordType::ANY) {
                answers.push(Record::from_rdata(
                    qname.clone(),
                    SINKHOLE_TTL,
                    RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)),
                ));
            }
            base(answers, ResponseCode::NoError, true)
        }
    }
}

async fn rewrite_answer(
    state: &AppState,
    qname: &Name,
    qtype: RecordType,
    target: RewriteTarget,
    recursion_available: bool,
) -> (ResolveOutput, QueryOutcome) {
    let mut answers = Vec::new();
    match target {
        RewriteTarget::Ip(ip) => match (qtype, ip) {
            (RecordType::A | RecordType::ANY, IpAddr::V4(v4)) => {
                answers.push(Record::from_rdata(
                    qname.clone(),
                    REWRITE_TTL,
                    RData::A(A(v4)),
                ));
            }
            (RecordType::AAAA | RecordType::ANY, IpAddr::V6(v6)) => {
                answers.push(Record::from_rdata(
                    qname.clone(),
                    REWRITE_TTL,
                    RData::AAAA(AAAA(v6)),
                ));
            }
            // Mismatched address family for the query type: NODATA.
            _ => {}
        },
        RewriteTarget::Name(target_name) => {
            answers.push(Record::from_rdata(
                qname.clone(),
                REWRITE_TTL,
                RData::CNAME(CNAME(target_name.clone())),
            ));
            // Resolve the target to concrete addresses when possible.
            if matches!(qtype, RecordType::A | RecordType::AAAA) {
                if let Some(up) = state.upstream() {
                    let r = up.resolve(&target_name, qtype).await;
                    answers.extend(r.answers);
                }
            }
        }
    }

    (
        ResolveOutput {
            answers,
            authority: vec![],
            rcode: ResponseCode::NoError,
            authoritative: true,
            recursion_available,
        },
        QueryOutcome::Rewritten,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn a_records(ips: &[&str]) -> Vec<Record> {
        ips.iter()
            .map(|s| {
                Record::from_rdata(
                    Name::root(),
                    300,
                    RData::A(A(s.parse::<Ipv4Addr>().unwrap())),
                )
            })
            .collect()
    }

    #[test]
    fn round_robin_rotates_addresses() {
        let mut ans = a_records(&["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
        apply_load_balance(&mut ans, LoadBalance::RoundRobin, || 1);
        let got: Vec<String> = ans.iter().map(|r| r.data.to_string()).collect();
        assert_eq!(got, vec!["2.2.2.2", "3.3.3.3", "1.1.1.1"]);
    }

    #[test]
    fn off_keeps_order() {
        let mut ans = a_records(&["1.1.1.1", "2.2.2.2"]);
        apply_load_balance(&mut ans, LoadBalance::Off, || 99);
        assert_eq!(ans[0].data.to_string(), "1.1.1.1");
        assert_eq!(ans[1].data.to_string(), "2.2.2.2");
    }

    #[test]
    fn random_preserves_the_set() {
        let mut ans = a_records(&["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
        apply_load_balance(&mut ans, LoadBalance::Random, || 0);
        let mut got: Vec<String> = ans.iter().map(|r| r.data.to_string()).collect();
        got.sort();
        assert_eq!(got, vec!["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
    }
}
