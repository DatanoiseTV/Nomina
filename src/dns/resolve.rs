//! The transport-independent resolution core. Plain DNS, DoT, and DoH all funnel
//! through [`resolve_query`], which applies, in order: authoritative local
//! zones, DNS rewrites, blocklist filtering, then upstream
//! forwarding/recursion (or REFUSED in authoritative-only mode).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::dns::dnssec::ZoneSigner;
use crate::filter::{Decision, RewriteTarget};
use crate::models::BlockMode;
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
    let recursion_available = state.upstream().is_some();
    let store = state.store();

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
                record_stat(state, client, None, qname, qtype, QueryOutcome::Authoritative, &out);
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
                record_stat(state, client, None, qname, qtype, QueryOutcome::Authoritative, &out);
                return out;
            }
        }
    }

    let result = store.lookup(qname, qtype, client);
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
        Outcome::NotAuthoritative => resolve_external(state, qname, qtype, recursion_available).await,
    };

    // DNSSEC: sign authoritative answers / prove denials on signed zones.
    if dnssec_ok && outcome != Outcome::NotAuthoritative {
        if let Some(signer) = store.signer_for(qname) {
            apply_dnssec(&signer, &store, qname, outcome, &mut out);
        }
    }

    state.stats.record(
        state.query_log(),
        client,
        view,
        qname.to_string().trim_end_matches('.').to_string(),
        qtype.to_string(),
        stat,
        format!("{:?}", out.rcode).to_uppercase(),
    );
    out
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
    state.stats.record(
        state.query_log(),
        client,
        view,
        qname.to_string().trim_end_matches('.').to_string(),
        qtype.to_string(),
        stat,
        format!("{:?}", out.rcode).to_uppercase(),
    );
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

    match state.filter().decide(&key) {
        Decision::Rewrite(target) => {
            return rewrite_answer(state, qname, qtype, target, recursion_available).await;
        }
        Decision::Block => {
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
                    QueryOutcome::Blocked,
                );
            }
        }
    }

    // Conditional forwarding: a per-domain upstream takes precedence over the
    // global resolver (and works even in authoritative-only mode).
    if let Some(up) = state.conditional().match_for(&key) {
        let r = up.resolve(qname, qtype).await;
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
            let r = up.resolve(qname, qtype).await;
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
                answers.push(Record::from_rdata(qname.clone(), REWRITE_TTL, RData::A(A(v4))));
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
