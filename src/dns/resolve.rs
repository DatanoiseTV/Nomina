//! The transport-independent resolution core. Plain DNS, DoT, and DoH all funnel
//! through [`resolve_query`], which applies, in order: authoritative local
//! zones, DNS rewrites, blocklist filtering, then upstream
//! forwarding/recursion (or REFUSED in authoritative-only mode).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::filter::{Decision, RewriteTarget};
use crate::models::BlockMode;
use crate::state::AppState;
use crate::stats::QueryOutcome;
use crate::store::Outcome;

const SINKHOLE_TTL: u32 = 60;
const REWRITE_TTL: u32 = 300;

pub struct ResolveOutput {
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub rcode: ResponseCode,
    pub authoritative: bool,
    pub recursion_available: bool,
}

/// Resolve a single query and record statistics.
pub async fn resolve_query(
    state: &AppState,
    qname: &Name,
    qtype: RecordType,
    client: IpAddr,
) -> ResolveOutput {
    let recursion_available = state.upstream().is_some();
    let store = state.store();
    let result = store.lookup(qname, qtype, client);
    let view = result.view_name.clone();

    let (out, stat) = match result.outcome {
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
        Decision::Allow | Decision::Pass => {}
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
