//! The DNS [`RequestHandler`]: split-horizon authoritative lookup with upstream
//! forwarding for everything else.

use async_trait::async_trait;
use hickory_proto::op::{Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_server::net::runtime::Time;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;

use crate::state::SharedState;
use crate::stats::QueryOutcome;
use crate::store::Outcome;

pub struct DnsHandler {
    pub state: SharedState,
}

impl DnsHandler {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }
}

struct Resolved {
    answers: Vec<Record>,
    authority: Vec<Record>,
    rcode: ResponseCode,
    authoritative: bool,
    stat: QueryOutcome,
    view: Option<String>,
}

#[async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let info = match request.request_info() {
            Ok(i) => i,
            Err(e) => {
                tracing::debug!("malformed request: {e}");
                return fallback_info(0, ResponseCode::FormErr);
            }
        };

        let client = info.src.ip();
        let qtype = info.query.query_type();
        let qname: Name = info.query.original().name().clone();
        let op_code = info.metadata.op_code;
        let req_id = info.metadata.id;

        // We only answer standard queries.
        if op_code != OpCode::Query {
            return self
                .send_error(request, info.metadata, response_handle, ResponseCode::NotImp)
                .await;
        }

        let recursion_available = self
            .state
            .forwarder()
            .map(|f| f.enabled)
            .unwrap_or(false);

        let resolved = self.resolve(&qname, qtype, client).await;

        // Record statistics (best-effort, never blocks the response).
        self.state.stats.record(
            client.to_string(),
            resolved.view.clone(),
            qname.to_string().trim_end_matches('.').to_string(),
            qtype.to_string(),
            resolved.stat,
            format!("{:?}", resolved.rcode).to_uppercase(),
        );

        let mut meta = Metadata::response_from_request(info.metadata);
        meta.authoritative = resolved.authoritative;
        meta.recursion_available = recursion_available;
        meta.response_code = resolved.rcode;

        let builder = MessageResponseBuilder::from_message_request(request);
        let response = builder.build(
            meta,
            resolved.answers.iter(),
            std::iter::empty::<&Record>(),
            resolved.authority.iter(),
            std::iter::empty::<&Record>(),
        );

        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                tracing::warn!(%qname, "failed to send response: {e}");
                fallback_info(req_id, ResponseCode::ServFail)
            }
        }
    }
}

impl DnsHandler {
    /// Resolve a query: authoritative first, then forward.
    async fn resolve(&self, qname: &Name, qtype: RecordType, client: std::net::IpAddr) -> Resolved {
        let store = self.state.store();
        let result = store.lookup(qname, qtype, client);

        match result.outcome {
            Outcome::Authoritative | Outcome::NoData => Resolved {
                answers: result.answers,
                authority: result.authority,
                rcode: result.rcode,
                authoritative: true,
                stat: QueryOutcome::Authoritative,
                view: result.view_name,
            },
            Outcome::NxDomain => Resolved {
                answers: result.answers,
                authority: result.authority,
                rcode: ResponseCode::NXDomain,
                authoritative: true,
                stat: QueryOutcome::NxDomain,
                view: result.view_name,
            },
            Outcome::NotAuthoritative => {
                // Forward to upstream if enabled.
                match self.state.forwarder() {
                    Some(fw) if fw.enabled => {
                        let fr = fw.resolve(qname, qtype).await;
                        let stat = match fr.rcode {
                            ResponseCode::NXDomain => QueryOutcome::NxDomain,
                            ResponseCode::ServFail => QueryOutcome::ServFail,
                            _ => QueryOutcome::Forwarded,
                        };
                        Resolved {
                            answers: fr.answers,
                            authority: fr.authority,
                            rcode: fr.rcode,
                            authoritative: false,
                            stat,
                            view: result.view_name,
                        }
                    }
                    _ => Resolved {
                        answers: vec![],
                        authority: vec![],
                        rcode: ResponseCode::Refused,
                        authoritative: false,
                        stat: QueryOutcome::Refused,
                        view: result.view_name,
                    },
                }
            }
        }
    }

    async fn send_error<R: ResponseHandler>(
        &self,
        request: &Request,
        request_meta: &Metadata,
        mut response_handle: R,
        code: ResponseCode,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);
        let response = builder.error_msg(request_meta, code);
        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(_) => fallback_info(request_meta.id, code),
        }
    }
}

/// Build a [`ResponseInfo`] without sending, for paths where sending failed or
/// the request could not be parsed.
fn fallback_info(id: u16, code: ResponseCode) -> ResponseInfo {
    let mut metadata = Metadata::new(id, MessageType::Response, OpCode::Query);
    metadata.response_code = code;
    ResponseInfo::from(Header {
        metadata,
        counts: HeaderCounts::default(),
    })
}
