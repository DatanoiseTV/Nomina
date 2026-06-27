//! The hickory [`RequestHandler`] for plain DNS, TCP, and DoT. It delegates all
//! resolution logic to the shared [`crate::dns::resolve`] core.

use async_trait::async_trait;
use hickory_proto::op::{Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_server::net::runtime::Time;
use hickory_server::net::xfer::Protocol;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;

use std::net::IpAddr;

use crate::dns::resolve::resolve_query;
use crate::state::SharedState;

pub struct DnsHandler {
    pub state: SharedState,
}

impl DnsHandler {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }
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

        if op_code != OpCode::Query {
            let builder = MessageResponseBuilder::from_message_request(request);
            let response = builder.error_msg(info.metadata, ResponseCode::NotImp);
            return match response_handle.send_response(response).await {
                Ok(i) => i,
                Err(_) => fallback_info(req_id, ResponseCode::NotImp),
            };
        }

        // Zone transfer (TCP/DoT only, IP-allowlisted). IXFR is answered with a
        // full transfer per RFC 1995 (fallback when no incremental journal applies).
        if matches!(qtype, RecordType::AXFR | RecordType::IXFR) {
            return self
                .handle_axfr(
                    request,
                    info.metadata,
                    info.protocol,
                    &qname,
                    client,
                    response_handle,
                )
                .await;
        }

        let dnssec_ok = request
            .edns
            .as_ref()
            .map(|e| e.flags().dnssec_ok)
            .unwrap_or(false);
        let out = resolve_query(&self.state, &qname, qtype, client, dnssec_ok).await;

        let mut meta = Metadata::response_from_request(info.metadata);
        meta.authoritative = out.authoritative;
        meta.recursion_available = out.recursion_available;
        meta.response_code = out.rcode;

        let mut builder = MessageResponseBuilder::from_message_request(request);
        // Echo the client's OPT (with DO) so the response carries EDNS/DNSSEC OK.
        if dnssec_ok {
            if let Some(edns) = &request.edns {
                builder.edns(edns);
            }
        }
        let response = builder.build(
            meta,
            out.answers.iter(),
            std::iter::empty::<&Record>(),
            out.authority.iter(),
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
    /// Serve an AXFR zone transfer to an allow-listed secondary over TCP/DoT.
    async fn handle_axfr<R: ResponseHandler>(
        &self,
        request: &Request,
        req_meta: &Metadata,
        proto: Protocol,
        qname: &Name,
        client: IpAddr,
        response_handle: R,
    ) -> ResponseInfo {
        // AXFR over UDP is invalid; require a connection-oriented transport.
        if proto == Protocol::Udp {
            return self
                .send_code(request, req_meta, response_handle, ResponseCode::Refused)
                .await;
        }
        if !self.state.axfr_allowed(client) {
            tracing::warn!(%client, %qname, "denied AXFR (not allow-listed)");
            return self
                .send_code(request, req_meta, response_handle, ResponseCode::Refused)
                .await;
        }
        // TSIG: verify the request signature against configured keys; require it
        // when configured.
        if self.state.axfr_require_tsig() {
            let keys = self.state.tsig_keys();
            let ok = match request.signature.as_deref() {
                Some(sig) => match crate::dns::tsig::verify_request(&keys, request.as_slice(), sig)
                {
                    Ok(name) => {
                        tracing::debug!(%client, key = %name, "AXFR TSIG verified");
                        true
                    }
                    Err(e) => {
                        tracing::warn!(%client, "AXFR TSIG verification failed: {e}");
                        false
                    }
                },
                None => false,
            };
            if !ok {
                return self
                    .send_code(request, req_meta, response_handle, ResponseCode::Refused)
                    .await;
            }
        }

        match self.state.store().axfr(qname, client) {
            Some(records) => {
                let mut handle = response_handle;
                let mut meta = Metadata::response_from_request(req_meta);
                meta.authoritative = true;
                meta.response_code = ResponseCode::NoError;
                let builder = MessageResponseBuilder::from_message_request(request);
                let response = builder.build(
                    meta,
                    records.iter(),
                    std::iter::empty::<&Record>(),
                    std::iter::empty::<&Record>(),
                    std::iter::empty::<&Record>(),
                );
                tracing::info!(%client, %qname, records = records.len(), "served AXFR");
                match handle.send_response(response).await {
                    Ok(i) => i,
                    Err(_) => fallback_info(req_meta.id, ResponseCode::ServFail),
                }
            }
            None => {
                self.send_code(request, req_meta, response_handle, ResponseCode::Refused)
                    .await
            }
        }
    }

    async fn send_code<R: ResponseHandler>(
        &self,
        request: &Request,
        req_meta: &Metadata,
        mut response_handle: R,
        code: ResponseCode,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);
        let response = builder.error_msg(req_meta, code);
        match response_handle.send_response(response).await {
            Ok(i) => i,
            Err(_) => fallback_info(req_meta.id, code),
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
