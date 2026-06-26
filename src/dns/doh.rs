//! A self-contained DNS-over-HTTPS (RFC 8484) endpoint supporting both GET
//! (`?dns=<base64url>`) and POST (`application/dns-message` body). It reuses the
//! shared resolve core, so split-horizon, rewrites, blocklists and forwarding
//! all apply. The client IP for split-horizon is the TLS peer address.

use std::net::SocketAddr;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use hickory_proto::op::Message;
use serde::Deserialize;

use crate::dns::resolve::resolve_query;
use crate::state::SharedState;

const DNS_MESSAGE: &str = "application/dns-message";

/// A DoH-only router (used for dedicated DoH listeners).
pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/dns-query", get(doh_get).post(doh_post))
        .with_state(state)
}

/// Register the DoH route onto an existing router (e.g. the web server).
pub fn route(router: Router<SharedState>) -> Router<SharedState> {
    router.route("/dns-query", get(doh_get).post(doh_post))
}

#[derive(Deserialize)]
struct DohParams {
    dns: Option<String>,
}

async fn doh_get(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(params): Query<DohParams>,
) -> Response {
    let Some(b64) = params.dns else {
        return bad_request("missing 'dns' query parameter");
    };
    let trimmed = b64.trim_end_matches('=');
    let Ok(bytes) =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, trimmed)
    else {
        return bad_request("invalid base64url in 'dns'");
    };
    handle(state, peer.ip(), bytes).await
}

async fn doh_post(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Response {
    handle(state, peer.ip(), body.to_vec()).await
}

async fn handle(state: SharedState, client: std::net::IpAddr, bytes: Vec<u8>) -> Response {
    let request = match Message::from_vec(&bytes) {
        Ok(m) => m,
        Err(_) => return bad_request("malformed DNS message"),
    };
    let Some(query) = request.queries.first().cloned() else {
        return bad_request("no query in DNS message");
    };

    let qname = query.name().clone();
    let qtype = query.query_type();
    let dnssec_ok = request
        .edns
        .as_ref()
        .map(|e| e.flags().dnssec_ok)
        .unwrap_or(false);
    let out = resolve_query(&state, &qname, qtype, client, dnssec_ok).await;

    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = out.recursion_available;
    response.metadata.authoritative = out.authoritative;
    response.metadata.response_code = out.rcode;
    response.add_query(query);
    response.add_answers(out.answers);
    response.authorities = out.authority;
    if dnssec_ok {
        if let Some(edns) = &request.edns {
            response.edns = Some(edns.clone());
        }
    }

    match response.to_vec() {
        Ok(buf) => ([(header::CONTENT_TYPE, DNS_MESSAGE)], buf).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "encoding failure").into_response(),
    }
}

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, msg.to_string()).into_response()
}
