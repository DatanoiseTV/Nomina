//! DynDNS2-compatible update endpoint (`GET /nic/update`).
//!
//! Speaks the de-facto DynDNS2 protocol used by ddclient, routers (FRITZ!Box,
//! UniFi, OpenWrt), and No-IP/Dyn clients: HTTP Basic auth, query parameters
//! `hostname`/`myip`/`myipv6`, and plain-text `good`/`nochg`/`nohost`/`badauth`
//! responses.
//!
//! Authentication is via dedicated [`crate::models::DynDnsToken`]s, each scoped
//! to an explicit hostname list — distinct from the admin login. Because update
//! clients sit on dynamic, remote IPs, this route is intentionally exempt from
//! the management IP allow-list; the per-token credential is the security
//! boundary. Updates upsert A/AAAA records in the matching local zone and bump
//! the zone serial so secondaries, AXFR, and DNSSEC signing pick up the change.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::db::{Db, DynUpdate};
use crate::state::SharedState;
use crate::web::auth::verify_password;

/// Plain-text DynDNS2 response.
fn text(status: StatusCode, body: impl Into<String>) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body.into(),
    )
        .into_response()
}

/// Decode an HTTP Basic `Authorization` header into `(user, pass)`.
fn basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = raw
        .strip_prefix("Basic ")
        .or_else(|| raw.strip_prefix("basic "))?;
    let decoded = STANDARD.decode(b64.trim()).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (u, p) = s.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}

pub async fn nic_update(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    // ----- authenticate -----
    let Some((user, pass)) = basic_auth(&headers) else {
        return text(StatusCode::UNAUTHORIZED, "badauth");
    };
    let lookup_user = user.clone();
    let auth = match state
        .db
        .run(move |c| Db::dyndns_auth(c, &lookup_user))
        .await
    {
        Ok(Some(a)) if a.enabled => a,
        Ok(_) => return text(StatusCode::UNAUTHORIZED, "badauth"),
        Err(e) => {
            tracing::error!("dyndns auth lookup failed: {e}");
            return text(StatusCode::INTERNAL_SERVER_ERROR, "911");
        }
    };
    if !verify_password(&pass, &auth.secret_hash) {
        return text(StatusCode::UNAUTHORIZED, "badauth");
    }

    // ----- resolve the addresses to set (at most one per family) -----
    let mut v4: Option<IpAddr> = None;
    let mut v6: Option<IpAddr> = None;
    for key in ["myip", "myipv6", "ip"] {
        if let Some(val) = params.get(key) {
            for tok in val.split(',') {
                match tok.trim().parse::<IpAddr>() {
                    Ok(ip @ IpAddr::V4(_)) if v4.is_none() => v4 = Some(ip),
                    Ok(ip @ IpAddr::V6(_)) if v6.is_none() => v6 = Some(ip),
                    _ => {}
                }
            }
        }
    }
    if v4.is_none() && v6.is_none() {
        match peer.ip() {
            ip @ IpAddr::V4(_) => v4 = Some(ip),
            ip @ IpAddr::V6(_) => v6 = Some(ip),
        }
    }
    let addrs: Vec<IpAddr> = v4.into_iter().chain(v6).collect();

    // ----- hostnames -----
    let hosts: Vec<String> = match params.get("hostname").or_else(|| params.get("host")) {
        Some(h) => h
            .split(',')
            .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect(),
        None => return text(StatusCode::BAD_REQUEST, "notfqdn"),
    };
    if hosts.is_empty() {
        return text(StatusCode::BAD_REQUEST, "notfqdn");
    }

    let mut lines = Vec::with_capacity(hosts.len());
    let mut any_change = false;
    let ip_label = addrs
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",");

    for host in &hosts {
        // Scope check: a token may only repoint hostnames it owns.
        if !auth.hostnames.iter().any(|h| h == host) {
            lines.push("nohost".to_string());
            continue;
        }
        let mut changed = false;
        let mut had_zone = false;
        for &ip in &addrs {
            let h = host.clone();
            let view = auth.view_id;
            let ttl = auth.ttl;
            match state
                .db
                .run(move |c| Db::dyndns_set_address(c, &h, ip, view, ttl))
                .await
            {
                Ok(DynUpdate::Created) | Ok(DynUpdate::Updated) => {
                    changed = true;
                    had_zone = true;
                }
                Ok(DynUpdate::Unchanged) => had_zone = true,
                Ok(DynUpdate::NoZone) => {}
                Err(e) => {
                    tracing::error!(%host, "dyndns update failed: {e}");
                    return text(StatusCode::INTERNAL_SERVER_ERROR, "911");
                }
            }
        }
        if !had_zone {
            lines.push("nohost".to_string());
        } else if changed {
            any_change = true;
            lines.push(format!("good {ip_label}"));
        } else {
            lines.push(format!("nochg {ip_label}"));
        }
    }

    if any_change {
        if let Err(e) = state.reload_store() {
            tracing::error!("dyndns store reload failed: {e}");
            return text(StatusCode::INTERNAL_SERVER_ERROR, "911");
        }
    }
    // Record the update against the token for the UI/audit trail.
    let token_id = auth.id;
    let last_ip = ip_label.clone();
    let _ = state
        .db
        .run(move |c| Db::touch_dyndns_token(c, token_id, &last_ip))
        .await;

    text(StatusCode::OK, lines.join("\n"))
}
