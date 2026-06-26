//! JSON management API handlers. See `docs/api-contract.md`.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::Duration as TimeDuration;

use crate::db::Db;
use crate::dns::server::listener_infos;
use crate::error::{ApiResult, AppError};
use crate::models::*;
use crate::state::SharedState;
use crate::web::auth::*;

const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ok_json(value: Value) -> Response {
    (StatusCode::OK, Json(value)).into_response()
}

fn created_json(value: Value) -> Response {
    (StatusCode::CREATED, Json(value)).into_response()
}

fn with_cookies(status: StatusCode, value: Value, cookies: Vec<String>) -> Response {
    let mut resp = (status, Json(value)).into_response();
    for c in cookies {
        if let Ok(hv) = HeaderValue::from_str(&c) {
            resp.headers_mut().append(SET_COOKIE, hv);
        }
    }
    resp
}

fn validation_field(field: &str, reason: &str) -> AppError {
    let mut fields = BTreeMap::new();
    fields.insert(field.to_string(), reason.to_string());
    AppError::validation("Validation failed").with_fields(fields)
}

fn valid_view_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 40
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

// ---------------------------------------------------------------------------
// Health / status / stats
// ---------------------------------------------------------------------------

pub async fn health() -> Response {
    ok_json(json!({ "status": "ok", "version": VERSION }))
}

/// Prometheus metrics (aggregate, non-identifying). Unauthenticated like
/// `/health`; protect via the management bind address / `allow_networks`.
pub async fn metrics(State(state): State<SharedState>) -> Response {
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.stats.prometheus(),
    )
        .into_response()
}

pub async fn status(State(state): State<SharedState>, _auth: Authed) -> ApiResult<Response> {
    let store = state.store();
    let filter = state.filter();
    let zones = state.db.run(Db::list_zones).await?;
    let record_count: i64 = zones.iter().map(|z| z.record_count).sum();
    Ok(ok_json(json!({
        "version": VERSION,
        "uptime_seconds": state.stats.uptime_seconds(),
        "started_at": state.stats.started_at(),
        "listeners": listener_infos(&state.config),
        "management": {
            "addr": state.config.web.listen.to_string(),
            "scheme": if state.config.web.tls { "https" } else { "http" },
            "disabled": state.config.web.disabled,
            "allow_networks": state.config.web.allow_networks,
        },
        "zone_count": zones.len(),
        "active_zone_count": store.zone_count(),
        "record_count": record_count,
        "view_count": store.view_count(),
        "resolution_mode": state.resolution_mode(),
        "blocked_domains": filter.blocked_count(),
        "rewrite_count": filter.rewrite_count(),
        "conditional_forward_count": state.conditional().len(),
    })))
}

pub async fn stats(State(state): State<SharedState>, _auth: Authed) -> Response {
    let mut snap = state.stats.snapshot();
    let (hits, misses, size) = state.cache().stats(std::time::Instant::now());
    let lookups = hits + misses;
    let hit_rate = if lookups > 0 {
        (hits as f64 / lookups as f64 * 1000.0).round() / 1000.0
    } else {
        0.0
    };
    if let Some(obj) = snap.as_object_mut() {
        obj.insert("query_log".into(), json!(state.query_log()));
        obj.insert(
            "cache".into(),
            json!({ "hits": hits, "misses": misses, "size": size, "hit_rate": hit_rate }),
        );
    }
    ok_json(snap)
}

/// Clear retained per-query detail (recent queries + top domains).
pub async fn clear_stats(State(state): State<SharedState>, _auth: Authed) -> Response {
    state.stats.clear_log();
    state.cache().clear();
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
pub struct QueryLogParams {
    page: Option<i64>,
    per_page: Option<i64>,
    q: Option<String>,
    outcome: Option<String>,
    qtype: Option<String>,
    sort: Option<String>,
    desc: Option<bool>,
}

/// Paginated, filterable, sortable persistent query log.
pub async fn query_log(
    State(state): State<SharedState>,
    _auth: Authed,
    Query(p): Query<QueryLogParams>,
) -> ApiResult<Response> {
    let page = p.page.unwrap_or(1).max(1);
    let per_page = p.per_page.unwrap_or(50).clamp(1, 500);
    let offset = (page - 1) * per_page;
    let sort = p.sort.unwrap_or_else(|| "at".into());
    let desc = p.desc.unwrap_or(true);
    let (rows, total) = state
        .db
        .run(move |c| {
            Db::query_log_page(
                c,
                p.q.as_deref(),
                p.outcome.as_deref(),
                p.qtype.as_deref(),
                &sort,
                desc,
                per_page,
                offset,
            )
        })
        .await?;
    Ok(ok_json(json!({
        "queries": rows,
        "total": total,
        "page": page,
        "per_page": per_page,
    })))
}

/// Clear the persistent query log.
pub async fn clear_query_log(State(state): State<SharedState>, _auth: Authed) -> ApiResult<Response> {
    state.db.run(|c| Db::prune_query_log(c, 0)).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

async fn start_session(state: &SharedState, user_id: i64) -> ApiResult<(String, String)> {
    let token = random_token();
    let csrf = random_token();
    let hashed = hash_session_id(&token);
    let csrf_db = csrf.clone();
    let expires = OffsetDateTime::now_utc() + TimeDuration::seconds(SESSION_TTL_SECS);
    state
        .db
        .run(move |c| Db::create_session(c, &hashed, user_id, &csrf_db, expires))
        .await?;
    Ok((token, csrf))
}

fn session_cookies(state: &SharedState, token: &str, csrf: &str) -> Vec<String> {
    let secure = state.config.web.tls;
    vec![
        session_cookie(token, secure, SESSION_TTL_SECS),
        csrf_cookie(csrf, secure, SESSION_TTL_SECS),
    ]
}

pub async fn login(
    State(state): State<SharedState>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Response> {
    let throttle_key = req.username.to_ascii_lowercase();
    if state.is_locked_out(&throttle_key) {
        return Err(AppError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "Too many failed attempts; try again later",
        ));
    }

    let username = req.username.clone();
    let row = state
        .db
        .run(move |c| Db::user_by_username(c, &username))
        .await?;

    let valid = match &row {
        Some(u) => verify_password(&req.password, &u.password_hash),
        // Run a dummy verify to reduce username-enumeration timing differences.
        None => {
            let _ = verify_password(
                &req.password,
                "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
            );
            false
        }
    };

    let Some(user) = row else {
        state.record_login_failure(&throttle_key);
        return Err(AppError::unauthorized());
    };
    if !valid {
        state.record_login_failure(&throttle_key);
        return Err(AppError::unauthorized());
    }

    state.clear_login_failures(&throttle_key);
    let (token, csrf) = start_session(&state, user.id).await?;
    Ok(with_cookies(
        StatusCode::OK,
        json!({ "user": user.public() }),
        session_cookies(&state, &token, &csrf),
    ))
}

pub async fn logout(
    State(state): State<SharedState>,
    headers: HeaderMap,
    _auth: Authed,
) -> ApiResult<Response> {
    let cookies = parse_cookies(&headers);
    if let Some(token) = cookies.get(SESSION_COOKIE) {
        let hashed = hash_session_id(token);
        let _ = state.db.run(move |c| Db::delete_session(c, &hashed)).await;
    }
    let secure = state.config.web.tls;
    let clear = vec![
        session_cookie("", secure, 0),
        csrf_cookie("", secure, 0),
    ];
    Ok(with_cookies(StatusCode::NO_CONTENT, json!({}), clear))
}

pub async fn me(State(state): State<SharedState>, headers: HeaderMap) -> ApiResult<Response> {
    let count = state.db.run(Db::user_count).await?;
    if count == 0 {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "setup_required",
            "No administrator account exists yet",
        ));
    }
    let authed = resolve_session(&state, &headers).await?;
    Ok(ok_json(json!({ "user": authed.user })))
}

#[derive(Deserialize)]
pub struct SetupRequest {
    username: String,
    password: String,
}

pub async fn setup(
    State(state): State<SharedState>,
    Json(req): Json<SetupRequest>,
) -> ApiResult<Response> {
    if req.username.trim().is_empty() {
        return Err(validation_field("username", "must not be empty"));
    }
    if req.password.len() < 12 {
        return Err(validation_field("password", "must be at least 12 characters"));
    }

    let username = req.username.trim().to_string();
    let hash = hash_password(&req.password)?;
    let user_id = state
        .db
        .run(move |c| {
            if Db::user_count(c)? > 0 {
                return Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
                    Some("setup already completed".into()),
                ));
            }
            Db::create_user(c, &username, &hash, false)
        })
        .await
        .map_err(|e| match e {
            AppError { status, .. } if status == StatusCode::CONFLICT => {
                AppError::conflict("Setup already completed")
            }
            other => other,
        })?;

    let user = state
        .db
        .run(move |c| Db::user_by_id(c, user_id))
        .await?
        .ok_or_else(|| AppError::internal("user vanished after creation"))?;

    let (token, csrf) = start_session(&state, user_id).await?;
    Ok(with_cookies(
        StatusCode::CREATED,
        json!({ "user": user.public() }),
        session_cookies(&state, &token, &csrf),
    ))
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

pub async fn change_password(
    State(state): State<SharedState>,
    auth: Authed,
    Json(req): Json<ChangePasswordRequest>,
) -> ApiResult<Response> {
    if req.new_password.len() < 12 {
        return Err(validation_field("new_password", "must be at least 12 characters"));
    }
    let uid = auth.user.id;
    let row = state
        .db
        .run(move |c| Db::user_by_id(c, uid))
        .await?
        .ok_or_else(AppError::unauthorized)?;
    if !verify_password(&req.current_password, &row.password_hash) {
        return Err(AppError::forbidden("Current password is incorrect"));
    }
    let hash = hash_password(&req.new_password)?;
    state.db.run(move |c| Db::set_password(c, uid, &hash)).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ViewCreate {
    name: String,
    networks: Vec<String>,
    #[serde(default = "default_priority")]
    priority: i64,
}

fn default_priority() -> i64 {
    100
}

#[derive(Deserialize)]
pub struct ViewUpdate {
    name: Option<String>,
    networks: Option<Vec<String>>,
    priority: Option<i64>,
}

fn validate_networks(networks: &[String]) -> Result<(), AppError> {
    for n in networks {
        n.parse::<IpNet>()
            .map_err(|_| validation_field("networks", &format!("invalid CIDR: {n}")))?;
    }
    Ok(())
}

pub async fn list_views(State(state): State<SharedState>, _auth: Authed) -> ApiResult<Response> {
    let views = state.db.run(Db::list_views).await?;
    Ok(ok_json(json!({ "views": views })))
}

pub async fn create_view(
    State(state): State<SharedState>,
    _auth: Authed,
    Json(req): Json<ViewCreate>,
) -> ApiResult<Response> {
    if !valid_view_name(&req.name) {
        return Err(validation_field("name", "1-40 chars, alphanumeric/_/- only"));
    }
    validate_networks(&req.networks)?;
    let name = req.name.clone();
    let nets = req.networks.clone();
    let id = state
        .db
        .run(move |c| Db::create_view(c, &name, &nets, req.priority))
        .await?;
    state.reload_store()?;
    let view = state.db.run(move |c| Db::view(c, id)).await?;
    Ok(created_json(json!({ "view": view })))
}

pub async fn update_view(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
    Json(req): Json<ViewUpdate>,
) -> ApiResult<Response> {
    let existing = state
        .db
        .run(move |c| Db::view(c, id))
        .await?
        .ok_or_else(|| AppError::not_found("view not found"))?;
    if let Some(name) = &req.name {
        if !valid_view_name(name) {
            return Err(validation_field("name", "1-40 chars, alphanumeric/_/- only"));
        }
    }
    if let Some(nets) = &req.networks {
        if existing.is_default {
            return Err(AppError::conflict("cannot change networks of the default view"));
        }
        validate_networks(nets)?;
    }
    let name = req.name.clone();
    let nets = req.networks.clone();
    state
        .db
        .run(move |c| {
            Db::update_view(c, id, name.as_deref(), nets.as_deref(), req.priority)
        })
        .await?;
    state.reload_store()?;
    let view = state.db.run(move |c| Db::view(c, id)).await?;
    Ok(ok_json(json!({ "view": view })))
}

pub async fn delete_view(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
) -> ApiResult<Response> {
    let view = state
        .db
        .run(move |c| Db::view(c, id))
        .await?
        .ok_or_else(|| AppError::not_found("view not found"))?;
    if view.is_default {
        return Err(AppError::conflict("cannot delete the default view"));
    }
    state.db.run(move |c| Db::delete_view(c, id)).await?;
    state.reload_store()?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// Zones
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ZoneCreate {
    name: String,
    default_ttl: Option<u32>,
    soa: Option<Soa>,
}

#[derive(Deserialize)]
pub struct ZoneUpdate {
    enabled: Option<bool>,
    default_ttl: Option<u32>,
    soa: Option<Soa>,
}

pub async fn list_zones(State(state): State<SharedState>, _auth: Authed) -> ApiResult<Response> {
    let zones = state.db.run(Db::list_zones).await?;
    Ok(ok_json(json!({ "zones": zones })))
}

pub async fn create_zone(
    State(state): State<SharedState>,
    _auth: Authed,
    Json(req): Json<ZoneCreate>,
) -> ApiResult<Response> {
    let name = canonical_zone_name(&req.name).map_err(|e| validation_field("name", &e))?;
    let ttl = req.default_ttl.unwrap_or(300);
    let soa = req.soa.unwrap_or_else(|| Soa::default_for(&name));
    let primary_ns = soa.primary_ns.clone();

    let name_for_db = name.clone();
    let zone_id = state
        .db
        .run(move |c| {
            let id = Db::create_zone(c, &name_for_db, &soa, ttl)?;
            // Auto-create the apex NS record.
            Db::create_record(c, id, None, "@", "NS", None, &primary_ns)?;
            Ok(id)
        })
        .await?;

    state.reload_store()?;
    let zone = state.db.run(move |c| Db::zone(c, zone_id)).await?;
    Ok(created_json(json!({ "zone": zone })))
}

pub async fn get_zone(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
) -> ApiResult<Response> {
    let zone = state
        .db
        .run(move |c| Db::zone(c, id))
        .await?
        .ok_or_else(|| AppError::not_found("zone not found"))?;
    let records = state.db.run(move |c| Db::list_records(c, id)).await?;
    Ok(ok_json(json!({ "zone": zone, "records": records })))
}

pub async fn update_zone(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
    Json(req): Json<ZoneUpdate>,
) -> ApiResult<Response> {
    state
        .db
        .run(move |c| Db::zone(c, id))
        .await?
        .ok_or_else(|| AppError::not_found("zone not found"))?;
    let soa = req.soa.clone();
    state
        .db
        .run(move |c| Db::update_zone(c, id, req.enabled, soa.as_ref(), req.default_ttl))
        .await?;
    state.reload_store()?;
    let zone = state.db.run(move |c| Db::zone(c, id)).await?;
    Ok(ok_json(json!({ "zone": zone })))
}

pub async fn delete_zone(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
) -> ApiResult<Response> {
    state.db.run(move |c| Db::delete_zone(c, id)).await?;
    state.reload_store()?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn export_zone(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
) -> ApiResult<Response> {
    let zone = state
        .db
        .run(move |c| Db::zone(c, id))
        .await?
        .ok_or_else(|| AppError::not_found("zone not found"))?;
    let records = state.db.run(move |c| Db::list_records(c, id)).await?;

    let mut out = String::new();
    out.push_str(&format!("$ORIGIN {}.\n", zone.name));
    out.push_str(&format!("$TTL {}\n", zone.default_ttl));
    out.push_str(&format!(
        "@\tIN\tSOA\t{} {} (\n\t\t{} ; serial\n\t\t{} ; refresh\n\t\t{} ; retry\n\t\t{} ; expire\n\t\t{} ; minimum\n\t\t)\n",
        zone.soa.primary_ns,
        zone.soa.admin_email,
        zone.serial,
        zone.soa.refresh,
        zone.soa.retry,
        zone.soa.expire,
        zone.soa.minimum,
    ));
    for r in records {
        if r.rtype == "SOA" {
            continue;
        }
        let owner = if r.name == "@" || r.name.is_empty() { "@".to_string() } else { r.name };
        let ttl = r.ttl.map(|t| t.to_string()).unwrap_or_default();
        let view_comment = match r.view_id {
            Some(v) => format!("\t; view {v}"),
            None => String::new(),
        };
        let enabled = if r.enabled { "" } else { "; (disabled) " };
        out.push_str(&format!(
            "{enabled}{owner}\t{ttl}\tIN\t{}\t{}{view_comment}\n",
            r.rtype, r.data
        ));
    }

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        out,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Secondary zones
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SecondaryCreate {
    name: String,
    primary: String,
    #[serde(default)]
    tsig_key: Option<String>,
}

pub async fn list_secondaries(State(state): State<SharedState>, _auth: Authed) -> ApiResult<Response> {
    let items = state.db.run(Db::list_secondaries).await?;
    Ok(ok_json(json!({ "secondary_zones": items })))
}

pub async fn create_secondary(
    State(state): State<SharedState>,
    _auth: Authed,
    Json(req): Json<SecondaryCreate>,
) -> ApiResult<Response> {
    let name = canonical_zone_name(&req.name).map_err(|e| validation_field("name", &e))?;
    let primary = crate::dns::secondary::parse_primary(req.primary.trim())
        .map_err(|e| validation_field("primary", &e.to_string()))?;

    // Create the zone shell + secondary marker.
    let soa = Soa::default_for(&name);
    let name_db = name.clone();
    let primary_str = primary.to_string();
    let tsig = req.tsig_key.clone();
    let zone_id = state
        .db
        .run(move |c| {
            let id = Db::create_zone(c, &name_db, &soa, 300)?;
            Db::create_secondary(c, id, &primary_str, 3600, tsig.as_deref())?;
            Ok(id)
        })
        .await?;

    // Initial transfer.
    match crate::dns::secondary::transfer(&state, zone_id, &name, primary, req.tsig_key.as_deref())
        .await
    {
        Ok(_) => {}
        Err(e) => {
            let msg = e.to_string();
            let _ = state
                .db
                .run(move |c| Db::set_secondary_status(c, zone_id, Some(&msg), None))
                .await;
        }
    }

    let zone = state.db.run(move |c| Db::zone(c, zone_id)).await?;
    Ok(created_json(json!({ "zone": zone })))
}

pub async fn refresh_secondary(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
) -> ApiResult<Response> {
    let zone = state
        .db
        .run(move |c| Db::zone(c, id))
        .await?
        .ok_or_else(|| AppError::not_found("zone not found"))?;
    let primary = zone
        .primary_addr
        .clone()
        .ok_or_else(|| AppError::conflict("not a secondary zone"))?;
    let primary = crate::dns::secondary::parse_primary(&primary)
        .map_err(|e| AppError::internal(e.to_string()))?;
    let tsig_key = state.db.run(move |c| Db::secondary(c, id)).await?;

    crate::dns::secondary::transfer(&state, id, &zone.name, primary, tsig_key.as_deref())
        .await
        .map_err(|e| {
            AppError::new(StatusCode::BAD_GATEWAY, "transfer_failed", e.to_string())
        })?;
    let zone = state.db.run(move |c| Db::zone(c, id)).await?;
    Ok(ok_json(json!({ "zone": zone })))
}

#[derive(Deserialize)]
pub struct ZoneImport {
    zonefile: String,
    #[serde(default)]
    replace: bool,
}

/// Import a BIND-style zone file into an existing zone. SOA and unsupported
/// types are skipped. Records are added to the all-views set.
pub async fn import_zone(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
    Json(req): Json<ZoneImport>,
) -> ApiResult<Response> {
    let zone = state
        .db
        .run(move |c| Db::zone(c, id))
        .await?
        .ok_or_else(|| AppError::not_found("zone not found"))?;

    let origin = hickory_proto::rr::Name::from_utf8(format!("{}.", zone.name))
        .map_err(|e| validation_field("zonefile", &format!("bad origin: {e}")))?;

    if zone.is_secondary {
        return Err(AppError::conflict(
            "zone is a secondary; its records are managed by transfer",
        ));
    }

    let (records, skipped) = parse_zonefile(&req.zonefile, &origin, &zone.name)
        .map_err(|e| validation_field("zonefile", &e))?;

    let replace = req.replace;
    let imported = state
        .db
        .run_mut(move |c| Db::import_records(c, id, replace, &records))
        .await?;
    state.reload_store()?;
    Ok(ok_json(json!({ "imported": imported, "skipped": skipped })))
}

/// Parse a zone file into `(name, rtype, ttl, data)` tuples for supported types.
fn parse_zonefile(
    text: &str,
    origin: &hickory_proto::rr::Name,
    zone: &str,
) -> Result<(Vec<(String, String, u32, String)>, usize), String> {
    use hickory_proto::serialize::txt::Parser;
    let (_zone_origin, rrsets) = Parser::new(text.to_string(), None, Some(origin.clone()))
        .parse()
        .map_err(|e| format!("parse error: {e}"))?;

    let zone_lc = zone.trim_end_matches('.').to_ascii_lowercase();
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for (_key, rrset) in rrsets {
        for rec in rrset.records_without_rrsigs() {
            let rtype = rec.record_type().to_string();
            if !SUPPORTED_RECORD_TYPES.contains(&rtype.as_str()) {
                skipped += 1;
                continue;
            }
            let fqdn = rec.name.to_string();
            let f = fqdn.trim_end_matches('.').to_ascii_lowercase();
            let name = if f == zone_lc {
                "@".to_string()
            } else if let Some(rel) = f.strip_suffix(&format!(".{zone_lc}")) {
                rel.to_string()
            } else {
                f
            };
            out.push((name, rtype, rec.ttl, rec.data.to_string()));
        }
    }
    Ok((out, skipped))
}

// ---------------------------------------------------------------------------
// DNSSEC
// ---------------------------------------------------------------------------

async fn dnssec_status(state: &SharedState, zone_name: &str) -> ApiResult<Response> {
    let apex = record_fqdn_name("@", zone_name)
        .map_err(|e| AppError::internal(format!("bad apex: {e}")))?;
    match state.store().signer_for(&apex) {
        Some(signer) => Ok(ok_json(json!({
            "enabled": true,
            "algorithm": "ECDSAP256SHA256",
            "key_tag": signer.key_tag(),
            "dnskey": signer.dnskey_text(),
            "ds": signer.ds_text().ok(),
            "nsec3": signer.uses_nsec3(),
        }))),
        None => Ok(ok_json(json!({ "enabled": false }))),
    }
}

#[derive(Deserialize, Default)]
pub struct DnssecEnable {
    #[serde(default)]
    nsec3: bool,
}

pub async fn get_dnssec(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
) -> ApiResult<Response> {
    let zone = state
        .db
        .run(move |c| Db::zone(c, id))
        .await?
        .ok_or_else(|| AppError::not_found("zone not found"))?;
    dnssec_status(&state, &zone.name).await
}

pub async fn enable_dnssec(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
    body: Option<Json<DnssecEnable>>,
) -> ApiResult<Response> {
    let zone = state
        .db
        .run(move |c| Db::zone(c, id))
        .await?
        .ok_or_else(|| AppError::not_found("zone not found"))?;
    if zone.is_secondary {
        return Err(AppError::conflict("cannot sign a secondary zone"));
    }
    let nsec3 = body.map(|b| b.nsec3).unwrap_or(false);
    let secret = crate::dns::dnssec::generate_secret()
        .map_err(|e| AppError::internal(e.to_string()))?;
    // Random 8-byte salt (hex); 0 iterations per RFC 9276.
    let (salt_hex, iterations) = if nsec3 {
        let mut salt = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        (Some(data_encoding::HEXLOWER.encode(&salt)), 0i64)
    } else {
        (None, 0i64)
    };
    // Algorithm 13 = ECDSAP256SHA256.
    let salt_clone = salt_hex.clone();
    state
        .db
        .run(move |c| Db::create_dnssec_key(c, id, 13, &secret, nsec3, salt_clone.as_deref(), iterations))
        .await?;
    state.reload_store()?;
    dnssec_status(&state, &zone.name).await
}

pub async fn disable_dnssec(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
) -> ApiResult<Response> {
    state.db.run(move |c| Db::delete_dnssec_key(c, id)).await?;
    state.reload_store()?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RecordCreate {
    name: String,
    #[serde(rename = "type")]
    rtype: String,
    data: String,
    ttl: Option<u32>,
    #[serde(default)]
    view_id: Option<i64>,
}

#[derive(Deserialize)]
pub struct RecordUpdate {
    name: Option<String>,
    data: Option<String>,
    ttl: Option<Option<u32>>,
    view_id: Option<Option<i64>>,
    enabled: Option<bool>,
}

pub async fn list_records(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
) -> ApiResult<Response> {
    let records = state.db.run(move |c| Db::list_records(c, id)).await?;
    Ok(ok_json(json!({ "records": records })))
}

pub async fn create_record(
    State(state): State<SharedState>,
    Path(zone_id): Path<i64>,
    _auth: Authed,
    Json(req): Json<RecordCreate>,
) -> ApiResult<Response> {
    let zone = state
        .db
        .run(move |c| Db::zone(c, zone_id))
        .await?
        .ok_or_else(|| AppError::not_found("zone not found"))?;
    if zone.is_secondary {
        return Err(AppError::conflict(
            "zone is a secondary; its records are managed by transfer",
        ));
    }

    let rtype = parse_record_type(&req.rtype).map_err(|e| validation_field("type", &e))?;
    // Validate the data parses (and qualify relative names to the zone).
    parse_rdata(rtype, &req.data, &zone.name).map_err(|e| validation_field("data", &e))?;
    record_fqdn_name(&req.name, &zone.name).map_err(|e| validation_field("name", &e))?;

    if let Some(vid) = req.view_id {
        if state.db.run(move |c| Db::view(c, vid)).await?.is_none() {
            return Err(validation_field("view_id", "view not found"));
        }
    }

    let name = req.name.trim().to_string();
    let rtype_s = req.rtype.trim().to_ascii_uppercase();
    let data = req.data.trim().to_string();
    let id = state
        .db
        .run(move |c| {
            Db::create_record(c, zone_id, req.view_id, &name, &rtype_s, req.ttl, &data)
        })
        .await?;
    state.reload_store()?;
    let record = state.db.run(move |c| Db::record(c, id)).await?;
    Ok(created_json(json!({ "record": record })))
}

pub async fn update_record(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
    Json(req): Json<RecordUpdate>,
) -> ApiResult<Response> {
    let existing = state
        .db
        .run(move |c| Db::record(c, id))
        .await?
        .ok_or_else(|| AppError::not_found("record not found"))?;
    let zone = state
        .db
        .run({
            let zid = existing.zone_id;
            move |c| Db::zone(c, zid)
        })
        .await?
        .ok_or_else(|| AppError::not_found("zone not found"))?;

    let rtype = parse_record_type(&existing.rtype).map_err(|e| validation_field("type", &e))?;
    if let Some(data) = &req.data {
        parse_rdata(rtype, data, &zone.name).map_err(|e| validation_field("data", &e))?;
    }
    if let Some(name) = &req.name {
        record_fqdn_name(name, &zone.name).map_err(|e| validation_field("name", &e))?;
    }
    if let Some(Some(vid)) = req.view_id {
        if state.db.run(move |c| Db::view(c, vid)).await?.is_none() {
            return Err(validation_field("view_id", "view not found"));
        }
    }

    let name = req.name.map(|n| n.trim().to_string());
    let data = req.data.map(|d| d.trim().to_string());
    state
        .db
        .run(move |c| {
            Db::update_record(
                c,
                id,
                req.view_id,
                name.as_deref(),
                req.ttl,
                data.as_deref(),
                req.enabled,
            )
        })
        .await?;
    state.reload_store()?;
    let record = state.db.run(move |c| Db::record(c, id)).await?;
    Ok(ok_json(json!({ "record": record })))
}

pub async fn delete_record(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
) -> ApiResult<Response> {
    state.db.run(move |c| Db::delete_record(c, id)).await?;
    state.reload_store()?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SettingsUpdate {
    forwarders: Option<Vec<Forwarder>>,
    resolution_mode: Option<ResolutionMode>,
    block_mode: Option<BlockMode>,
    blocking_enabled: Option<bool>,
    query_log: Option<QueryLog>,
    homograph_protection: Option<HomographMode>,
    cache_size: Option<u64>,
    cache_min_ttl: Option<u32>,
    cache_max_ttl: Option<u32>,
    dnssec_validate_upstream: Option<bool>,
    allow_axfr_from: Option<Vec<String>>,
    tsig_keys: Option<Vec<TsigKey>>,
    axfr_require_tsig: Option<bool>,
}

pub async fn get_settings(State(state): State<SharedState>, _auth: Authed) -> ApiResult<Response> {
    let settings = state.db.run(Db::get_settings).await?;
    Ok(ok_json(json!({ "settings": settings })))
}

pub async fn put_settings(
    State(state): State<SharedState>,
    _auth: Authed,
    Json(req): Json<SettingsUpdate>,
) -> ApiResult<Response> {
    let mut settings = state.db.run(Db::get_settings).await?;
    if let Some(fwds) = req.forwarders {
        for f in &fwds {
            f.addr
                .parse::<std::net::IpAddr>()
                .map_err(|_| validation_field("forwarders", &format!("invalid address: {}", f.addr)))?;
            if matches!(f.protocol, ForwardProtocol::Tls | ForwardProtocol::Https)
                && f.tls_name.as_deref().unwrap_or("").is_empty()
            {
                return Err(validation_field(
                    "forwarders",
                    "tls/https forwarders require tls_name",
                ));
            }
        }
        settings.forwarders = fwds;
    }
    if let Some(v) = req.resolution_mode {
        settings.resolution_mode = v;
    }
    if let Some(v) = req.block_mode {
        settings.block_mode = v;
    }
    if let Some(v) = req.blocking_enabled {
        settings.blocking_enabled = v;
    }
    if let Some(v) = req.query_log {
        settings.query_log = v;
    }
    if let Some(v) = req.homograph_protection {
        settings.homograph_protection = v;
    }
    if let Some(v) = req.cache_size {
        settings.cache_size = v;
    }
    if let Some(v) = req.cache_min_ttl {
        settings.cache_min_ttl = v;
    }
    if let Some(v) = req.cache_max_ttl {
        settings.cache_max_ttl = v;
    }
    if let Some(v) = req.dnssec_validate_upstream {
        settings.dnssec_validate_upstream = v;
    }
    if let Some(v) = req.allow_axfr_from {
        for cidr in &v {
            cidr.parse::<ipnet::IpNet>()
                .map_err(|_| validation_field("allow_axfr_from", &format!("invalid CIDR: {cidr}")))?;
        }
        settings.allow_axfr_from = v;
    }
    if let Some(keys) = req.tsig_keys {
        for k in &keys {
            crate::dns::tsig::build_signer(k)
                .map_err(|e| validation_field("tsig_keys", &e.to_string()))?;
        }
        settings.tsig_keys = keys;
    }
    if let Some(v) = req.axfr_require_tsig {
        settings.axfr_require_tsig = v;
    }

    let to_store = settings.clone();
    state.db.run(move |c| Db::put_settings(c, &to_store)).await?;
    // Apply live: rebuild the upstream resolver and reload the filter.
    state.apply_settings(settings.clone());
    Ok(ok_json(json!({ "settings": settings })))
}

// ---------------------------------------------------------------------------
// Blocklists
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct BlocklistCreate {
    name: String,
    url: String,
    #[serde(default)]
    format: BlocklistFormat,
    #[serde(default)]
    refresh_now: bool,
}

#[derive(Deserialize)]
pub struct BlocklistUpdate {
    name: Option<String>,
    enabled: Option<bool>,
}

pub async fn list_blocklists(State(state): State<SharedState>, _auth: Authed) -> ApiResult<Response> {
    let lists = state.db.run(Db::list_blocklists).await?;
    Ok(ok_json(json!({ "blocklists": lists })))
}

/// A curated catalog of well-known blocklists the UI can offer one-click.
pub async fn blocklist_catalog(_auth: Authed) -> Response {
    // (name, url, format, category, description)
    let catalog = [
        ("StevenBlack (unified)", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "hosts", "ads + malware", "Popular unified hosts: ads, malware, fakenews-free base list."),
        ("Hagezi Multi PRO", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt", "hosts", "ads + tracking", "Balanced, well-maintained ad/tracker/affiliate blocklist."),
        ("1Hosts (Lite)", "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.txt", "hosts", "ads + tracking", "Lightweight, low-false-positive ad/tracker list."),
        ("OISD (small)", "https://small.oisd.nl/domains", "domains", "ads + tracking", "Curated meta-list focused on low breakage."),
        ("Peter Lowe's list", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", "hosts", "ads + tracking", "Long-running ad/tracking server list."),
        ("Dan Pollock (someonewhocares)", "https://someonewhocares.org/hosts/zero/hosts", "hosts", "ads + tracking", "Classic curated hosts file."),
        ("URLhaus malware", "https://urlhaus.abuse.ch/downloads/hostfile/", "hosts", "malware", "abuse.ch malware/payload distribution hosts."),
    ];
    let items: Vec<_> = catalog
        .iter()
        .map(|(name, url, format, category, description)| {
            json!({ "name": name, "url": url, "format": format,
                    "category": category, "description": description })
        })
        .collect();
    ok_json(json!({ "catalog": items }))
}

pub async fn create_blocklist(
    State(state): State<SharedState>,
    _auth: Authed,
    Json(req): Json<BlocklistCreate>,
) -> ApiResult<Response> {
    if req.name.trim().is_empty() {
        return Err(validation_field("name", "must not be empty"));
    }
    if !(req.url.starts_with("http://") || req.url.starts_with("https://")) {
        return Err(validation_field("url", "must be an http(s) URL"));
    }
    let name = req.name.trim().to_string();
    let url = req.url.trim().to_string();
    let id = state
        .db
        .run(move |c| Db::create_blocklist(c, &name, &url, req.format, true))
        .await?;

    if req.refresh_now {
        refresh_one(&state, id).await;
    }
    state.reload_filter()?;
    let list = state.db.run(move |c| Db::blocklist(c, id)).await?;
    Ok(created_json(json!({ "blocklist": list })))
}

pub async fn update_blocklist(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
    Json(req): Json<BlocklistUpdate>,
) -> ApiResult<Response> {
    let name = req.name.clone();
    state
        .db
        .run(move |c| Db::update_blocklist(c, id, name.as_deref(), req.enabled))
        .await?;
    state.reload_filter()?;
    let list = state.db.run(move |c| Db::blocklist(c, id)).await?;
    Ok(ok_json(json!({ "blocklist": list })))
}

pub async fn delete_blocklist(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
) -> ApiResult<Response> {
    state.db.run(move |c| Db::delete_blocklist(c, id)).await?;
    state.reload_filter()?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn refresh_blocklist(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
) -> ApiResult<Response> {
    refresh_one(&state, id).await;
    state.reload_filter()?;
    let list = state
        .db
        .run(move |c| Db::blocklist(c, id))
        .await?
        .ok_or_else(|| AppError::not_found("blocklist not found"))?;
    Ok(ok_json(json!({ "blocklist": list })))
}

pub async fn refresh_all_blocklists(
    State(state): State<SharedState>,
    _auth: Authed,
) -> ApiResult<Response> {
    let lists = state.db.run(Db::list_blocklists).await?;
    for l in &lists {
        if l.enabled {
            refresh_one(&state, l.id).await;
        }
    }
    state.reload_filter()?;
    let lists = state.db.run(Db::list_blocklists).await?;
    Ok(ok_json(json!({ "blocklists": lists })))
}

/// Fetch and parse one blocklist, replacing its cached entries.
async fn refresh_one(state: &SharedState, id: i64) {
    let list = match state.db.run(move |c| Db::blocklist(c, id)).await {
        Ok(Some(l)) => l,
        _ => return,
    };

    match crate::web::fetch::fetch_blocklist(&list.url, list.format).await {
        Ok(domains) => {
            if let Err(e) = state
                .db
                .run_mut(move |c| Db::replace_blocklist_entries(c, id, &domains, None))
                .await
            {
                tracing::error!("storing blocklist {id}: {e}");
            }
        }
        Err(e) => {
            let msg = e.to_string();
            let _ = state
                .db
                .run(move |c| Db::set_blocklist_error(c, id, &msg))
                .await;
            tracing::warn!("fetching blocklist {id}: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Block rules (manual allow/deny)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct BlockRuleCreate {
    domain: String,
    action: RuleAction,
    #[serde(default)]
    comment: Option<String>,
}

pub async fn list_block_rules(State(state): State<SharedState>, _auth: Authed) -> ApiResult<Response> {
    let rules = state.db.run(Db::list_block_rules).await?;
    Ok(ok_json(json!({ "rules": rules })))
}

pub async fn create_block_rule(
    State(state): State<SharedState>,
    _auth: Authed,
    Json(req): Json<BlockRuleCreate>,
) -> ApiResult<Response> {
    let domain = normalize_domain(&req.domain)?;
    let comment = req.comment.clone();
    let id = state
        .db
        .run(move |c| Db::create_block_rule(c, &domain, req.action, comment.as_deref()))
        .await?;
    state.reload_filter()?;
    let rules = state.db.run(Db::list_block_rules).await?;
    let rule = rules.into_iter().find(|r| r.id == id);
    Ok(created_json(json!({ "rule": rule })))
}

pub async fn delete_block_rule(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
) -> ApiResult<Response> {
    state.db.run(move |c| Db::delete_block_rule(c, id)).await?;
    state.reload_filter()?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// Rewrites
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RewriteCreate {
    domain: String,
    target: String,
    #[serde(default)]
    comment: Option<String>,
}

#[derive(Deserialize)]
pub struct RewriteUpdate {
    domain: Option<String>,
    target: Option<String>,
    enabled: Option<bool>,
}

pub async fn list_rewrites(State(state): State<SharedState>, _auth: Authed) -> ApiResult<Response> {
    let rewrites = state.db.run(Db::list_rewrites).await?;
    Ok(ok_json(json!({ "rewrites": rewrites })))
}

pub async fn create_rewrite(
    State(state): State<SharedState>,
    _auth: Authed,
    Json(req): Json<RewriteCreate>,
) -> ApiResult<Response> {
    let domain = normalize_domain(&req.domain)?;
    validate_rewrite_target(&req.target)?;
    let target = req.target.trim().to_string();
    let comment = req.comment.clone();
    let id = state
        .db
        .run(move |c| Db::create_rewrite(c, &domain, &target, comment.as_deref()))
        .await?;
    state.reload_filter()?;
    let rewrite = state.db.run(move |c| Db::rewrite(c, id)).await?;
    Ok(created_json(json!({ "rewrite": rewrite })))
}

pub async fn update_rewrite(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
    Json(req): Json<RewriteUpdate>,
) -> ApiResult<Response> {
    if let Some(t) = &req.target {
        validate_rewrite_target(t)?;
    }
    let domain = match &req.domain {
        Some(d) => Some(normalize_domain(d)?),
        None => None,
    };
    let target = req.target.clone();
    state
        .db
        .run(move |c| Db::update_rewrite(c, id, domain.as_deref(), target.as_deref(), req.enabled))
        .await?;
    state.reload_filter()?;
    let rewrite = state.db.run(move |c| Db::rewrite(c, id)).await?;
    Ok(ok_json(json!({ "rewrite": rewrite })))
}

pub async fn delete_rewrite(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
) -> ApiResult<Response> {
    state.db.run(move |c| Db::delete_rewrite(c, id)).await?;
    state.reload_filter()?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// Conditional forwarders
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ConditionalCreate {
    domain: String,
    forwarders: Vec<Forwarder>,
}

#[derive(Deserialize)]
pub struct ConditionalUpdate {
    forwarders: Option<Vec<Forwarder>>,
    enabled: Option<bool>,
}

fn validate_forwarders(forwarders: &[Forwarder]) -> Result<(), AppError> {
    if forwarders.is_empty() {
        return Err(validation_field("forwarders", "at least one forwarder required"));
    }
    for f in forwarders {
        f.addr
            .parse::<std::net::IpAddr>()
            .map_err(|_| validation_field("forwarders", &format!("invalid address: {}", f.addr)))?;
        if matches!(f.protocol, ForwardProtocol::Tls | ForwardProtocol::Https)
            && f.tls_name.as_deref().unwrap_or("").is_empty()
        {
            return Err(validation_field(
                "forwarders",
                "tls/https forwarders require tls_name",
            ));
        }
    }
    Ok(())
}

pub async fn list_conditional(State(state): State<SharedState>, _auth: Authed) -> ApiResult<Response> {
    let items = state.db.run(Db::list_conditional_forwards).await?;
    Ok(ok_json(json!({ "conditional_forwards": items })))
}

pub async fn create_conditional(
    State(state): State<SharedState>,
    _auth: Authed,
    Json(req): Json<ConditionalCreate>,
) -> ApiResult<Response> {
    let domain = normalize_domain(&req.domain)?;
    validate_forwarders(&req.forwarders)?;
    let fwds = req.forwarders.clone();
    let id = state
        .db
        .run(move |c| Db::create_conditional_forward(c, &domain, &fwds))
        .await?;
    state.reload_conditional()?;
    let item = state.db.run(move |c| Db::conditional_forward(c, id)).await?;
    Ok(created_json(json!({ "conditional_forward": item })))
}

pub async fn update_conditional(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
    Json(req): Json<ConditionalUpdate>,
) -> ApiResult<Response> {
    if let Some(f) = &req.forwarders {
        validate_forwarders(f)?;
    }
    let fwds = req.forwarders.clone();
    state
        .db
        .run(move |c| Db::update_conditional_forward(c, id, fwds.as_deref(), req.enabled))
        .await?;
    state.reload_conditional()?;
    let item = state.db.run(move |c| Db::conditional_forward(c, id)).await?;
    Ok(ok_json(json!({ "conditional_forward": item })))
}

pub async fn delete_conditional(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
) -> ApiResult<Response> {
    state
        .db
        .run(move |c| Db::delete_conditional_forward(c, id))
        .await?;
    state.reload_conditional()?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// DynDNS tokens
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct DynDnsTokenCreate {
    label: String,
    username: String,
    /// Optional client password; a strong one is generated when omitted.
    secret: Option<String>,
    hostnames: Vec<String>,
    view_id: Option<i64>,
    ttl: Option<u32>,
}

pub async fn list_dyndns_tokens(
    State(state): State<SharedState>,
    _auth: Authed,
) -> ApiResult<Response> {
    let tokens = state.db.run(Db::list_dyndns_tokens).await?;
    Ok(ok_json(json!({ "tokens": tokens })))
}

pub async fn create_dyndns_token(
    State(state): State<SharedState>,
    _auth: Authed,
    Json(req): Json<DynDnsTokenCreate>,
) -> ApiResult<Response> {
    let label = req.label.trim().to_string();
    if label.is_empty() {
        return Err(validation_field("label", "must not be empty"));
    }
    let username = req.username.trim().to_string();
    if username.is_empty() || username.len() > 64 || username.contains(':') {
        return Err(validation_field("username", "must be 1-64 chars and contain no colon"));
    }
    if req.hostnames.is_empty() {
        return Err(validation_field("hostnames", "at least one hostname is required"));
    }

    // Each hostname must be a valid FQDN covered by a local zone.
    let zones = state.db.run(Db::list_zones).await?;
    let mut hostnames = Vec::new();
    for h in &req.hostnames {
        let host = h.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            continue;
        }
        if hickory_proto::rr::Name::from_utf8(format!("{host}.")).is_err() {
            return Err(validation_field("hostnames", &format!("invalid hostname: {host}")));
        }
        let covered = zones.iter().any(|z| {
            let zn = z.name.trim_end_matches('.').to_ascii_lowercase();
            host == zn || host.ends_with(&format!(".{zn}"))
        });
        if !covered {
            return Err(validation_field(
                "hostnames",
                &format!("no local zone covers {host}"),
            ));
        }
        hostnames.push(host);
    }
    if hostnames.is_empty() {
        return Err(validation_field("hostnames", "at least one hostname is required"));
    }

    if let Some(vid) = req.view_id {
        if state.db.run(move |c| Db::view(c, vid)).await?.is_none() {
            return Err(validation_field("view_id", "view not found"));
        }
    }

    // Usernames must be unique (also enforced by a DB constraint).
    let exists_user = username.clone();
    if state
        .db
        .run(move |c| Db::dyndns_auth(c, &exists_user))
        .await?
        .is_some()
    {
        return Err(AppError::conflict("a token with this username already exists"));
    }

    let secret = req.secret.filter(|s| !s.trim().is_empty()).unwrap_or_else(random_token);
    let secret_hash = hash_password(&secret)?;
    let ttl = req.ttl.unwrap_or(60).max(1);
    let view_id = req.view_id;

    let label_db = label.clone();
    let username_db = username.clone();
    let id = state
        .db
        .run(move |c| {
            Db::create_dyndns_token(c, &label_db, &username_db, &secret_hash, &hostnames, view_id, ttl)
        })
        .await?;

    // The plaintext secret is returned only once, at creation.
    Ok(created_json(json!({
        "id": id,
        "label": label,
        "username": username,
        "secret": secret,
        "update_url": format!("/nic/update?hostname=<host>&myip=<ip>"),
    })))
}

pub async fn delete_dyndns_token(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    _auth: Authed,
) -> ApiResult<Response> {
    state.db.run(move |c| Db::delete_dyndns_token(c, id)).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

fn normalize_domain(domain: &str) -> Result<String, AppError> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return Err(validation_field("domain", "must not be empty"));
    }
    // Allow a leading wildcard label.
    let check = d.strip_prefix("*.").unwrap_or(&d);
    if hickory_proto::rr::Name::from_utf8(format!("{check}.")).is_err() {
        return Err(validation_field("domain", "invalid domain"));
    }
    Ok(d)
}

fn validate_rewrite_target(target: &str) -> Result<(), AppError> {
    let t = target.trim();
    if t.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    let fqdn = if t.ends_with('.') { t.to_string() } else { format!("{t}.") };
    if hickory_proto::rr::Name::from_utf8(&fqdn).is_ok() {
        Ok(())
    } else {
        Err(validation_field("target", "must be an IP address or hostname"))
    }
}
