//! Authentication: password hashing, server-side sessions, and the request
//! extractor that gates the API (including CSRF for mutating requests).

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

use crate::db::Db;
use crate::error::AppError;
use crate::models::User;
use crate::state::SharedState;

/// Session lifetime.
pub const SESSION_TTL_SECS: i64 = 7 * 24 * 3600;

// ----- password hashing ----------------------------------------------------

pub fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::internal(format!("password hashing failed: {e}")))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

// ----- tokens ---------------------------------------------------------------

/// Generate a 256-bit random token, URL-safe base64 (no padding).
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Hash a session id for storage at rest, so a database leak does not expose
/// live session tokens.
pub fn hash_session_id(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    STANDARD_NO_PAD.encode(digest)
}

// ----- cookies --------------------------------------------------------------

pub const SESSION_COOKIE: &str = "nomina_session";
pub const CSRF_COOKIE: &str = "nomina_csrf";

/// Build the `Set-Cookie` value for the session cookie.
pub fn session_cookie(token: &str, secure: bool, max_age: i64) -> String {
    cookie(SESSION_COOKIE, token, secure, true, max_age)
}

/// Build the `Set-Cookie` value for the (JS-readable) CSRF cookie.
pub fn csrf_cookie(token: &str, secure: bool, max_age: i64) -> String {
    cookie(CSRF_COOKIE, token, secure, false, max_age)
}

fn cookie(name: &str, value: &str, secure: bool, http_only: bool, max_age: i64) -> String {
    let mut c = format!("{name}={value}; Path=/; SameSite=Strict; Max-Age={max_age}");
    if http_only {
        c.push_str("; HttpOnly");
    }
    if secure {
        c.push_str("; Secure");
    }
    c
}

/// Parse the `Cookie` header into name->value pairs.
pub fn parse_cookies(headers: &HeaderMap) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    if let Some(raw) = headers.get(axum::http::header::COOKIE).and_then(|v| v.to_str().ok()) {
        for pair in raw.split(';') {
            if let Some((k, v)) = pair.trim().split_once('=') {
                map.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    map
}

// ----- the authenticated-request extractor ----------------------------------

/// Proof that the request carries a valid session. For mutating methods, CSRF
/// has also been verified.
pub struct Authed {
    pub user: User,
    pub csrf_token: String,
}

fn is_mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// Resolve and validate the session from cookies, returning the user and the
/// session's CSRF token. Does not perform the CSRF check.
pub async fn resolve_session(
    state: &SharedState,
    headers: &HeaderMap,
) -> Result<Authed, AppError> {
    let cookies = parse_cookies(headers);
    let token = cookies
        .get(SESSION_COOKIE)
        .cloned()
        .ok_or_else(AppError::unauthorized)?;
    let hashed = hash_session_id(&token);

    let session = state
        .db
        .run(move |c| Db::session(c, &hashed))
        .await?
        .ok_or_else(AppError::unauthorized)?;

    if session.expires_at < OffsetDateTime::now_utc() {
        let hashed = hash_session_id(&token);
        let _ = state.db.run(move |c| Db::delete_session(c, &hashed)).await;
        return Err(AppError::unauthorized());
    }

    let uid = session.user_id;
    let user = state
        .db
        .run(move |c| Db::user_by_id(c, uid))
        .await?
        .ok_or_else(AppError::unauthorized)?;

    Ok(Authed {
        user: user.public(),
        csrf_token: session.csrf_token,
    })
}

impl FromRequestParts<SharedState> for Authed {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let authed = resolve_session(state, &parts.headers).await?;

        // CSRF: the header must match the session's server-side token.
        if is_mutating(&parts.method) {
            let header = parts
                .headers
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let ok: bool = header
                .as_bytes()
                .ct_eq(authed.csrf_token.as_bytes())
                .into();
            if !ok {
                return Err(AppError::new(
                    StatusCode::FORBIDDEN,
                    "csrf_failed",
                    "Missing or invalid CSRF token",
                ));
            }
        }

        Ok(authed)
    }
}
