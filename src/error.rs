//! Unified error type for the management API.
//!
//! Every fallible web handler returns [`AppError`]; it renders to the JSON error
//! envelope defined in `docs/api-contract.md`:
//! `{ "error": { "code", "message", "fields"? } }`.

use std::collections::BTreeMap;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// An error returned from a web handler, carrying an HTTP status, a stable
/// machine code, and a human-readable message.
#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub fields: Option<BTreeMap<String, String>>,
}

impl AppError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            fields: None,
        }
    }

    pub fn with_fields(mut self, fields: BTreeMap<String, String>) -> Self {
        self.fields = Some(fields);
        self
    }

    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", "Authentication required")
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", msg)
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", msg)
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", msg)
    }

    pub fn validation(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "validation", msg)
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", msg)
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Avoid leaking internal detail in 5xx responses.
        let message = if self.status.is_server_error() {
            tracing::error!(code = self.code, error = %self.message, "internal error");
            "Internal server error".to_string()
        } else {
            self.message
        };
        let mut err = json!({ "code": self.code, "message": message });
        if let Some(fields) = self.fields {
            err["fields"] = json!(fields);
        }
        (self.status, Json(json!({ "error": err }))).into_response()
    }
}

/// Convenience: turn anyhow/other errors into a 500.
impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::internal(e.to_string())
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        // UNIQUE constraint violations map to 409.
        if let rusqlite::Error::SqliteFailure(f, _) = &e {
            if f.code == rusqlite::ErrorCode::ConstraintViolation {
                return AppError::conflict("Resource already exists or violates a constraint");
            }
        }
        AppError::internal(e.to_string())
    }
}

impl From<tokio::task::JoinError> for AppError {
    fn from(e: tokio::task::JoinError) -> Self {
        AppError::internal(format!("task failure: {e}"))
    }
}

pub type ApiResult<T> = Result<T, AppError>;
