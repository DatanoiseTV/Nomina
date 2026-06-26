//! The management web server: JSON API + embedded single-page UI, served over
//! HTTP or HTTPS (sharing the DNS TLS material).

pub mod api;
pub mod auth;

use std::convert::Infallible;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Request, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rust_embed::Embed;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tower::Service;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::state::SharedState;

#[derive(Embed)]
#[folder = "web/"]
struct Assets;

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
    img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; \
    base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

/// Build the full application router.
pub fn router(state: SharedState) -> Router {
    let api = Router::new()
        .route("/api/health", get(api::health))
        .route("/api/status", get(api::status))
        .route("/api/stats", get(api::stats))
        .route("/api/auth/login", post(api::login))
        .route("/api/auth/logout", post(api::logout))
        .route("/api/auth/me", get(api::me))
        .route("/api/auth/change-password", post(api::change_password))
        .route("/api/setup", post(api::setup))
        .route("/api/views", get(api::list_views).post(api::create_view))
        .route("/api/views/{id}", put(api::update_view).delete(api::delete_view))
        .route("/api/zones", get(api::list_zones).post(api::create_zone))
        .route(
            "/api/zones/{id}",
            get(api::get_zone).put(api::update_zone).delete(api::delete_zone),
        )
        .route(
            "/api/zones/{id}/records",
            get(api::list_records).post(api::create_record),
        )
        .route("/api/zones/{id}/export", get(api::export_zone))
        .route(
            "/api/records/{id}",
            put(api::update_record).delete(api::delete_record),
        )
        .route("/api/settings", get(api::get_settings).put(api::put_settings));

    Router::new()
        .merge(api)
        .fallback(static_handler)
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(512 * 1024))
        .layer(security_header("content-security-policy", CSP))
        .layer(security_header("x-content-type-options", "nosniff"))
        .layer(security_header("x-frame-options", "DENY"))
        .layer(security_header(
            "referrer-policy",
            "strict-origin-when-cross-origin",
        ))
        .layer(TraceLayer::new_for_http())
}

fn security_header(name: &'static str, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::overriding(
        HeaderName::from_static(name),
        HeaderValue::from_static(value),
    )
}

/// Serve embedded UI assets, falling back to `index.html` for SPA routes.
async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Unknown API routes are JSON 404s, not the SPA shell.
    if path.starts_with("api/") || path == "api" {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": { "code": "not_found", "message": "No such endpoint" }
            })),
        )
            .into_response();
    }

    let lookup = if path.is_empty() { "index.html" } else { path };
    match Assets::get(lookup) {
        Some(content) => serve_embedded(content),
        None => match Assets::get("index.html") {
            Some(content) => serve_embedded(content),
            None => (StatusCode::NOT_FOUND, "UI assets not bundled").into_response(),
        },
    }
}

fn serve_embedded(content: rust_embed::EmbeddedFile) -> Response {
    let mime = content.metadata.mimetype();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, mime.to_string())],
        content.data.into_owned(),
    )
        .into_response()
}

/// Run the web server (plain HTTP).
pub async fn serve_plain(listener: TcpListener, app: Router) -> anyhow::Result<()> {
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

/// Run the web server over TLS using the shared rustls config.
pub async fn serve_tls(
    listener: TcpListener,
    app: Router,
    tls_config: Arc<ServerConfig>,
) -> anyhow::Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("web accept error: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("TLS handshake failed: {e}");
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                let mut app = app.clone();
                async move {
                    let res: Result<Response, Infallible> =
                        app.call(req.map(Body::new)).await;
                    res
                }
            });
            if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
            {
                tracing::debug!("web connection error: {e}");
            }
        });
    }
}
