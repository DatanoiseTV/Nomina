//! The management web server: JSON API + embedded single-page UI, served over
//! HTTP or HTTPS (sharing the DNS TLS material).

pub mod api;
pub mod auth;
pub mod dyndns;
pub mod fetch;

use std::convert::Infallible;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request as ExtractRequest, State};
use axum::http::{HeaderName, HeaderValue, Request, StatusCode, Uri, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use ipnet::IpNet;
use rust_embed::Embed;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tower::Service;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::dns::doh;
use crate::state::SharedState;
use std::net::SocketAddr;

#[derive(Embed)]
#[folder = "web/"]
struct Assets;

// `img-src` also allows OpenStreetMap tile servers for the Map view (Leaflet is
// vendored locally; only the map tiles are fetched from OSM).
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
    img-src 'self' data: https://*.tile.openstreetmap.org; connect-src 'self'; \
    font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; \
    frame-ancestors 'none'";

/// Build the full application router.
pub fn router(state: SharedState) -> Router {
    let api = Router::new()
        .route("/api/health", get(api::health))
        .route("/metrics", get(api::metrics))
        .route("/api/status", get(api::status))
        .route("/api/stats", get(api::stats))
        .route("/api/stats/clear", post(api::clear_stats))
        .route("/api/map", get(api::map_points))
        .route(
            "/api/queries",
            get(api::query_log).delete(api::clear_query_log),
        )
        .route("/api/auth/login", post(api::login))
        .route("/api/auth/logout", post(api::logout))
        .route("/api/auth/me", get(api::me))
        .route("/api/auth/change-password", post(api::change_password))
        .route("/api/setup", post(api::setup))
        .route("/api/views", get(api::list_views).post(api::create_view))
        .route(
            "/api/views/{id}",
            put(api::update_view).delete(api::delete_view),
        )
        .route("/api/zones", get(api::list_zones).post(api::create_zone))
        .route(
            "/api/zones/{id}",
            get(api::get_zone)
                .put(api::update_zone)
                .delete(api::delete_zone),
        )
        .route(
            "/api/zones/{id}/records",
            get(api::list_records).post(api::create_record),
        )
        .route("/api/zones/{id}/export", get(api::export_zone))
        .route("/api/zones/{id}/import", post(api::import_zone))
        .route(
            "/api/zones/{id}/dnssec",
            get(api::get_dnssec)
                .post(api::enable_dnssec)
                .delete(api::disable_dnssec),
        )
        .route(
            "/api/secondary-zones",
            get(api::list_secondaries).post(api::create_secondary),
        )
        .route(
            "/api/secondary-zones/{id}/refresh",
            post(api::refresh_secondary),
        )
        .route(
            "/api/records/{id}",
            put(api::update_record).delete(api::delete_record),
        )
        .route(
            "/api/settings",
            get(api::get_settings).put(api::put_settings),
        )
        .route(
            "/api/blocklists",
            get(api::list_blocklists).post(api::create_blocklist),
        )
        .route("/api/blocklists/catalog", get(api::blocklist_catalog))
        .route(
            "/api/blocklists/refresh_all",
            post(api::refresh_all_blocklists),
        )
        .route(
            "/api/blocklists/{id}",
            put(api::update_blocklist).delete(api::delete_blocklist),
        )
        .route("/api/blocklists/{id}/refresh", post(api::refresh_blocklist))
        .route(
            "/api/rules",
            get(api::list_block_rules).post(api::create_block_rule),
        )
        .route(
            "/api/rules/{id}",
            axum::routing::delete(api::delete_block_rule),
        )
        .route(
            "/api/rewrites",
            get(api::list_rewrites).post(api::create_rewrite),
        )
        .route(
            "/api/rewrites/{id}",
            put(api::update_rewrite).delete(api::delete_rewrite),
        )
        .route(
            "/api/conditional-forwards",
            get(api::list_conditional).post(api::create_conditional),
        )
        .route(
            "/api/conditional-forwards/{id}",
            put(api::update_conditional).delete(api::delete_conditional),
        )
        .route(
            "/api/dyndns/tokens",
            get(api::list_dyndns_tokens).post(api::create_dyndns_token),
        )
        .route(
            "/api/dyndns/tokens/{id}",
            axum::routing::delete(api::delete_dyndns_token),
        )
        .route(
            "/api/dhcp/scopes",
            get(api::list_dhcp_scopes).post(api::create_dhcp_scope),
        )
        .route(
            "/api/dhcp/scopes/{id}",
            get(api::get_dhcp_scope)
                .put(api::update_dhcp_scope)
                .delete(api::delete_dhcp_scope),
        )
        .route(
            "/api/dhcp/scopes/{id}/reservations",
            post(api::create_dhcp_reservation),
        )
        .route(
            "/api/dhcp/reservations/{id}",
            put(api::update_dhcp_reservation).delete(api::delete_dhcp_reservation),
        )
        .route("/api/dhcp/leases", get(api::list_dhcp_leases))
        .route(
            "/api/dhcp/leases/{id}",
            axum::routing::delete(api::delete_dhcp_lease),
        )
        .route("/api/dhcp/option-catalog", get(api::dhcp_option_catalog))
        // DynDNS2 update endpoint. Authenticated by per-token HTTP Basic auth;
        // intentionally outside the session/CSRF gate above.
        .route("/nic/update", get(dyndns::nic_update))
        .route("/v3/update", get(dyndns::nic_update));

    // Optional CIDR allow-list for the whole management server.
    let allow: Arc<Vec<IpNet>> = Arc::new(
        state
            .config
            .web
            .allow_networks
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect(),
    );

    let app = Router::new().merge(api);
    // DoH (RFC 8484) is also served on the management port when over HTTPS.
    let app = doh::route(app);

    let app = app
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
        .layer(TraceLayer::new_for_http());

    if allow.is_empty() {
        app
    } else {
        app.layer(from_fn_with_state(allow, ip_guard))
    }
}

/// Reject clients outside the configured management allow-list.
async fn ip_guard(
    State(allow): State<Arc<Vec<IpNet>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: ExtractRequest,
    next: Next,
) -> Response {
    // DynDNS clients live on dynamic, remote IPs by nature, so the update
    // endpoint is exempt from the management allow-list — its per-token Basic
    // auth is the security boundary.
    let path = req.uri().path();
    let dyndns = path == "/nic/update" || path == "/v3/update";
    if dyndns || allow.iter().any(|n| n.contains(&peer.ip())) {
        next.run(req).await
    } else {
        tracing::warn!(client = %peer.ip(), "rejected management request (not in allow-list)");
        (StatusCode::FORBIDDEN, "forbidden").into_response()
    }
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
    // `no-cache` = the browser must revalidate before reuse, so a rebuilt UI is
    // picked up without a manual hard refresh (assets aren't fingerprinted).
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, mime.to_string()),
            (header::CACHE_CONTROL, "no-cache".to_string()),
        ],
        content.data.into_owned(),
    )
        .into_response()
}

/// Run the web server (plain HTTP). Client connect-info is exposed so DoH
/// split-horizon sees the real peer IP.
pub async fn serve_plain(listener: TcpListener, app: Router) -> anyhow::Result<()> {
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
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
        let (stream, peer) = match listener.accept().await {
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
                    // Inject the peer address so ConnectInfo<SocketAddr> works.
                    let mut req = req.map(Body::new);
                    req.extensions_mut()
                        .insert(axum::extract::ConnectInfo(peer));
                    let res: Result<Response, Infallible> = app.call(req).await;
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
