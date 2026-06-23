//! smirk-backend-core
//!
//! Open, self-hostable backend for the Smirk non-custodial multi-chain wallet:
//! authentication, per-chain wallet access (Bitcoin, Litecoin, Monero, Wownero,
//! Grin), the Grin slatepack relay, and Nostr-based identity.
//!
//! The HTTP contract is generated from the handlers (`utoipa`) into
//! `openapi.json`, which is the single source of truth for the API and the
//! wallet's generated TypeScript client.

pub mod api;
pub mod config;
pub mod core;
pub mod error;
pub mod infra;
pub mod models;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderValue, Method};
use axum::{routing::get, Router};
use tokio::sync::RwLock;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::core::session::{SessionManager, WebChallenge};
use crate::infra::chains::ChainClients;
use crate::infra::db::Database;

/// Global request-body cap (backstop; handlers validate tighter per field).
const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Global request deadline (backstop above the chain clients' own ~30s timeouts,
/// so their errors surface first for chain calls; bounds any slow handler).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

// Per-IP rate-limit tiers (one token replenished per period; `burst` = bucket).
// STRICT throttles the unauthenticated, abuse-prone surface (auth + website);
// NORMAL covers the authenticated wallet/identity API. Sane defaults; operator-
// tunable config can follow.
const STRICT_PERIOD_MS: u64 = 500; // ~2 req/s sustained
const STRICT_BURST: u32 = 20;
const NORMAL_PERIOD_MS: u64 = 100; // ~10 req/s sustained
const NORMAL_BURST: u32 = 60;

/// Shared application state injected into handlers via `State<Arc<AppState>>`.
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: Database,
    pub sessions: SessionManager,
    /// Per-chain data-source clients (present only for enabled chains).
    pub chains: ChainClients,
    /// In-memory website-auth challenges, keyed by nonce. Single-node store;
    /// a shared/stateless variant is the load-balanced-fleet path.
    pub web_challenges: Arc<RwLock<HashMap<String, WebChallenge>>>,
}

/// Assemble the full application router with every route mounted and state
/// applied. Shared by `main` and the integration-test harness so both exercise
/// the exact same wiring: `/health` and the NIP-05 directory at the root, the
/// authenticated wallet/identity API nested under `/api/v1`.
pub fn build_router(state: Arc<AppState>) -> Router {
    let cors = cors_layer(&state.config);

    // Per-IP rate limiting (PeerIpKeyExtractor reads ConnectInfo — `main` serves
    // with `into_make_service_with_connect_info`; the test harness injects it).
    // Tiered: stricter on the unauthenticated auth/website surface (closes the
    // website-challenge growth vector), looser on the wallet/identity API.
    let mut strict_cfg = GovernorConfigBuilder::default();
    strict_cfg
        .per_millisecond(STRICT_PERIOD_MS)
        .burst_size(STRICT_BURST);
    let strict = GovernorLayer {
        config: Arc::new(strict_cfg.finish().expect("valid strict governor config")),
    };

    let mut normal_cfg = GovernorConfigBuilder::default();
    normal_cfg
        .per_millisecond(NORMAL_PERIOD_MS)
        .burst_size(NORMAL_BURST);
    let normal = GovernorLayer {
        config: Arc::new(normal_cfg.finish().expect("valid normal governor config")),
    };

    let api_v1 = api::auth::routes()
        .merge(api::website::routes())
        .layer(strict)
        .merge(
            api::users::routes()
                .merge(api::wallet::routes())
                .layer(normal),
        );

    Router::new()
        .route("/health", get(api::health::health))
        .merge(api::nip05::routes())
        .nest("/api/v1", api_v1)
        .with_state(state)
        // Layers apply outside-in (last added = outermost). Body cap + timeout
        // sit closest to the handlers; CORS + compression wrap them; tracing is
        // outermost so it observes every request (incl. rejected ones).
        // Per-IP rate limiting is layered separately (it needs ConnectInfo).
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(TimeoutLayer::new(REQUEST_TIMEOUT))
        .layer(cors)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
}

/// Build the CORS layer. With no configured origins, allow any origin — safe
/// because authentication is a Bearer token (no cookies), so a cross-origin
/// request carries no ambient credentials. Credentials are never allowed.
fn cors_layer(config: &Config) -> CorsLayer {
    let methods = [Method::GET, Method::POST, Method::OPTIONS];
    let headers = [header::AUTHORIZATION, header::CONTENT_TYPE];
    let base = CorsLayer::new()
        .allow_methods(methods)
        .allow_headers(headers);

    if config.cors_allowed_origins.is_empty() {
        base.allow_origin(Any)
    } else {
        let origins: Vec<HeaderValue> = config
            .cors_allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        base.allow_origin(origins)
    }
}
