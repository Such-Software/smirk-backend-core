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

use axum::{routing::get, Router};
use tokio::sync::RwLock;

use crate::config::Config;
use crate::core::session::{SessionManager, WebChallenge};
use crate::infra::chains::ChainClients;
use crate::infra::db::Database;

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
    let api_v1 = api::auth::routes()
        .merge(api::website::routes())
        .merge(api::users::routes());

    Router::new()
        .route("/health", get(api::health::health))
        .merge(api::nip05::routes())
        .nest("/api/v1", api_v1)
        .with_state(state)
}
