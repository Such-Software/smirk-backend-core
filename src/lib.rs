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

use tokio::sync::RwLock;

use crate::config::Config;
use crate::core::session::{SessionManager, WebChallenge};
use crate::infra::db::Database;

/// Shared application state injected into handlers via `State<Arc<AppState>>`.
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: Database,
    pub sessions: SessionManager,
    /// In-memory website-auth challenges, keyed by nonce. Single-node store;
    /// a shared/stateless variant is the load-balanced-fleet path.
    pub web_challenges: Arc<RwLock<HashMap<String, WebChallenge>>>,
}
