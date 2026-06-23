//! Wallet (chain-access) handlers: thin authenticated proxies over the per-chain
//! infra clients. The backend is non-custodial — these endpoints relay reads and
//! finalized broadcasts; all key handling and signing happen in the wallet.
//!
//! Each chain family lives in its own submodule and contributes its routes here.

use std::sync::Arc;

use axum::Router;

use crate::AppState;

pub mod btc_ltc;

/// All wallet routes, RELATIVE to the `/api/v1` mount point.
pub fn routes() -> Router<Arc<AppState>> {
    btc_ltc::routes()
}
