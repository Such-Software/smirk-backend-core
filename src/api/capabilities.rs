//! Capability discovery.
//!
//! A public, unauthenticated description of what *this* deployment offers, so the
//! wallet can adapt to the instance it's pointed at (grey out disabled chains and
//! features, pick the right network). This is the client-facing half of the
//! open-core/feature-flag design: every capability is a config switch, surfaced
//! here. No secrets — only on/off flags and the public network names.

use std::sync::Arc;

use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;
use tracing::instrument;

use crate::AppState;

/// Per-chain availability. `network` is the configured network for UTXO chains
/// (so the wallet derives addresses for the right one); `null` for chains whose
/// network isn't a backend setting.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ChainCapability {
    pub enabled: bool,
    pub network: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ChainCapabilities {
    pub btc: ChainCapability,
    pub ltc: ChainCapability,
    pub xmr: ChainCapability,
    pub wow: ChainCapability,
    pub grin: ChainCapability,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FeatureCapabilities {
    /// Grin async slatepack relay mailbox.
    pub grin_relay: bool,
    /// Fiat price feed.
    pub prices: bool,
    /// Nostr-native identity (NIP-98 login/link, NIP-05 directory).
    pub nostr_identity: bool,
    /// Tipping (parked).
    pub tips: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CapabilitiesResponse {
    /// Backend version (Cargo package version).
    pub version: String,
    pub chains: ChainCapabilities,
    pub features: FeatureCapabilities,
}

/// Describe this instance's enabled chains and features.
#[utoipa::path(
    get,
    path = "/capabilities",
    responses((status = 200, description = "Enabled chains and features", body = CapabilitiesResponse)),
    tag = "system"
)]
#[instrument(skip(state))]
pub async fn capabilities(State(state): State<Arc<AppState>>) -> Json<CapabilitiesResponse> {
    let cfg = &state.config;
    let chains = &cfg.features.chains;
    Json(CapabilitiesResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        chains: ChainCapabilities {
            btc: ChainCapability {
                enabled: chains.btc,
                network: Some(cfg.chains.btc.network.clone()),
            },
            ltc: ChainCapability {
                enabled: chains.ltc,
                network: Some(cfg.chains.ltc.network.clone()),
            },
            xmr: ChainCapability {
                enabled: chains.xmr,
                network: None,
            },
            wow: ChainCapability {
                enabled: chains.wow,
                network: None,
            },
            grin: ChainCapability {
                enabled: chains.grin,
                network: None,
            },
        },
        features: FeatureCapabilities {
            grin_relay: cfg.features.grin_relay,
            prices: cfg.features.prices,
            nostr_identity: cfg.features.nostr_identity,
            tips: cfg.features.tips,
        },
    })
}

/// Capability route, RELATIVE to the `/api/v1` mount point. Public (no auth).
pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/capabilities", get(capabilities))
}
