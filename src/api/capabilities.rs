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

use crate::config::Config;
use crate::AppState;

/// Capabilities contract version. Bumped only on a breaking shape change; clients
/// soft-notice a higher value and ignore unknown (additive) keys.
pub const CAPABILITIES_CONTRACT_VERSION: u32 = 1;

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
    /// Capabilities contract version (additive changes do not bump it).
    pub contract_version: u32,
    pub chains: ChainCapabilities,
    pub features: FeatureCapabilities,
}

/// Whether an enabled chain can actually be served (its infra secret/URL is
/// present). A chain whose flag is on but whose source is unconfigured reports
/// `enabled:false` — so `/capabilities` never advertises a chain that 404s, and
/// a missing-secret downgrade is indistinguishable from a deliberately-off chain.
fn chain_serviceable(config: &Config, asset: &str) -> bool {
    let f = &config.features.chains;
    let c = &config.chains;
    match asset {
        "btc" => {
            f.btc && (c.btc.electrum_primary.is_some() || !c.btc.electrum_fallbacks.is_empty())
        }
        "ltc" => {
            f.ltc && (c.ltc.electrum_primary.is_some() || !c.ltc.electrum_fallbacks.is_empty())
        }
        "xmr" => f.xmr && !c.xmr.lws_admin_key.is_empty(),
        "wow" => f.wow && !c.wow.lws_admin_key.is_empty(),
        "grin" => f.grin && !c.grin.owner_api_secret.is_empty(),
        _ => false,
    }
}

/// Build the public capabilities projection with the secret-presence downgrade.
pub fn effective_capabilities(config: &Config) -> CapabilitiesResponse {
    let utxo_net = |on: bool, net: &str| ChainCapability {
        enabled: on,
        network: Some(net.to_string()),
    };
    CapabilitiesResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        contract_version: CAPABILITIES_CONTRACT_VERSION,
        chains: ChainCapabilities {
            btc: utxo_net(chain_serviceable(config, "btc"), &config.chains.btc.network),
            ltc: utxo_net(chain_serviceable(config, "ltc"), &config.chains.ltc.network),
            xmr: ChainCapability {
                enabled: chain_serviceable(config, "xmr"),
                network: None,
            },
            wow: ChainCapability {
                enabled: chain_serviceable(config, "wow"),
                network: None,
            },
            grin: ChainCapability {
                enabled: chain_serviceable(config, "grin"),
                network: None,
            },
        },
        features: FeatureCapabilities {
            // The relay needs Grin chain access to be serviceable.
            grin_relay: config.features.grin_relay && chain_serviceable(config, "grin"),
            prices: config.features.prices,
            // Nostr identity needs the canonical PUBLIC_API_URL.
            nostr_identity: config.features.nostr_identity
                && config.identity.public_api_url.is_some(),
            tips: config.features.tips,
        },
    }
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
    Json(effective_capabilities(&state.config))
}

/// Capability route, RELATIVE to the `/api/v1` mount point. Public (no auth).
pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/capabilities", get(capabilities))
}
