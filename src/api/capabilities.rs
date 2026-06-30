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

/// This instance's wallet-restore (import) policy. The wallet uses it to adapt
/// its import UX — hide/grey the restore-height field under `create-only`, warn
/// when a chosen date exceeds the bound. `max_depth_days` is present only for
/// the `bounded` policy.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RestoreCapability {
    /// `create-only` | `bounded` | `unlimited`.
    pub policy: String,
    pub max_depth_days: Option<u32>,
    /// Restore PoW pricing curve: a restore depth (days) free of PoW, then `+1`
    /// hashcash difficulty bit per `pow_days_per_bit` days beyond it
    /// (`0` = pricing off), capped at `pow_max_bits`. The wallet computes its
    /// required difficulty from this + the restore date and solves the hashcash.
    pub pow_free_days: u32,
    pub pow_days_per_bit: u32,
    pub pow_max_bits: u32,
}

/// Registration gates this instance enforces for a NEW wallet (returning wallets
/// and self-hosting bypass them). The wallet uses these to shape onboarding —
/// prompt for an invite code, solve PoW, etc.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RegistrationCapability {
    /// A valid operator-minted invite code is required to register.
    pub invite_required: bool,
    /// A proof-of-work solution is required to register.
    pub pow_required: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CapabilitiesResponse {
    /// Backend version (Cargo package version).
    pub version: String,
    /// Capabilities contract version (additive changes do not bump it).
    pub contract_version: u32,
    pub chains: ChainCapabilities,
    pub features: FeatureCapabilities,
    /// Wallet restore (import) policy for this instance.
    pub restore: RestoreCapability,
    /// Registration gates for a new wallet on this instance.
    pub registration: RegistrationCapability,
}

/// Whether an enabled chain can actually be served (its infra secret/URL is
/// present). A chain whose flag is on but whose source is unconfigured reports
/// `enabled:false` — so `/capabilities` never advertises a chain that 404s, and
/// a missing-secret downgrade is indistinguishable from a deliberately-off chain.
pub(crate) fn chain_serviceable(config: &Config, asset: &str) -> bool {
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
            // The relay is a non-custodial mailbox (the wallet broadcasts
            // locally), so it is NOT coupled to this backend's Grin chain access.
            grin_relay: config.features.grin_relay,
            prices: config.features.prices,
            // Nostr identity needs the canonical PUBLIC_API_URL.
            nostr_identity: config.features.nostr_identity
                && config.identity.public_api_url.is_some(),
            tips: config.features.tips,
        },
        restore: RestoreCapability {
            policy: config.restore.policy.as_str().to_string(),
            max_depth_days: match config.restore.policy {
                crate::config::RestorePolicy::Bounded => Some(config.restore.max_depth_days),
                _ => None,
            },
            pow_free_days: config.restore.pow_free_days,
            pow_days_per_bit: config.restore.pow_days_per_bit,
            pow_max_bits: config.restore.pow_max_bits,
        },
        registration: RegistrationCapability {
            invite_required: config.registration.require_invite,
            pow_required: config.pow.enabled && config.pow.required,
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
