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
    /// First-party Nostr relay (encrypted DM inbox). See `messaging` for details.
    pub nostr_relay: bool,
    /// Paid premium tier for general Nostr posting to the relay. See `premium`.
    pub premium_relay: bool,
    /// Public curated Nostr feed for this instance. See `feed`.
    pub feed: bool,
    /// Tipping (parked).
    pub tips: bool,
}

/// First-party Nostr relay details (present only when `features.nostr_relay`).
/// The wallet connects here as its DM inbox (alongside the public interop
/// relays) and adapts its UI to the policy.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MessagingCapability {
    /// The ws(s):// relay URL clients connect to.
    pub relay_url: String,
    /// Write policy: `inbox-outbox` | `author-allowlist` | `open` | `premium-post`.
    pub write_policy: String,
    /// NIP-13 PoW bits required on cross-ecosystem inbound (0 = off).
    pub inbound_pow_bits: u8,
    /// NIPs the relay speaks (e.g. `[1, 17, 44, 59]`).
    pub supported_nips: Vec<u16>,
}

/// A single premium plan (discount tier): `days` of relay-posting access for
/// `amount` in [`PremiumCapability::currency`].
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PremiumPlanInfo {
    pub id: String,
    pub days: i32,
    pub amount: String,
}

/// Premium tier details (present only when `features.premium_relay`). The wallet
/// renders the plan tiers (discount visible) and gates general-Nostr posting to
/// the Smirk relay on the user's premium status; wallet events stay free.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PremiumCapability {
    pub currency: String,
    pub plans: Vec<PremiumPlanInfo>,
    /// The relay premium posting targets (mirrors `messaging.relay_url`).
    pub relay_url: String,
}

/// Public curated feed details (present only when `features.feed`). A read-only
/// web feed (e.g. `feed.<domain>`) reads from the relay and shows posts per the
/// operator's curation knobs.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FeedCapability {
    /// The relay the feed reads from (mirrors `messaging.relay_url`).
    pub relay_url: String,
    /// Include the operator's own posts.
    pub show_owner: bool,
    /// Include premium members' posts (all general notes on the gated relay).
    pub show_premium: bool,
    /// The operator's npub for owner filtering + display; `null` when unset.
    pub owner_npub: Option<String>,
    /// Specific featured npubs to surface.
    pub allowlist_npubs: Vec<String>,
    /// Extra relays to also pull the allowlisted authors from.
    pub extra_relays: Vec<String>,
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
    /// A settled payment invoice (from `/auth/payment-invoice`) is required to
    /// register a new wallet.
    pub payment_required: bool,
    /// The registration price + currency — present only when `payment_required`,
    /// so the wallet can show "registration costs X" before minting an invoice.
    pub payment_amount: Option<String>,
    pub payment_currency: Option<String>,
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
    /// First-party Nostr relay details; present only when `features.nostr_relay`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messaging: Option<MessagingCapability>,
    /// Premium tier details; present only when `features.premium_relay`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub premium: Option<PremiumCapability>,
    /// Public curated feed details; present only when `features.feed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feed: Option<FeedCapability>,
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
            // Relay advertised only when enabled AND a URL is configured (config
            // presence downgrade — never advertise a relay clients can't reach).
            nostr_relay: relay_advertised(config),
            premium_relay: premium_advertised(config),
            feed: feed_advertised(config),
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
            payment_required: config.registration.payment.require_payment,
            payment_amount: config
                .registration
                .payment
                .require_payment
                .then(|| config.registration.payment.amount.clone()),
            payment_currency: config
                .registration
                .payment
                .require_payment
                .then(|| config.registration.payment.currency.clone()),
        },
        messaging: relay_advertised(config).then(|| {
            let r = &config.messaging.relay;
            MessagingCapability {
                relay_url: r.advertised_url.clone(),
                write_policy: r.write_policy.clone(),
                inbound_pow_bits: r.inbound_pow_bits,
                supported_nips: crate::infra::relay::SUPPORTED_NIPS.to_vec(),
            }
        }),
        premium: premium_advertised(config).then(|| PremiumCapability {
            currency: config.premium.currency.clone(),
            plans: config
                .premium
                .plans
                .iter()
                .map(|p| PremiumPlanInfo {
                    id: p.id.clone(),
                    days: p.days,
                    amount: p.amount.clone(),
                })
                .collect(),
            relay_url: config.messaging.relay.advertised_url.clone(),
        }),
        feed: feed_advertised(config).then(|| {
            let f = &config.feed;
            FeedCapability {
                relay_url: config.messaging.relay.advertised_url.clone(),
                show_owner: f.show_owner,
                show_premium: f.show_premium,
                owner_npub: (!f.owner_npub.is_empty()).then(|| f.owner_npub.clone()),
                allowlist_npubs: f.allowlist_npubs.clone(),
                extra_relays: f.extra_relays.clone(),
            }
        }),
    }
}

/// Whether the relay is enabled AND reachable (a URL is configured). Mirrors the
/// chain/nostr-identity secret-presence downgrade: never advertise a relay the
/// client can't connect to.
fn relay_advertised(config: &Config) -> bool {
    config.messaging.relay.enabled && !config.messaging.relay.advertised_url.trim().is_empty()
}

/// Whether the premium tier is enabled AND the relay it gates is advertised
/// (config validation already couples premium to relay + the premium-post policy).
fn premium_advertised(config: &Config) -> bool {
    config.premium.enabled && relay_advertised(config)
}

/// Whether the public feed is enabled AND the relay it reads is advertised.
fn feed_advertised(config: &Config) -> bool {
    config.feed.enabled && relay_advertised(config)
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
