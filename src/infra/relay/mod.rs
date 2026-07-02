//! Optional first-party Nostr relay (messaging plane).
//!
//! The seam that lets `nostr-rs-relay` be swapped for another relay (strfry, an
//! external relay) or, later, a different messaging protocol — mirroring
//! `infra::payment` (trait + `from_config` → `Option<Arc<dyn …>>`, feature-gated,
//! fail-closed) and the client-side ChainProvider seam.
//!
//! The backend does not run the relay process (it never spawns subprocesses — it
//! connects to + advertises external services). Instead it: (1) advertises the
//! relay URL + policy (`/capabilities`, NIP-05 hints), and (2) for a non-`open`
//! write policy, enforces admission via `nostr-rs-relay`'s gRPC event-admission
//! hook, evaluated by the pure engine in [`policy`].

mod policy;

pub use policy::{decide, leading_zero_bits, Admit, EventMeta, WritePolicy, GIFT_WRAP_KIND};

use std::sync::Arc;

use crate::config::Config;
use crate::error::AppError;

/// NIPs the relay integration speaks (advertised via `/capabilities`).
/// 1 = basic protocol, 44 = encryption, 59 = gift-wrap, 17 = private DMs.
pub const SUPPORTED_NIPS: &[u16] = &[1, 17, 44, 59];

/// A messaging-relay backend. Kept thin: the write policy + PoW live in the pure
/// [`policy`] engine, and the admission transport (gRPC nauthz) is the adapter's
/// concern — a future strfry/other adapter can enforce the same policy over a
/// different mechanism.
pub trait RelayProvider: Send + Sync {
    /// Adapter kind, e.g. `nostr-rs-relay` or `external`.
    fn kind(&self) -> &'static str;
    /// The public ws(s):// URL clients connect to + we advertise.
    fn advertised_url(&self) -> &str;
    /// The configured write policy.
    fn write_policy(&self) -> WritePolicy;
    /// NIP-13 PoW bits required on cross-ecosystem inbound (0 = off).
    fn inbound_pow_bits(&self) -> u8;
    /// NIPs advertised as supported.
    fn supported_nips(&self) -> &'static [u16] {
        SUPPORTED_NIPS
    }
}

/// Config-selected relay provider, or `None` when the relay is disabled.
/// Mirrors [`crate::infra::payment::from_config`].
pub fn from_config(cfg: &Config) -> Result<Option<Arc<dyn RelayProvider>>, AppError> {
    let r = &cfg.messaging.relay;
    if !r.enabled {
        return Ok(None);
    }
    // `validate()` already checked the policy string, so this cannot fail in
    // practice; fail closed regardless.
    let policy = WritePolicy::parse(&r.write_policy).ok_or_else(|| {
        AppError::ConfigError(format!("invalid RELAY_WRITE_POLICY: {}", r.write_policy))
    })?;
    let provider: Arc<dyn RelayProvider> = match r.mode.as_str() {
        // From the backend's POV, `bundled` and `external` are the same: a relay
        // reachable at `advertised_url` that we advertise + admit for. They differ
        // only in who runs the process (packaging), a deploy concern.
        "bundled" | "external" => Arc::new(NostrRelayProvider {
            kind: if r.mode == "bundled" {
                "nostr-rs-relay"
            } else {
                "external"
            },
            advertised_url: r.advertised_url.clone(),
            policy,
            inbound_pow_bits: r.inbound_pow_bits,
        }),
        other => {
            return Err(AppError::ConfigError(format!(
                "unsupported RELAY_MODE: {other}"
            )))
        }
    };
    Ok(Some(provider))
}

/// Default adapter: a relay reachable at `advertised_url`. Admission is enforced
/// out-of-band by the gRPC nauthz service using the shared [`policy`] engine.
struct NostrRelayProvider {
    kind: &'static str,
    advertised_url: String,
    policy: WritePolicy,
    inbound_pow_bits: u8,
}

impl RelayProvider for NostrRelayProvider {
    fn kind(&self) -> &'static str {
        self.kind
    }
    fn advertised_url(&self) -> &str {
        &self.advertised_url
    }
    fn write_policy(&self) -> WritePolicy {
        self.policy
    }
    fn inbound_pow_bits(&self) -> u8 {
        self.inbound_pow_bits
    }
}
