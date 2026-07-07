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

pub mod nauthz;
mod policy;

pub use policy::{decide, leading_zero_bits, Admit, EventMeta, WritePolicy, GIFT_WRAP_KIND};

use std::collections::HashSet;
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
    /// Max event size (bytes) the admission service enforces as defence-in-depth
    /// (the relay enforces its own limit too).
    fn max_event_bytes(&self) -> usize;
    /// Whether `author_hex` (canonical lowercase x-only pubkey hex) is on the
    /// operator write-allowlist — may publish any kind regardless of policy or
    /// premium. Default: never. See `RELAY_WRITE_ALLOWLIST_NPUBS`.
    fn is_write_allowlisted(&self, _author_hex: &str) -> bool {
        false
    }
    /// NIPs advertised as supported.
    fn supported_nips(&self) -> &'static [u16] {
        SUPPORTED_NIPS
    }
}

/// Normalize a write-allowlist entry (`npub1…` or 64-char hex) to canonical
/// lowercase x-only pubkey hex, or `None` if it isn't a valid pubkey. npubs are
/// bech32-decoded; hex is validated + lowercased. Keeps the admission comparison
/// (which is hex) operator-friendly (npubs) without a hex-only requirement.
fn allowlist_entry_to_hex(entry: &str) -> Option<String> {
    let s = entry.trim();
    if s.is_empty() {
        return None;
    }
    if s.starts_with("npub1") {
        // bech32 npub → 32-byte x-only pubkey → hex.
        let (hrp, data) = bech32::decode(s).ok()?;
        if hrp.as_str() != "npub" || data.len() != 32 {
            return None;
        }
        return Some(hex::encode(data));
    }
    // Bare hex (x-only = 32 bytes = 64 chars).
    let lower = s.to_lowercase();
    if lower.len() == 64 && hex::decode(&lower).is_ok() {
        Some(lower)
    } else {
        None
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
        "bundled" | "external" => {
            // Decode the operator write-allowlist to canonical hex once, at
            // startup. A malformed entry is logged + skipped rather than failing
            // the whole boot (the relay still works; that npub just isn't exempt).
            let mut write_allowlist: HashSet<String> = HashSet::new();
            for entry in &r.write_allowlist {
                match allowlist_entry_to_hex(entry) {
                    Some(hex) => {
                        write_allowlist.insert(hex);
                    }
                    None => tracing::warn!(
                        "RELAY_WRITE_ALLOWLIST_NPUBS: skipping invalid entry {entry:?}"
                    ),
                }
            }
            Arc::new(NostrRelayProvider {
                kind: if r.mode == "bundled" {
                    "nostr-rs-relay"
                } else {
                    "external"
                },
                advertised_url: r.advertised_url.clone(),
                policy,
                inbound_pow_bits: r.inbound_pow_bits,
                max_event_bytes: r.max_event_bytes,
                write_allowlist,
            })
        }
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
    max_event_bytes: usize,
    /// Canonical-hex write-exempt pubkeys (decoded from config npubs/hex).
    write_allowlist: HashSet<String>,
}

#[cfg(test)]
mod tests {
    use super::allowlist_entry_to_hex;

    // Canonical NIP-19 test vector.
    const NPUB: &str = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
    const HEX: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

    #[test]
    fn decodes_npub_to_hex() {
        assert_eq!(allowlist_entry_to_hex(NPUB).as_deref(), Some(HEX));
    }

    #[test]
    fn accepts_bare_hex_and_lowercases() {
        assert_eq!(allowlist_entry_to_hex(HEX).as_deref(), Some(HEX));
        assert_eq!(
            allowlist_entry_to_hex(&format!("  {}  ", HEX.to_uppercase())).as_deref(),
            Some(HEX),
        );
    }

    #[test]
    fn rejects_junk() {
        assert_eq!(allowlist_entry_to_hex(""), None);
        assert_eq!(allowlist_entry_to_hex("not-a-key"), None);
        assert_eq!(allowlist_entry_to_hex("npub1garbage"), None);
        assert_eq!(allowlist_entry_to_hex("deadbeef"), None); // too short
    }
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
    fn max_event_bytes(&self) -> usize {
        self.max_event_bytes
    }
    fn is_write_allowlisted(&self, author_hex: &str) -> bool {
        !self.write_allowlist.is_empty() && self.write_allowlist.contains(author_hex)
    }
}
