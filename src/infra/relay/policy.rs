//! Relay write-admission policy — a PURE decision function.
//!
//! The gRPC admission service (nostr-rs-relay's `nauthz` hook) resolves the two
//! registration booleans against the DB, then calls [`decide`]. Keeping the
//! decision pure makes every branch unit-testable without a relay or a database.
//!
//! Policies (operator-configured, `RELAY_WRITE_POLICY`):
//! * `open` — accept everything (resource caps in the relay itself still apply).
//! * `author-allowlist` — only registered Smirk npubs may publish anything.
//! * `inbox-outbox` (default) — registered npubs publish their own events
//!   (outbox); anyone may deliver a NIP-17 gift-wrap (kind 1059) ADDRESSED to a
//!   registered user (inbox), optionally behind a NIP-13 proof-of-work gate to
//!   blunt cross-ecosystem spam. Everything else is rejected.
//! * `premium-post` — registered users publish `WALLET_KINDS` (DMs, tips, swap
//!   coordination) free; a general (non-wallet) event requires the author to hold
//!   an active premium subscription. Inbox delivery works as in `inbox-outbox`.

/// NIP-59 gift-wrap event kind (the sealed envelope carrying a NIP-17 DM).
pub const GIFT_WRAP_KIND: u64 = 1059;

/// Event kinds that make the Smirk wallet + its peer features work — free to
/// publish for any registered user under the `premium-post` policy (premium
/// unlocks *general* Nostr posting on top). Extensible as tip / atomic-swap
/// coordination kinds define their on-Nostr shape.
pub const WALLET_KINDS: &[u64] = &[
    GIFT_WRAP_KIND, // 1059 — NIP-17 encrypted DMs (incl. tip + swap payloads)
    10050,          // NIP-17 DM relay list (where a user receives DMs)
];

fn is_wallet_kind(kind: u64) -> bool {
    WALLET_KINDS.contains(&kind)
}

/// Operator write policy. Parsed from the validated `RELAY_WRITE_POLICY` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritePolicy {
    Open,
    AuthorAllowlist,
    InboxOutbox,
    /// Wallet events free for registered users; general Nostr posting requires an
    /// active premium subscription.
    PremiumPost,
}

impl WritePolicy {
    /// Parse the config string. Returns `None` for an unknown value (config
    /// `validate()` already rejects those at startup, so callers can `expect`).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "open" => Some(Self::Open),
            "author-allowlist" => Some(Self::AuthorAllowlist),
            "inbox-outbox" => Some(Self::InboxOutbox),
            "premium-post" => Some(Self::PremiumPost),
            _ => None,
        }
    }
}

/// The admission decision. `Deny` carries a static, non-sensitive reason (the
/// relay may surface it to the publisher).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    Permit,
    Deny(&'static str),
}

impl Admit {
    pub fn is_permit(&self) -> bool {
        matches!(self, Admit::Permit)
    }
}

/// The event facts the decision needs. The author + recipient registration
/// lookups are resolved by the caller (against the DB) and passed in as booleans
/// so this stays pure.
pub struct EventMeta<'a> {
    /// x-only pubkey hex of the event author (canonical lowercase).
    pub author_pubkey: &'a str,
    /// Event kind.
    pub kind: u64,
    /// Event id hex (used for the NIP-13 PoW check).
    pub id_hex: &'a str,
}

/// NIP-13 difficulty: the number of leading zero BITS of the (32-byte) event id.
pub fn leading_zero_bits(id_hex: &str) -> u32 {
    let Ok(bytes) = hex::decode(id_hex) else {
        return 0;
    };
    let mut count = 0u32;
    for b in bytes {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros(); // u8::leading_zeros ∈ 0..=7 here
            break;
        }
    }
    count
}

/// Inbox delivery of a NIP-17 gift-wrap (kind 1059) to a registered user,
/// optionally behind a NIP-13 PoW gate. Shared by `inbox-outbox` + `premium-post`.
fn giftwrap_inbox(meta: &EventMeta, inbound_pow_bits: u8, recipient_registered: bool) -> Admit {
    if meta.kind == GIFT_WRAP_KIND && recipient_registered {
        // Optionally require proof-of-work to blunt cross-ecosystem spam.
        if inbound_pow_bits > 0 && leading_zero_bits(meta.id_hex) < u32::from(inbound_pow_bits) {
            Admit::Deny("insufficient proof-of-work for cross-ecosystem delivery")
        } else {
            Admit::Permit
        }
    } else {
        Admit::Deny("external authors may only deliver gift-wrapped DMs to registered users")
    }
}

/// Decide whether to admit an event.
///
/// `author_registered` = the author pubkey is a registered Smirk npub.
/// `recipient_registered` = at least one `p` tag is a registered Smirk npub.
/// `author_premium` = the author holds an active premium subscription (only the
/// `premium-post` policy consults it).
/// `author_allowlisted` = the author is on the operator's write-allowlist
/// (`RELAY_WRITE_ALLOWLIST_NPUBS`) — e.g. the announcements / feed-owner account.
/// The caller resolves all of these before calling.
pub fn decide(
    meta: &EventMeta,
    policy: WritePolicy,
    inbound_pow_bits: u8,
    author_registered: bool,
    recipient_registered: bool,
    author_premium: bool,
    author_allowlisted: bool,
) -> Admit {
    // Operator write-allowlist: an owner/announcements npub may publish ANY kind
    // regardless of policy or premium. Checked first so the owner can seed a
    // premium-post feed (and post announcements) without a subscription.
    if author_allowlisted {
        return Admit::Permit;
    }
    match policy {
        WritePolicy::Open => Admit::Permit,
        WritePolicy::AuthorAllowlist => {
            if author_registered {
                Admit::Permit
            } else {
                Admit::Deny("author is not a registered npub")
            }
        }
        WritePolicy::InboxOutbox => {
            if author_registered {
                // Outbox: a registered user publishing their own events.
                Admit::Permit
            } else {
                giftwrap_inbox(meta, inbound_pow_bits, recipient_registered)
            }
        }
        WritePolicy::PremiumPost => {
            if author_premium {
                // Premium member: the general-purpose relay — any kind.
                Admit::Permit
            } else if author_registered && is_wallet_kind(meta.kind) {
                // Free for registered users: the events that make the wallet work.
                Admit::Permit
            } else if author_registered {
                // Registered, but a general (non-wallet) event without premium.
                Admit::Deny(
                    "premium membership required to post general Nostr events to this relay",
                )
            } else {
                // External author: only gift-wrapped DM inbox delivery, as inbox-outbox.
                giftwrap_inbox(meta, inbound_pow_bits, recipient_registered)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta<'a>(author: &'a str, kind: u64, id: &'a str) -> EventMeta<'a> {
        EventMeta {
            author_pubkey: author,
            kind,
            id_hex: id,
        }
    }

    // Placeholder author x-only hex (64 chars).
    const A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    // A 64-char id with zero leading-zero bits.
    const FF: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    #[test]
    fn parse_roundtrip() {
        assert_eq!(WritePolicy::parse("open"), Some(WritePolicy::Open));
        assert_eq!(
            WritePolicy::parse("author-allowlist"),
            Some(WritePolicy::AuthorAllowlist)
        );
        assert_eq!(
            WritePolicy::parse("inbox-outbox"),
            Some(WritePolicy::InboxOutbox)
        );
        assert_eq!(
            WritePolicy::parse("premium-post"),
            Some(WritePolicy::PremiumPost)
        );
        assert_eq!(WritePolicy::parse("nope"), None);
    }

    #[test]
    fn open_permits_everything() {
        let m = meta(A, 1, FF);
        assert!(decide(&m, WritePolicy::Open, 0, false, false, false, false).is_permit());
    }

    #[test]
    fn author_allowlist_gates_on_author() {
        let m = meta(A, 1, FF);
        assert!(decide(
            &m,
            WritePolicy::AuthorAllowlist,
            0,
            true,
            false,
            false,
            false
        )
        .is_permit());
        assert!(!decide(
            &m,
            WritePolicy::AuthorAllowlist,
            0,
            false,
            false,
            false,
            false
        )
        .is_permit());
    }

    #[test]
    fn inbox_outbox_permits_registered_author_outbox() {
        let m = meta(A, 1, FF); // any kind, registered author
        assert!(decide(&m, WritePolicy::InboxOutbox, 0, true, false, false, false).is_permit());
    }

    #[test]
    fn inbox_outbox_permits_giftwrap_to_registered_recipient() {
        let m = meta(A, GIFT_WRAP_KIND, FF);
        assert!(decide(&m, WritePolicy::InboxOutbox, 0, false, true, false, false).is_permit());
    }

    #[test]
    fn inbox_outbox_rejects_external_non_giftwrap() {
        let m = meta(A, 1, FF); // external author, non-gift-wrap
        assert!(!decide(&m, WritePolicy::InboxOutbox, 0, false, true, false, false).is_permit());
    }

    #[test]
    fn inbox_outbox_rejects_giftwrap_to_unregistered_recipient() {
        let m = meta(A, GIFT_WRAP_KIND, FF);
        assert!(!decide(&m, WritePolicy::InboxOutbox, 0, false, false, false, false).is_permit());
    }

    #[test]
    fn leading_zero_bits_counts_correctly() {
        assert_eq!(leading_zero_bits(FF), 0);
        assert_eq!(leading_zero_bits(&format!("00{}", "ff".repeat(31))), 8);
        assert_eq!(leading_zero_bits(&format!("0f{}", "ff".repeat(31))), 4);
        assert_eq!(leading_zero_bits(&format!("0000{}", "ff".repeat(30))), 16);
    }

    #[test]
    fn inbound_pow_gates_the_inbox_branch() {
        // id with 16 leading zero bits.
        let id = format!("0000{}", "ff".repeat(30));
        let m = meta(A, GIFT_WRAP_KIND, &id);
        // require 8 bits → permit; require 20 → deny.
        assert!(decide(&m, WritePolicy::InboxOutbox, 8, false, true, false, false).is_permit());
        assert!(!decide(&m, WritePolicy::InboxOutbox, 20, false, true, false, false).is_permit());
    }

    #[test]
    fn inbound_pow_does_not_gate_registered_outbox() {
        // A registered author's low-PoW event is still fine (PoW is inbound-only).
        let id = "ff".repeat(32); // 0 leading zero bits
        let m = meta(A, 1, &id);
        assert!(decide(&m, WritePolicy::InboxOutbox, 20, true, false, false, false).is_permit());
    }

    // ── premium-post ─────────────────────────────────────────────────────────

    #[test]
    fn premium_post_premium_author_posts_anything() {
        let m = meta(A, 1, FF); // a general kind-1 note
                                // premium → permit even a non-wallet kind.
        assert!(decide(&m, WritePolicy::PremiumPost, 0, true, false, true, false).is_permit());
    }

    #[test]
    fn premium_post_registered_gets_wallet_kinds_free() {
        for k in WALLET_KINDS {
            let m = meta(A, *k, FF);
            // registered, NOT premium → wallet kinds still permitted.
            assert!(
                decide(&m, WritePolicy::PremiumPost, 0, true, false, false, false).is_permit(),
                "wallet kind {k} should be free for registered users"
            );
        }
    }

    #[test]
    fn premium_post_registered_needs_premium_for_general() {
        let m = meta(A, 1, FF); // general kind-1, registered but not premium
        assert!(!decide(&m, WritePolicy::PremiumPost, 0, true, false, false, false).is_permit());
    }

    #[test]
    fn premium_post_allows_external_giftwrap_inbox() {
        let m = meta(A, GIFT_WRAP_KIND, FF);
        // external (unregistered) author delivering a DM to a registered user.
        assert!(decide(&m, WritePolicy::PremiumPost, 0, false, true, false, false).is_permit());
    }

    #[test]
    fn premium_post_rejects_external_general() {
        let m = meta(A, 1, FF); // external author, non-gift-wrap
        assert!(!decide(&m, WritePolicy::PremiumPost, 0, false, true, false, false).is_permit());
    }

    // ── write-allowlist (owner/announcements exemption) ──────────────────────

    #[test]
    fn allowlisted_author_posts_general_note_under_premium_post() {
        // The owner npub is NOT premium and NOT otherwise registered, but is on
        // the write-allowlist → may post a general kind-1 note to a premium relay.
        let m = meta(A, 1, FF);
        assert!(
            decide(&m, WritePolicy::PremiumPost, 0, false, false, false, true).is_permit(),
            "an allowlisted owner must be able to seed a premium-post feed"
        );
    }

    #[test]
    fn allowlist_bypasses_every_policy_and_kind() {
        for policy in [
            WritePolicy::Open,
            WritePolicy::AuthorAllowlist,
            WritePolicy::InboxOutbox,
            WritePolicy::PremiumPost,
        ] {
            for kind in [1u64, GIFT_WRAP_KIND, 30023] {
                let m = meta(A, kind, FF);
                assert!(
                    decide(&m, policy, 8, false, false, false, true).is_permit(),
                    "allowlisted author should be permitted under {policy:?} for kind {kind}"
                );
            }
        }
    }

    #[test]
    fn non_allowlisted_still_gated() {
        // Sanity: with allowlisted=false the premium gate still bites.
        let m = meta(A, 1, FF);
        assert!(!decide(&m, WritePolicy::PremiumPost, 0, true, false, false, false).is_permit());
    }
}
