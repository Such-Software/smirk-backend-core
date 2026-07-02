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

/// NIP-59 gift-wrap event kind (the sealed envelope carrying a NIP-17 DM).
pub const GIFT_WRAP_KIND: u64 = 1059;

/// Operator write policy. Parsed from the validated `RELAY_WRITE_POLICY` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritePolicy {
    Open,
    AuthorAllowlist,
    InboxOutbox,
}

impl WritePolicy {
    /// Parse the config string. Returns `None` for an unknown value (config
    /// `validate()` already rejects those at startup, so callers can `expect`).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "open" => Some(Self::Open),
            "author-allowlist" => Some(Self::AuthorAllowlist),
            "inbox-outbox" => Some(Self::InboxOutbox),
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

/// Decide whether to admit an event.
///
/// `author_registered` = the author pubkey is a registered Smirk npub.
/// `recipient_registered` = at least one `p` tag is a registered Smirk npub.
/// (The caller resolves both against the DB before calling.)
pub fn decide(
    meta: &EventMeta,
    policy: WritePolicy,
    inbound_pow_bits: u8,
    author_registered: bool,
    recipient_registered: bool,
) -> Admit {
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
            } else if meta.kind == GIFT_WRAP_KIND && recipient_registered {
                // Inbox: an external author delivering a gift-wrapped DM to one of
                // our users. Optionally require proof-of-work to blunt spam.
                if inbound_pow_bits > 0
                    && leading_zero_bits(meta.id_hex) < u32::from(inbound_pow_bits)
                {
                    Admit::Deny("insufficient proof-of-work for cross-ecosystem delivery")
                } else {
                    Admit::Permit
                }
            } else {
                Admit::Deny(
                    "external authors may only deliver gift-wrapped DMs to registered users",
                )
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
        assert_eq!(WritePolicy::parse("nope"), None);
    }

    #[test]
    fn open_permits_everything() {
        let m = meta(A, 1, FF);
        assert!(decide(&m, WritePolicy::Open, 0, false, false).is_permit());
    }

    #[test]
    fn author_allowlist_gates_on_author() {
        let m = meta(A, 1, FF);
        assert!(decide(&m, WritePolicy::AuthorAllowlist, 0, true, false).is_permit());
        assert!(!decide(&m, WritePolicy::AuthorAllowlist, 0, false, false).is_permit());
    }

    #[test]
    fn inbox_outbox_permits_registered_author_outbox() {
        let m = meta(A, 1, FF); // any kind, registered author
        assert!(decide(&m, WritePolicy::InboxOutbox, 0, true, false).is_permit());
    }

    #[test]
    fn inbox_outbox_permits_giftwrap_to_registered_recipient() {
        let m = meta(A, GIFT_WRAP_KIND, FF);
        assert!(decide(&m, WritePolicy::InboxOutbox, 0, false, true).is_permit());
    }

    #[test]
    fn inbox_outbox_rejects_external_non_giftwrap() {
        let m = meta(A, 1, FF); // external author, non-gift-wrap
        assert!(!decide(&m, WritePolicy::InboxOutbox, 0, false, true).is_permit());
    }

    #[test]
    fn inbox_outbox_rejects_giftwrap_to_unregistered_recipient() {
        let m = meta(A, GIFT_WRAP_KIND, FF);
        assert!(!decide(&m, WritePolicy::InboxOutbox, 0, false, false).is_permit());
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
        assert!(decide(&m, WritePolicy::InboxOutbox, 8, false, true).is_permit());
        assert!(!decide(&m, WritePolicy::InboxOutbox, 20, false, true).is_permit());
    }

    #[test]
    fn inbound_pow_does_not_gate_registered_outbox() {
        // A registered author's low-PoW event is still fine (PoW is inbound-only).
        let id = "ff".repeat(32); // 0 leading zero bits
        let m = meta(A, 1, &id);
        assert!(decide(&m, WritePolicy::InboxOutbox, 20, true, false).is_permit());
    }
}
