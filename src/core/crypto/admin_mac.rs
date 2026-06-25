//! Row-integrity MAC for the admin allowlist.
//!
//! Each `admin_keys` row carries an HMAC over its authorization-bearing fields,
//! keyed by `ADMIN_KEY_INTEGRITY_SECRET` (deliberately separate from
//! `DATABASE_URL`). Because the MAC covers `activated_at` AND `revoked_at`, a
//! DB-write attacker who flips `revoked_at` back to `NULL` (un-revoke) or revives
//! a key produces a mismatch the guard rejects — the MAC proves a pubkey is
//! *currently* authorized, not merely that it once was. Every write that changes
//! a covered field MUST recompute the MAC (the db layer does this centrally).

use chrono::{DateTime, Utc};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use super::pepper::peppered_hex;

/// The covered fields. Timestamps are compared at microsecond precision (the
/// resolution Postgres stores), so the MAC round-trips exactly.
pub struct AdminKeyMacInput<'a> {
    pub id: Uuid,
    pub pubkey: &'a str,
    pub scope: &'a str,
    pub created_at: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// `hex(HMAC-SHA256(secret, "admin_key_mac" ‖ canonical))`. The canonical form is
/// a JSON array (unambiguous escaping) of the covered fields, timestamps as
/// microsecond epochs (`null` when absent — so present-but-zero ≠ absent).
pub fn compute_admin_key_mac(secret: &str, input: &AdminKeyMacInput) -> String {
    let canonical = serde_json::json!([
        input.id.to_string(),
        input.pubkey,
        input.scope,
        input.created_at.timestamp_micros(),
        input.activated_at.map(|t| t.timestamp_micros()),
        input.revoked_at.map(|t| t.timestamp_micros()),
    ])
    .to_string();
    peppered_hex(secret, "admin_key_mac", &canonical)
}

/// Constant-time check of a stored MAC against the recomputed one.
pub fn verify_admin_key_mac(secret: &str, input: &AdminKeyMacInput, mac_hex: &str) -> bool {
    let expected = compute_admin_key_mac(secret, input);
    expected.as_bytes().ct_eq(mac_hex.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn input() -> AdminKeyMacInput<'static> {
        AdminKeyMacInput {
            id: Uuid::from_u128(1),
            pubkey: PK,
            scope: "admin",
            created_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            activated_at: None,
            revoked_at: None,
        }
    }

    #[test]
    fn deterministic_and_verifies() {
        let i = input();
        let mac = compute_admin_key_mac("secret", &i);
        assert!(verify_admin_key_mac("secret", &i, &mac));
    }

    #[test]
    fn rejects_wrong_secret() {
        let i = input();
        let mac = compute_admin_key_mac("secret-A", &i);
        assert!(!verify_admin_key_mac("secret-B", &i, &mac));
    }

    #[test]
    fn revocation_state_is_bound() {
        // The MAC for a revoked key must not validate once revoked_at is cleared
        // (the un-revoke attack), and vice versa.
        let active = input();
        let mac_active = compute_admin_key_mac("secret", &active);

        let mut revoked = input();
        revoked.revoked_at = Some(DateTime::from_timestamp(1_700_000_500, 0).unwrap());
        assert!(!verify_admin_key_mac("secret", &revoked, &mac_active));

        let mac_revoked = compute_admin_key_mac("secret", &revoked);
        assert!(!verify_admin_key_mac("secret", &active, &mac_revoked));
    }

    #[test]
    fn activation_state_is_bound() {
        let pending = input();
        let mac_pending = compute_admin_key_mac("secret", &pending);
        let mut activated = input();
        activated.activated_at = Some(DateTime::from_timestamp(1_700_000_100, 0).unwrap());
        assert!(!verify_admin_key_mac("secret", &activated, &mac_pending));
    }
}
