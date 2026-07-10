//! `TipStatus` — single source of truth for the `social_tips.status` column.
//!
//! The wire/DB strings here MUST match the `social_tips_status_check` CHECK
//! constraint in `migrations/20260710000001_social_tips.sql` exactly. Setting
//! status in SQL uses `.bind(TipStatus::Pending.as_str())` so the literal
//! matches the constraint by construction; `WHERE status IN (...)` filters stay
//! raw string literals (the CHECK constraint already locks the column).
//!
//! When adding a status, land in the same change: the variant here (+ `as_str`
//! / `from_db` arms), a migration extending the CHECK constraint (a fresh ALTER,
//! never editing a deployed one), and every SQL `status IN (...)` guard.

use std::fmt;

/// The set of legal `social_tips.status` values (lifecycle order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TipStatus {
    /// Two-phase creation, pre-broadcast: `funding_txid` not attached yet. Pure
    /// DB row, no on-chain footprint.
    Draft,
    /// Funding tx attached but not yet confirmed to threshold, or the verifier
    /// hasn't observed the on-chain receipt. The verifier flips this to
    /// `Pending` (covered), `FundingMismatch` (short), or leaves it here.
    PendingConfirmation,
    /// Funding confirmed AND amount-verified: claimable (URL holders can claim).
    Pending,
    /// `mark_tip_claiming` lock held; claimer is mid-sweep. Settles to `Claimed`
    /// when the sweep confirms on-chain.
    Claiming,
    /// Sweep confirmed on-chain. Terminal.
    Claimed,
    /// Sender reclaimed the funds via clawback. Terminal.
    ClawedBack,
    /// Draft abandoned (manual cancel or GC of a stale draft / stuck
    /// pending_confirmation). May still hold on-chain funds — clawback covers
    /// the recoverable case. Terminal for the forward lifecycle.
    Cancelled,
    /// Verifier saw a positive on-chain receipt strictly less than the declared
    /// amount. Never becomes claimable; the sender can clawback. NON-terminal.
    FundingMismatch,
}

impl TipStatus {
    /// Wire / DB string. MUST match the CHECK constraint exactly.
    pub const fn as_str(self) -> &'static str {
        match self {
            TipStatus::Draft => "draft",
            TipStatus::PendingConfirmation => "pending_confirmation",
            TipStatus::Pending => "pending",
            TipStatus::Claiming => "claiming",
            TipStatus::Claimed => "claimed",
            TipStatus::ClawedBack => "clawed_back",
            TipStatus::Cancelled => "cancelled",
            TipStatus::FundingMismatch => "funding_mismatch",
        }
    }

    /// Parse the DB string back into a `TipStatus`. `None` for any value outside
    /// the CHECK set (we prefer `None` over a panic on an unexpected string).
    pub fn from_db(s: &str) -> Option<Self> {
        match s {
            "draft" => Some(TipStatus::Draft),
            "pending_confirmation" => Some(TipStatus::PendingConfirmation),
            "pending" => Some(TipStatus::Pending),
            "claiming" => Some(TipStatus::Claiming),
            "claimed" => Some(TipStatus::Claimed),
            "clawed_back" => Some(TipStatus::ClawedBack),
            "cancelled" => Some(TipStatus::Cancelled),
            "funding_mismatch" => Some(TipStatus::FundingMismatch),
            _ => None,
        }
    }

    /// True iff the row is past the lifecycle's terminal cliff. The verifier and
    /// reconciler skip already-settled rows. `FundingMismatch` is NON-terminal
    /// (the sender can still clawback).
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            TipStatus::Claimed | TipStatus::ClawedBack | TipStatus::Cancelled,
        )
    }
}

impl fmt::Display for TipStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Confirmations required before an asset's funding tx is spendable/claimable.
/// XMR 10, GRIN 10, WOW 4, BTC/LTC 0 (immediately spendable).
pub const fn confirmations_for_asset(asset: &str) -> i32 {
    match asset.as_bytes() {
        b"xmr" => 10,
        b"grin" => 10,
        b"wow" => 4,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_every_variant() {
        for variant in [
            TipStatus::Draft,
            TipStatus::PendingConfirmation,
            TipStatus::Pending,
            TipStatus::Claiming,
            TipStatus::Claimed,
            TipStatus::ClawedBack,
            TipStatus::Cancelled,
            TipStatus::FundingMismatch,
        ] {
            assert_eq!(
                TipStatus::from_db(variant.as_str()),
                Some(variant),
                "round-trip failed for {variant:?}",
            );
        }
    }

    #[test]
    fn wire_strings_match_check_constraint() {
        assert_eq!(TipStatus::Draft.as_str(), "draft");
        assert_eq!(TipStatus::PendingConfirmation.as_str(), "pending_confirmation");
        assert_eq!(TipStatus::Pending.as_str(), "pending");
        assert_eq!(TipStatus::Claiming.as_str(), "claiming");
        assert_eq!(TipStatus::Claimed.as_str(), "claimed");
        assert_eq!(TipStatus::ClawedBack.as_str(), "clawed_back");
        assert_eq!(TipStatus::Cancelled.as_str(), "cancelled");
        assert_eq!(TipStatus::FundingMismatch.as_str(), "funding_mismatch");
    }

    #[test]
    fn only_claimed_clawedback_cancelled_are_terminal() {
        assert!(TipStatus::Claimed.is_terminal());
        assert!(TipStatus::ClawedBack.is_terminal());
        assert!(TipStatus::Cancelled.is_terminal());
        assert!(!TipStatus::FundingMismatch.is_terminal());
        assert!(!TipStatus::Pending.is_terminal());
        assert!(!TipStatus::Draft.is_terminal());
        assert!(!TipStatus::PendingConfirmation.is_terminal());
        assert!(!TipStatus::Claiming.is_terminal());
    }

    #[test]
    fn from_db_returns_none_for_unknown() {
        assert_eq!(TipStatus::from_db("bogus"), None);
        assert_eq!(TipStatus::from_db(""), None);
        assert_eq!(TipStatus::from_db("Draft"), None);
    }

    #[test]
    fn confirmations_by_asset() {
        assert_eq!(confirmations_for_asset("xmr"), 10);
        assert_eq!(confirmations_for_asset("wow"), 4);
        assert_eq!(confirmations_for_asset("btc"), 0);
        assert_eq!(confirmations_for_asset("ltc"), 0);
        assert_eq!(confirmations_for_asset("grin"), 10);
    }
}
