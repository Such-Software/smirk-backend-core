//! Background funding worker for public social tips (the "money-in" path).
//!
//! One periodic pass ([`run_tip_confirmation_cycle`], spawned from `main` on a
//! 60s interval when `FEATURE_TIPS` is on):
//!
//!   1. Confirmation-count pass for the poll-only CryptoNote assets (XMR/WOW):
//!      read the daemon's confirmation count for each funded tip and record it.
//!   2. Amount-verification pass across every `pending_confirmation` tip that
//!      has reached its confirmation threshold — check that the on-chain receipt
//!      at the tip address actually covers the sender-declared `amount` before
//!      flipping the row claimable. BTC/LTC (threshold 0) enter here directly.
//!
//! Money-safety invariant: any upstream failure (LWS/Electrum outage, a hostile
//! response, a missing address/view-key) leaves the row untouched except for the
//! `last_confirmation_check` rate-limit stamp — it NEVER mutates status. An
//! outage can therefore never mass-flip pending tips to `funding_mismatch`.

pub mod confirmation;
pub mod sweep_reconciler;

pub use confirmation::run_tip_confirmation_cycle;
pub use sweep_reconciler::{run_sweep_reconcile_cycle, run_sweep_reorg_cycle};
