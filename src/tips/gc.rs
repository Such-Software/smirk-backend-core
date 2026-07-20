//! Lifecycle + draft garbage-collection passes for public social tips.
//!
//! Two periodic janitor cycles, each spawned from `main` behind `FEATURE_TIPS`:
//!
//!   - [`run_tip_draft_gc_cycle`] (hourly): cancel `draft` rows abandoned
//!     mid-flow (created > 7 days ago, never funded-attached). Cancels the row
//!     and `warn!`s per cancelled draft so an operator can audit the
//!     funded-but-not-attached case (the sender may have broadcast the funding
//!     tx before the attach call landed).
//!
//!   - [`run_tip_lifecycle_gc_cycle`] (5 min): cancel `pending_confirmation`
//!     rows stuck > 7 days (RBF eviction / mempool drop / LWS blind spot left
//!     the funding tx unconfirmed forever), and READ-ONLY-scan `claiming` rows
//!     stuck > 15 minutes (`confirm_tip_sweep` never landed) for operator
//!     visibility — the scan mutates NOTHING.
//!
//! Ported (public subset) from the legacy `core/tip_draft_gc.rs` +
//! `core/tip_lifecycle_gc.rs`. The intervals + WHERE clauses live in the DB
//! methods (`cancel_old_drafts` / `cancel_stuck_pending_confirmation` /
//! `log_stuck_claiming`); these workers are the warn-per-row surface over them.
//!
//! MONEY-SAFETY: the two cancel passes flip funded-but-not-attached rows to
//! `cancelled` with no on-chain funds check — the 7-day window, the per-row
//! `warn!`, and clawback INCLUDING `cancelled` (see `clawback_social_tip`) are
//! the only mitigations. Neither pass ever touches a `pending` / `claiming`
//! (already-broadcast) row: cancels are `draft`/`pending_confirmation`-only and
//! the claiming scan is read-only.

use std::sync::Arc;

use tracing::{info, warn};

use crate::AppState;

/// One draft-GC cycle: cancel `draft` rows older than 7 days and `warn!` per
/// cancelled row. Never returns an error — a DB failure is logged and swallowed
/// so the spawn loop survives.
pub async fn run_tip_draft_gc_cycle(state: Arc<AppState>) {
    match state.db.cancel_old_drafts().await {
        Ok(cancelled) => {
            for row in &cancelled {
                warn!(
                    tip_id = %row.id,
                    asset = %row.asset,
                    tip_address = %row.tip_address.as_deref().unwrap_or("<none>"),
                    funding_txid = %row.funding_txid.as_deref().unwrap_or("<none>"),
                    created_at = %row.created_at,
                    "tip-draft GC: cancelled abandoned draft (operator: check tip_address for \
                     on-chain funds — a funded-but-not-attached draft is recoverable via clawback)"
                );
            }
            if !cancelled.is_empty() {
                info!(
                    count = cancelled.len(),
                    "tip-draft GC: cancelled abandoned drafts"
                );
            }
        }
        Err(e) => warn!(error = %e, "tip-draft GC cycle failed"),
    }
}

/// One lifecycle-GC cycle: cancel stuck `pending_confirmation` rows (> 7 days,
/// warn per row) then READ-ONLY-scan stuck `claiming` rows (> 15 min, warn-only,
/// mutates nothing). Two independent passes — a failure in one is logged and
/// does not abort the other. Never returns an error.
pub async fn run_tip_lifecycle_gc_cycle(state: Arc<AppState>) {
    match state.db.cancel_stuck_pending_confirmation().await {
        Ok(cancelled) => {
            for row in &cancelled {
                warn!(
                    tip_id = %row.id,
                    asset = %row.asset,
                    tip_address = %row.tip_address.as_deref().unwrap_or("<none>"),
                    funding_txid = %row.funding_txid.as_deref().unwrap_or("<none>"),
                    created_at = %row.created_at,
                    "tip-lifecycle GC: cancelled stuck pending_confirmation (funding tx never \
                     confirmed — RBF / mempool drop / LWS blind spot suspected; sender should \
                     re-broadcast or clawback)"
                );
            }
            if !cancelled.is_empty() {
                info!(
                    count = cancelled.len(),
                    "tip-lifecycle GC: cancelled stuck pending_confirmation rows"
                );
            }
        }
        Err(e) => warn!(error = %e, "tip-lifecycle GC: cancel_stuck_pending_confirmation failed"),
    }

    match state.db.log_stuck_claiming().await {
        Ok(stuck) => {
            for row in &stuck {
                warn!(
                    tip_id = %row.id,
                    asset = %row.asset,
                    tip_address = %row.tip_address.as_deref().unwrap_or("<none>"),
                    claimed_by_user_id = %row
                        .claimed_by_user_id
                        .map(|u| u.to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                    claimed_at = %row
                        .claimed_at
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_else(|| "<none>".to_string()),
                    "tip-lifecycle GC: stuck claiming row (confirm-sweep never landed) — \
                     operator-visible only; the sweep reconciler settles genuine on-chain sweeps"
                );
            }
            if !stuck.is_empty() {
                warn!(
                    count = stuck.len(),
                    "tip-lifecycle GC: observed stuck claiming rows — manual ops follow-up may be needed"
                );
            }
        }
        Err(e) => warn!(error = %e, "tip-lifecycle GC: log_stuck_claiming failed"),
    }
}
