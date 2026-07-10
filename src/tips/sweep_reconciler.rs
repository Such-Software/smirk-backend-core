//! Settle-on-sweep-confirmation reconciler for public social tips (the
//! "money-out" path). Ported (public subset) from the legacy
//! `smirk-backend/src/core/sweep_reconciler.rs`.
//!
//! Watches `claiming` tips and settles them to `claimed` ONLY after the sweep
//! transaction confirms on-chain to the per-asset depth. It is the sole new
//! writer of `status = 'claimed'` (via [`Database::confirm_sweep_onchain`] /
//! [`Database::clear_claimed_by_on_settle`]) and the sole writer of the reorg
//! revert ([`Database::revert_sweep_on_reorg`]).
//!
//! ## Source of truth = the ADDRESS, not the recorded `sweep_txid`
//!
//! Public tips carry the spend key in the URL fragment, so multiple claimers can
//! race; only one sweep wins on-chain (and a claimer may RBF-replace its own
//! sweep). So the source of truth is the tip ADDRESS's confirmed spend history:
//! we probe the address, collect confirmed spends, and pick the deterministic
//! winner ([`pick_winner`]).
//!
//! ## Confirmation thresholds (mirror the funding thresholds)
//!   BTC/LTC 1, WOW 4, XMR 10, GRIN 10.
//!
//! ## Grin (voucher asset) source of truth
//!   Grin has no address to scan: the "source of truth" is the voucher output
//!   COMMITMENT. Present in `get_outputs` = still unspent (not claimed). Absent =
//!   swept; `get_kernel(sweep_txid /* = kernel excess */)` dates the spend so the
//!   depth gate + reorg-revert reuse the same machinery. A reorg that un-spends
//!   the commitment makes it present again → not confirmed → revert.
//!
//! ## Money-safety invariants
//!   - A probe ERROR (Electrum/LWS unreachable, hostile amount) NEVER settles or
//!     reverts — it only stamps `last_confirmation_check` and retries.
//!   - Settle requires an affirmative confirmed spend at the required depth.
//!   - Reorg-revert requires an affirmative "the recorded sweep is GONE from
//!     confirmed history"; a probe error can never trigger it.
//!
//! ## Notifications
//!   The sender-DM side-effects are STUBBED to no-ops in this port (public tips
//!   deliver by share URL), but the exactly-once stamp writes
//!   (`stamp_sweep_confirmed_dm_sent` / `stamp_reorg_notified`) are preserved so
//!   re-enabling notifications later stays exactly-once.

use std::sync::Arc;

use tracing::{debug, info, instrument, warn};

use super::grin_commitment;
use crate::error::AppError;
use crate::infra::db::SocialTipRow;
use crate::infra::electrum::VerboseTransaction;
use crate::AppState;

/// Max rows processed per cycle (per pass).
const BATCH_SIZE: i64 = 50;

/// Advisory-lock key for the confirm/settle cycle. A fixed, arbitrary 64-bit
/// constant — single-instance guard so two replicas don't both probe + settle
/// the same batch. Distinct from the reorg key.
const SWEEP_CONFIRM_ADVISORY_LOCK_KEY: i64 = 0x53EE_D0C1;
/// Advisory-lock key for the reorg-check cycle (distinct from the confirm cycle
/// so the two passes run independently).
const SWEEP_REORG_ADVISORY_LOCK_KEY: i64 = 0x53EE_D0C2;

/// A confirmed spend of the tip address, distilled to what winner-determination
/// needs. Pure data, no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedSpend {
    /// On-chain identifier of the spend (BTC/LTC + XMR/WOW tx hash).
    pub txid: String,
    /// Block height the spend confirmed at.
    pub block_height: i64,
    /// Block hash at that height when trivially available (BTC/LTC don't fetch
    /// the merkle proof, so usually `None`).
    pub block_hash: Option<String>,
}

/// Per-asset sweep confirmation threshold (confirmations the winning spend needs
/// before we settle to `claimed`). Mirrors the funding-side thresholds. Unknown
/// assets default to the most conservative (10) so a misconfigured asset never
/// settles early.
pub(crate) fn sweep_confirm_threshold(asset: &str) -> u64 {
    match asset.to_lowercase().as_str() {
        "btc" | "ltc" => 1,
        "wow" => 4,
        "xmr" => 10,
        "grin" => 10,
        _ => 10,
    }
}

/// Pick the canonical winning spend: EARLIEST `block_height`, ties broken by the
/// lexicographically smallest `txid`. Deterministic + idempotent, so a re-probed
/// address always settles to the same winner. `None` for an empty slice.
pub(crate) fn pick_winner(spends: &[ConfirmedSpend]) -> Option<&ConfirmedSpend> {
    spends.iter().min_by(|a, b| {
        a.block_height
            .cmp(&b.block_height)
            .then_with(|| a.txid.cmp(&b.txid))
    })
}

/// Is this verbose BTC/LTC tx a SPEND of `address`? A single-use tip address is
/// a pure RECIPIENT in its funding tx and a pure SPENDER only in its sweep, so a
/// tx is a spend of the address iff the address received nothing in it
/// (`total_received_at(address) == 0`). Same `recv == 0` isolation the funding
/// verifier uses to avoid misreading a funding tx's change output as a send.
///
/// Returns `Err` when core's Result-returning accessor rejects a hostile /
/// non-finite amount — the caller bails the probe (never settles) on that.
pub(crate) fn is_verbose_tx_spend_of(
    tx: &VerboseTransaction,
    address: &str,
) -> Result<bool, AppError> {
    Ok(tx.total_received_at(address)? == 0)
}

// ============================================================================
// Advisory-lock single-instance guard
// ============================================================================

/// Acquire a session-scoped Postgres advisory lock on a PINNED connection. pg
/// advisory locks are connection(session)-scoped, so the lock MUST be acquired
/// and released on the SAME connection — releasing on a different pooled
/// connection leaks the lock. Returns the held connection on success (the caller
/// keeps it alive for the cycle, then passes it to `release_advisory_lock`), or
/// `None` if another holder has it (skip the cycle).
async fn acquire_advisory_lock(
    state: &AppState,
    key: i64,
) -> Result<Option<sqlx::pool::PoolConnection<sqlx::Postgres>>, AppError> {
    let mut conn = state.db.pool().acquire().await?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(key)
        .fetch_one(&mut *conn)
        .await?;
    if acquired {
        Ok(Some(conn))
    } else {
        Ok(None)
    }
}

/// Release the advisory lock on the SAME connection it was acquired on, then
/// drop the connection back to the pool. Best-effort — the lock auto-releases
/// when the connection closes.
async fn release_advisory_lock(
    mut conn: sqlx::pool::PoolConnection<sqlx::Postgres>,
    key: i64,
) {
    if let Err(e) = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(key)
        .execute(&mut *conn)
        .await
    {
        debug!(error = %e, key, "pg_advisory_unlock failed (lock auto-releases on conn close)");
    }
}

// ============================================================================
// Confirm cycle
// ============================================================================

/// One confirm/settle cycle: probe each awaiting tip's address, settle the
/// winner once it reaches the per-asset threshold. Guarded by a Postgres
/// advisory lock so only one instance processes a batch. Never returns an
/// error to the caller — a single tip's probe/settle failure is logged and
/// swallowed so it can't tank the batch (or the spawn loop).
pub async fn run_sweep_reconcile_cycle(state: Arc<AppState>) {
    if let Err(e) = run_confirm_cycle(&state).await {
        warn!(error = %e, "sweep confirm cycle failed");
    }
}

#[instrument(skip(state))]
async fn run_confirm_cycle(state: &AppState) -> Result<(), AppError> {
    let Some(lock_conn) = acquire_advisory_lock(state, SWEEP_CONFIRM_ADVISORY_LOCK_KEY).await? else {
        debug!("sweep confirm cycle: advisory lock held by another instance — skipping");
        return Ok(());
    };

    let result = confirm_cycle_inner(state).await;

    release_advisory_lock(lock_conn, SWEEP_CONFIRM_ADVISORY_LOCK_KEY).await;
    result
}

async fn confirm_cycle_inner(state: &AppState) -> Result<(), AppError> {
    let tips = state.db.get_tips_awaiting_sweep_confirmation(BATCH_SIZE).await?;
    if tips.is_empty() {
        debug!("no tips awaiting sweep confirmation");
        return Ok(());
    }
    info!(count = tips.len(), "reconciling tip sweeps");

    for tip in &tips {
        if let Err(e) = process_awaiting_tip(state, tip).await {
            // A single tip's probe/settle error must not tank the batch.
            warn!(tip_id = %tip.id, error = %e, "process_awaiting_tip failed");
        }
    }
    Ok(())
}

/// Process a single `claiming` tip: probe its address, pick the winner, require
/// the per-asset depth, settle, stamp the (stubbed) notify.
async fn process_awaiting_tip(state: &AppState, tip: &SocialTipRow) -> Result<(), AppError> {
    let asset = tip.asset.to_lowercase();

    // Probe the address for confirmed spends + the current chain tip.
    let (spends, tip_height) = match probe_confirmed_spends(state, tip).await {
        Ok(v) => v,
        Err(e) => {
            // Probe error (chain unreachable / disabled / hostile response):
            // NEVER settle. Stamp last_check so the rate-limit backs off, skip.
            warn!(tip_id = %tip.id, %asset, error = %e, "sweep probe failed — skipping (retry next cycle)");
            if let Err(e2) = state.db.touch_tip_last_check(tip.id).await {
                debug!(tip_id = %tip.id, error = %e2, "touch_tip_last_check failed after probe error");
            }
            return Ok(());
        }
    };

    let winner = match pick_winner(&spends) {
        Some(w) => w.clone(),
        None => {
            // No confirmed spend of the address yet — sweep not mined, or still
            // in mempool. Back off via last_check and retry.
            debug!(tip_id = %tip.id, %asset, "no confirmed sweep yet");
            if let Err(e) = state.db.touch_tip_last_check(tip.id).await {
                debug!(tip_id = %tip.id, error = %e, "touch_tip_last_check failed (no winner)");
            }
            return Ok(());
        }
    };

    // Threshold gate: confirmations = tip_height - winner_height + 1.
    let confirmations = tip_height
        .saturating_sub(winner.block_height)
        .saturating_add(1);
    let needed = sweep_confirm_threshold(&asset);
    if (confirmations as u64) < needed {
        debug!(tip_id = %tip.id, %asset, confirmations, needed, "sweep seen on-chain, waiting for depth");
        if let Err(e) = state.db.touch_tip_last_check(tip.id).await {
            debug!(tip_id = %tip.id, error = %e, "touch_tip_last_check failed (below threshold)");
        }
        return Ok(());
    }

    // Attribution (public-only): if the on-chain winner matches the recorded
    // sweep_txid, keep claimed_by (via confirm_sweep_onchain with claimed_by =
    // None). Otherwise the tip was swept by a URL holder who isn't the recorded
    // claimer (RBF / unknown sweeper / no recorded txid) — settle the funds-moved
    // fact but drop the now-unreliable attribution.
    let recorded = tip.sweep_txid.as_deref();
    let txid_matches = recorded == Some(winner.txid.as_str());
    let block_hash = winner.block_hash.as_deref();

    let settled = if txid_matches {
        state
            .db
            .confirm_sweep_onchain(tip.id, &winner.txid, winner.block_height as i32, block_hash, None)
            .await?
    } else {
        debug!(
            tip_id = %tip.id, %asset,
            recorded_sweep_txid = ?recorded, onchain_winner_txid = %winner.txid,
            "public tip on-chain winner differs from recorded sweep — clearing claimed_by"
        );
        state
            .db
            .clear_claimed_by_on_settle(tip.id, &winner.txid, winner.block_height as i32, block_hash)
            .await?
    };

    let settled = match settled {
        Some(row) => row,
        None => {
            // Another tick (or instance) already settled this row — side effects
            // belong to whoever won the UPDATE.
            debug!(tip_id = %tip.id, "sweep already settled by another tick — skipping side effects");
            return Ok(());
        }
    };

    info!(
        tip_id = %settled.id, %asset,
        winner_txid = %winner.txid, block_height = winner.block_height, confirmations,
        "tip sweep confirmed on-chain — settled to claimed"
    );

    // Notify side-effect is stubbed to a no-op in this port; keep the
    // exactly-once stamp so re-enabling it later stays exactly-once.
    send_sweep_confirmed_dm_if_needed(state, &settled).await;

    Ok(())
}

// ============================================================================
// Per-asset on-chain spend probe (source of truth = the ADDRESS)
// ============================================================================

/// Probe the tip address for confirmed spends and the current chain tip height.
/// Returns `(spends, tip_height)`. Any upstream error / disabled chain / missing
/// field is `Err` — the caller treats that as "skip this row, retry next cycle"
/// (never settle / revert on an error).
async fn probe_confirmed_spends(
    state: &AppState,
    tip: &SocialTipRow,
) -> Result<(Vec<ConfirmedSpend>, i64), AppError> {
    let asset = tip.asset.to_lowercase();
    match asset.as_str() {
        "btc" | "ltc" => probe_electrum_spends(state, tip, &asset).await,
        "xmr" | "wow" => probe_lws_spends(state, tip, &asset).await,
        "grin" => probe_grin_spends(state, tip).await,
        other => {
            // Only btc/ltc/xmr/wow/grin ever create a tip.
            warn!(tip_id = %tip.id, asset = %other, "sweep probe: unsupported asset");
            Err(AppError::ValidationError(format!(
                "sweep probe: unsupported asset {other}"
            )))
        }
    }
}

/// Grin (voucher) probe. The source of truth is the output COMMITMENT:
///   - PRESENT in `get_outputs` → still unspent (the claimer hasn't swept, or the
///     sweep isn't mined): no confirmed spend yet.
///   - ABSENT → the voucher left the UTXO set (swept). Date the spend with
///     `get_kernel(sweep_txid /* = kernel excess */)`: `Some(h)` yields a single
///     `ConfirmedSpend`; `None` (kernel not mined yet) yields no spend.
///
/// This flows through the unchanged `pick_winner` → depth-10 gate →
/// `confirm_sweep_onchain`. In the REORG cycle it is symmetric: a reorg that
/// un-spends the commitment makes `get_outputs` present again → no
/// `ConfirmedSpend` → the recorded txid vanishes from confirmed history → revert.
///
/// Money-safety: any node error is `Err` (the caller skips — never settles /
/// reverts). Absence WITHOUT a kernel height (no recorded excess, or the kernel
/// isn't mined) is treated as "no confirmed spend" — a settle needs the
/// affirmative kernel height, so a bogus excess can never fake a settlement; the
/// worst case is a stuck-claiming row (recoverable, surfaced by
/// `log_stuck_claiming`), not fund loss.
async fn probe_grin_spends(
    state: &AppState,
    tip: &SocialTipRow,
) -> Result<(Vec<ConfirmedSpend>, i64), AppError> {
    let grin = state
        .chains
        .grin
        .as_ref()
        .ok_or_else(|| AppError::NodeError("grin client disabled".into()))?;

    let commit = grin_commitment(tip)
        .ok_or_else(|| AppError::ValidationError("grin commitment missing for sweep probe".into()))?;

    let tip_height = grin.get_height().await? as i64;

    // Still in the UTXO set → not swept yet. No confirmed spend.
    let outputs = grin.get_outputs(std::slice::from_ref(&commit)).await?;
    if outputs.iter().any(|o| o.commit == commit) {
        return Ok((Vec::new(), tip_height));
    }

    // Absent → swept. We need the sweep kernel excess to date the spend.
    let Some(excess) = tip.sweep_txid.as_deref().filter(|s| !s.is_empty()) else {
        // No recorded excess: we can't affirmatively date the spend, so we do
        // NOT settle. (Stuck-claiming is recoverable; missettling is not.)
        debug!(tip_id = %tip.id, "grin voucher absent but no recorded sweep excess — no confirmed spend");
        return Ok((Vec::new(), tip_height));
    };

    match grin.get_kernel(excess).await? {
        Some(height) => Ok((
            vec![ConfirmedSpend {
                txid: excess.to_string(),
                block_height: height as i64,
                block_hash: None,
            }],
            tip_height,
        )),
        // Kernel not mined yet: absence of the commitment alone isn't a
        // depth-gateable spend, so treat as no confirmed spend (retry).
        None => {
            debug!(tip_id = %tip.id, "grin voucher absent, sweep kernel not yet mined — no confirmed spend");
            Ok((Vec::new(), tip_height))
        }
    }
}

/// BTC/LTC probe via Electrum. For each confirmed history entry (`height > 0`)
/// fetch the verbose tx and treat it as a SPEND iff the address received nothing
/// in it. `block_hash` stays `None` (no merkle fetch); reorg detection keys on
/// the txid vanishing from confirmed history, not the hash.
async fn probe_electrum_spends(
    state: &AppState,
    tip: &SocialTipRow,
    asset: &str,
) -> Result<(Vec<ConfirmedSpend>, i64), AppError> {
    let electrum = if asset == "btc" {
        state.chains.btc.as_ref()
    } else {
        state.chains.ltc.as_ref()
    }
    .ok_or_else(|| AppError::NodeError(format!("{asset} Electrum client disabled")))?;

    let address = tip
        .tip_address
        .as_deref()
        .ok_or_else(|| AppError::ValidationError("tip_address missing for Electrum probe".into()))?;

    let history = electrum.get_history(address).await?;
    // Chain height comes from ELECTRUM, not a local node (the backend runs none).
    let tip_height = electrum.get_tip_height().await?;

    let mut spends = Vec::new();
    for entry in history.iter().filter(|e| e.height > 0) {
        let tx = electrum.get_transaction_verbose(&entry.tx_hash).await?;
        if is_verbose_tx_spend_of(&tx, address)? {
            spends.push(ConfirmedSpend {
                txid: entry.tx_hash.clone(),
                block_height: entry.height,
                block_hash: None,
            });
        }
    }
    Ok((spends, tip_height))
}

/// XMR/WOW probe via LWS `get_address_txs`. A SPEND is a confirmed (`height > 0`,
/// not mempool) tx with `total_sent > 0 && total_received == 0` (the single-use
/// tip address only ever spends in its sweep). `tip_height` comes from the LWS
/// response's `blockchain_height`, falling back to the node height if it's 0.
async fn probe_lws_spends(
    state: &AppState,
    tip: &SocialTipRow,
    asset: &str,
) -> Result<(Vec<ConfirmedSpend>, i64), AppError> {
    let lws = if asset == "xmr" {
        state.chains.xmr.as_ref()
    } else {
        state.chains.wow.as_ref()
    }
    .ok_or_else(|| AppError::NodeError(format!("{asset} LWS client disabled")))?;

    let address = tip
        .tip_address
        .as_deref()
        .ok_or_else(|| AppError::ValidationError("tip_address missing for LWS probe".into()))?;
    let view_key = tip
        .tip_view_key
        .as_deref()
        .ok_or_else(|| AppError::ValidationError("tip_view_key missing for LWS probe".into()))?;

    let txs = lws.get_address_txs(address, view_key).await?;

    let tip_height = if txs.blockchain_height > 0 {
        txs.blockchain_height as i64
    } else {
        lws.get_blockchain_height().await? as i64
    };

    let spends: Vec<ConfirmedSpend> = txs
        .transactions
        .iter()
        .filter(|t| !t.mempool && t.height > 0 && t.total_sent > 0 && t.total_received == 0)
        .map(|t| ConfirmedSpend {
            txid: t.hash.clone(),
            block_height: t.height as i64,
            block_hash: None,
        })
        .collect();

    Ok((spends, tip_height))
}

// ============================================================================
// Reorg cycle
// ============================================================================

/// One reorg-check cycle: re-probe settled tips; if a recorded sweep is no longer
/// a confirmed spend of the address, revert to `claiming`. Guarded by its own
/// advisory lock. Runs on a slower cadence than the confirm cycle (the reorg
/// path is the lowest-frequency one and reverting is recoverable).
pub async fn run_sweep_reorg_cycle(state: Arc<AppState>) {
    if let Err(e) = run_reorg_cycle(&state).await {
        warn!(error = %e, "sweep reorg cycle failed");
    }
}

#[instrument(skip(state))]
async fn run_reorg_cycle(state: &AppState) -> Result<(), AppError> {
    let Some(lock_conn) = acquire_advisory_lock(state, SWEEP_REORG_ADVISORY_LOCK_KEY).await? else {
        debug!("sweep reorg cycle: advisory lock held by another instance — skipping");
        return Ok(());
    };

    let result = reorg_cycle_inner(state).await;

    release_advisory_lock(lock_conn, SWEEP_REORG_ADVISORY_LOCK_KEY).await;
    result
}

async fn reorg_cycle_inner(state: &AppState) -> Result<(), AppError> {
    let tips = state.db.get_settled_tips_for_reorg_check(BATCH_SIZE).await?;
    if tips.is_empty() {
        debug!("no settled tips to reorg-check");
        return Ok(());
    }
    debug!(count = tips.len(), "reorg-checking settled tip sweeps");

    for tip in &tips {
        if let Err(e) = process_settled_tip(state, tip).await {
            warn!(tip_id = %tip.id, error = %e, "process_settled_tip failed");
        }
    }
    Ok(())
}

/// Re-probe a settled tip. If its recorded `sweep_txid` is still a confirmed
/// spend of the address, do nothing (stamp). If it VANISHED (orphaned by a
/// reorg), revert to `claiming`. A probe ERROR never reverts.
async fn process_settled_tip(state: &AppState, tip: &SocialTipRow) -> Result<(), AppError> {
    let recorded_txid = match tip.sweep_txid.as_deref() {
        Some(t) => t,
        None => {
            // Settled with no recorded txid — nothing to reorg-check against.
            if let Err(e) = state.db.touch_tip_last_check(tip.id).await {
                debug!(tip_id = %tip.id, error = %e, "touch_tip_last_check failed (no recorded txid)");
            }
            return Ok(());
        }
    };

    let (spends, _tip_height) = match probe_confirmed_spends(state, tip).await {
        Ok(v) => v,
        Err(e) => {
            // NEVER revert on a probe error. Back off.
            warn!(tip_id = %tip.id, error = %e, "reorg re-probe failed — skipping (will retry)");
            if let Err(e2) = state.db.touch_tip_last_check(tip.id).await {
                debug!(tip_id = %tip.id, error = %e2, "touch_tip_last_check failed after reorg probe error");
            }
            return Ok(());
        }
    };

    // Still confirmed iff the recorded txid appears among the confirmed spends.
    // Absence = orphaned by a reorg.
    let still_confirmed = spends.iter().any(|s| s.txid == recorded_txid);
    if still_confirmed {
        if let Err(e) = state.db.touch_tip_last_check(tip.id).await {
            debug!(tip_id = %tip.id, error = %e, "touch_tip_last_check failed (still confirmed)");
        }
        return Ok(());
    }

    warn!(
        tip_id = %tip.id, asset = %tip.asset, recorded_sweep_txid = %recorded_txid,
        "recorded sweep no longer confirmed — reverting claim (chain reorg)"
    );

    match state.db.revert_sweep_on_reorg(tip.id).await? {
        Some(reverted) => send_reorg_dm_if_needed(state, &reverted).await,
        None => debug!(tip_id = %tip.id, "reorg revert no-op (already reverted) — skipping notify"),
    }
    Ok(())
}

// ============================================================================
// Notify side-effects (STUBBED to no-ops; exactly-once stamps preserved)
// ============================================================================

/// Sender "your tip was claimed" notify. STUBBED to a no-op in this port (public
/// tips deliver by share URL), but we still stamp `sweep_confirmed_dm_sent_at`
/// (guarded `IS NULL`) so re-enabling notifications later stays exactly-once.
async fn send_sweep_confirmed_dm_if_needed(state: &AppState, tip: &SocialTipRow) {
    if tip.sweep_confirmed_dm_sent_at.is_some() {
        return;
    }
    // TODO(notify): send the sender DM here when notifications are re-enabled.
    if let Err(e) = state.db.stamp_sweep_confirmed_dm_sent(tip.id).await {
        debug!(tip_id = %tip.id, error = %e, "stamp_sweep_confirmed_dm_sent failed");
    }
}

/// Sender "claim reversed by reorg" notify. STUBBED to a no-op; stamps
/// `reorg_notified_at` (guarded `IS NULL`) to keep exactly-once semantics.
async fn send_reorg_dm_if_needed(state: &AppState, tip: &SocialTipRow) {
    if tip.reorg_notified_at.is_some() {
        return;
    }
    // TODO(notify): send the sender reorg DM here when notifications are re-enabled.
    if let Err(e) = state.db.stamp_reorg_notified(tip.id).await {
        debug!(tip_id = %tip.id, error = %e, "stamp_reorg_notified failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::electrum::{ScriptPubKeyInfo, VerboseTransaction, VerboseVin, VerboseVout};

    fn spend(txid: &str, height: i64) -> ConfirmedSpend {
        ConfirmedSpend {
            txid: txid.to_string(),
            block_height: height,
            block_hash: None,
        }
    }

    // ---- pick_winner -------------------------------------------------

    #[test]
    fn pick_winner_empty_is_none() {
        let spends: Vec<ConfirmedSpend> = vec![];
        assert!(pick_winner(&spends).is_none());
    }

    #[test]
    fn pick_winner_earliest_height_wins() {
        let spends = vec![spend("zzz", 110), spend("aaa", 100), spend("mmm", 105)];
        let w = pick_winner(&spends).unwrap();
        assert_eq!(w.txid, "aaa");
        assert_eq!(w.block_height, 100);
    }

    #[test]
    fn pick_winner_same_height_smallest_txid_tiebreak() {
        let spends = vec![spend("ffff", 100), spend("aaaa", 100), spend("cccc", 100)];
        assert_eq!(pick_winner(&spends).unwrap().txid, "aaaa");
    }

    #[test]
    fn pick_winner_is_deterministic_across_input_order() {
        let a = vec![spend("bbb", 100), spend("aaa", 100)];
        let b = vec![spend("aaa", 100), spend("bbb", 100)];
        assert_eq!(pick_winner(&a).unwrap().txid, pick_winner(&b).unwrap().txid);
        assert_eq!(pick_winner(&a).unwrap().txid, "aaa");
    }

    #[test]
    fn pick_winner_height_beats_txid() {
        let spends = vec![spend("aaa", 200), spend("zzz", 100)];
        assert_eq!(pick_winner(&spends).unwrap().txid, "zzz");
    }

    // ---- sweep_confirm_threshold -------------------------------------

    #[test]
    fn threshold_btc_ltc_is_one() {
        assert_eq!(sweep_confirm_threshold("btc"), 1);
        assert_eq!(sweep_confirm_threshold("ltc"), 1);
        assert_eq!(sweep_confirm_threshold("BTC"), 1);
    }

    #[test]
    fn threshold_wow_is_four() {
        assert_eq!(sweep_confirm_threshold("wow"), 4);
        assert_eq!(sweep_confirm_threshold("WOW"), 4);
    }

    #[test]
    fn threshold_xmr_is_ten() {
        assert_eq!(sweep_confirm_threshold("xmr"), 10);
    }

    #[test]
    fn threshold_grin_is_ten() {
        assert_eq!(sweep_confirm_threshold("grin"), 10);
        assert_eq!(sweep_confirm_threshold("GRIN"), 10);
    }

    #[test]
    fn threshold_unknown_defaults_conservative() {
        assert_eq!(sweep_confirm_threshold("doge"), 10);
    }

    // ---- is_verbose_tx_spend_of --------------------------------------

    fn spk(addr: &str) -> ScriptPubKeyInfo {
        ScriptPubKeyInfo {
            address: Some(addr.to_string()),
            addresses: None,
        }
    }

    #[test]
    fn funding_tx_is_not_a_spend_of_tip_address() {
        // Funding tx: tip address RECEIVES; recv != 0 → not a spend.
        let tx = VerboseTransaction {
            txid: "fund".into(),
            vin: vec![VerboseVin { txid: Some("alice_prev".into()), vout: Some(0), prevout: None }],
            vout: vec![
                VerboseVout { value: 0.001, n: 0, script_pub_key: spk("ltc1qtip") },
                VerboseVout { value: 0.296, n: 1, script_pub_key: spk("ltc1qalice") },
            ],
        };
        assert!(!is_verbose_tx_spend_of(&tx, "ltc1qtip").unwrap());
    }

    #[test]
    fn sweep_tx_is_a_spend_of_tip_address() {
        // Sweep: tip address absent from outputs (recv == 0) → spend.
        let tx = VerboseTransaction {
            txid: "sweep".into(),
            vin: vec![VerboseVin { txid: Some("fund".into()), vout: Some(0), prevout: None }],
            vout: vec![VerboseVout { value: 0.00099, n: 0, script_pub_key: spk("ltc1qbob") }],
        };
        assert!(is_verbose_tx_spend_of(&tx, "ltc1qtip").unwrap());
    }

    #[test]
    fn incoming_payment_with_change_is_not_a_spend() {
        // Tip address receives with the payer's change to a third party —
        // recv != 0 → not a spend (guards the funding-with-change case).
        let tx = VerboseTransaction {
            txid: "pay".into(),
            vin: vec![VerboseVin { txid: Some("payer_prev".into()), vout: Some(0), prevout: None }],
            vout: vec![
                VerboseVout { value: 0.5, n: 0, script_pub_key: spk("ltc1qtip") },
                VerboseVout { value: 0.3, n: 1, script_pub_key: spk("ltc1qpayer") },
            ],
        };
        assert!(!is_verbose_tx_spend_of(&tx, "ltc1qtip").unwrap());
    }
}
