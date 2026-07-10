//! Funding confirmation + amount verification for public social tips.
//!
//! Ported (public subset) from the legacy `core/tip_confirmation.rs`. Grin and
//! all DM/announcement side-effects are dropped: public tips deliver by share
//! URL, so the "fire the recipient a notification" branches become no-ops here.
//!
//! Confirmation thresholds (see [`crate::models::tip_status::confirmations_for_asset`]):
//! XMR 10, WOW 4, BTC/LTC 0. BTC/LTC skip the confirmation-count pass entirely
//! and go straight to amount verification.

use std::sync::Arc;

use tracing::{debug, info, instrument, warn};

use crate::error::AppError;
use crate::infra::db::SocialTipRow;
use crate::infra::lws::AddressTxsResponse;
use crate::AppState;

/// CryptoNote assets that require an on-chain confirmation count before the
/// amount pass. BTC/LTC are deliberately absent (`confirmations_required = 0`).
const CONFIRMATION_ASSETS: [&str; 2] = ["xmr", "wow"];

/// Run one full funding pass: confirmation counting for XMR/WOW, then the
/// amount-verification pass across all `pending_confirmation` tips. Never
/// returns an error — every fallible step is logged and swallowed so a single
/// bad tip or a chain outage can't abort the cycle (or, via the spawn loop,
/// stall every other tip).
pub async fn run_tip_confirmation_cycle(state: Arc<AppState>) {
    for asset in CONFIRMATION_ASSETS {
        if let Err(e) = check_asset_confirmations(&state, asset).await {
            warn!(error = %e, asset, "tip confirmation-count pass failed");
        }
    }

    if let Err(e) = process_pending_verifications(&state).await {
        warn!(error = %e, "tip funding-amount verification pass failed");
    }
}

/// Update the confirmation counter for every funded tip of `asset` awaiting
/// confirmations. Skips silently when the chain is disabled on this instance.
///
/// Money-safety: `update_tip_confirmations` only writes the counter + timestamps
/// (never status), and a daemon error leaves the row entirely untouched (retried
/// next poll) — the count can never regress a tip out of a settled state.
#[instrument(skip(state))]
async fn check_asset_confirmations(state: &AppState, asset: &str) -> Result<(), AppError> {
    // Poll-only CryptoNote assets reach the daemon via the LWS client. If the
    // chain is disabled here, there's nothing to poll.
    let lws = match asset {
        "xmr" => state.chains.xmr.as_ref(),
        "wow" => state.chains.wow.as_ref(),
        _ => None,
    };
    let Some(lws) = lws else {
        return Ok(());
    };

    let tips = state.db.get_tips_pending_confirmation(asset).await?;
    if tips.is_empty() {
        debug!(asset, "no tips awaiting confirmation");
        return Ok(());
    }
    info!(asset, count = tips.len(), "checking tip funding confirmations");

    for tip in &tips {
        let funding_txid = match tip.funding_txid.as_deref() {
            Some(txid) if !txid.is_empty() => txid,
            _ => continue,
        };
        match lws.get_transaction_confirmations(funding_txid).await {
            Ok(Some(confs)) => {
                let confs_i32 = confs.min(i32::MAX as u64) as i32;
                if let Err(e) = state.db.update_tip_confirmations(tip.id, confs_i32).await {
                    warn!(tip_id = %tip.id, error = %e, "failed to update tip confirmations");
                }
            }
            Ok(None) => {
                // Tx not found / still in the mempool without a height. Stamp the
                // check timestamp (counter stays 0) so we don't re-poll it hot.
                if let Err(e) = state.db.update_tip_confirmations(tip.id, 0).await {
                    warn!(tip_id = %tip.id, error = %e, "failed to stamp tip check timestamp");
                }
            }
            Err(e) => {
                // Daemon/LWS error: leave the row untouched for the next poll.
                // NEVER mutate status here.
                warn!(tip_id = %tip.id, error = %e, "failed to fetch confirmation count");
            }
        }
    }
    Ok(())
}

/// Result of checking whether the on-chain receipt at a tip's address covers the
/// sender-declared `amount`. The verifier acts on this; only `Verified` /
/// `Short` mutate status.
#[derive(Debug, PartialEq, Eq)]
pub enum FundingVerification {
    /// Confirmed net receipt covers `amount`. Carries the observed total
    /// (atomic units) so the row can record what was actually received.
    Verified { observed: u64 },
    /// Confirmed net receipt is positive but strictly less than `amount`
    /// (sender underfunded). Flips the row to `funding_mismatch`.
    Short { observed: u64 },
    /// Confirmed net receipt is zero (never funded, or only mempool entries so
    /// far). Row stays in `pending_confirmation` for the next poll.
    Unfunded,
    /// The address HAS seen funds (`total_sent > 0`) but currently holds less
    /// than `amount` — funded then (partially) drained before the verifier ran
    /// (clawback, or a URL holder claimed first). We do NOT announce (funds are
    /// gone) and do NOT auto-flip `funding_mismatch` (the sender may have
    /// legitimately recovered). Distinguished from `Unfunded` for operator
    /// visibility.
    Drained { net: u64, total_sent: u64 },
    /// LWS / Electrum / upstream errored, or a required field was missing. Row
    /// stays in `pending_confirmation` for the next poll. This variant MUST NOT
    /// flip a row to `funding_mismatch` — that would mass-mismatch every pending
    /// tip during an outage.
    LwsError,
}

/// Classify an LWS `get_address_txs` response against `expected` (atomic units).
///
/// Sums `total_received` and `total_sent` SEPARATELY over confirmed
/// (non-mempool, `height > 0`) txs, then signed-subtracts once at the end
/// (`net = received.saturating_sub(sent)`). This separate-then-subtract order is
/// load-bearing: the old per-tx `saturating_sub` counted a fully-swept address
/// (funding tx received=N, sweep tx sent=N) as `Verified` for N, phantom-DMing a
/// recipient about funds the address no longer held. Pure function (no I/O) so
/// it is unit-testable without an LWS client.
pub(crate) fn classify_funding_amount(
    txs: &AddressTxsResponse,
    expected: i64,
) -> FundingVerification {
    let total_received: u64 = txs
        .transactions
        .iter()
        .filter(|tx| !tx.mempool && tx.height > 0)
        .map(|tx| tx.total_received)
        .sum();
    let total_sent: u64 = txs
        .transactions
        .iter()
        .filter(|tx| !tx.mempool && tx.height > 0)
        .map(|tx| tx.total_sent)
        .sum();
    let net = total_received.saturating_sub(total_sent);

    // `expected` is always non-negative in practice (create-tip validates
    // amount > 0); saturate a defensive negative to 0.
    let expected_u64: u64 = if expected < 0 { 0 } else { expected as u64 };

    // Drained before Unfunded/Short: the address SAW funds but is now short.
    if net < expected_u64 && total_sent > 0 {
        return FundingVerification::Drained { net, total_sent };
    }
    if net == 0 {
        return FundingVerification::Unfunded;
    }
    if net >= expected_u64 {
        FundingVerification::Verified { observed: net }
    } else {
        FundingVerification::Short { observed: net }
    }
}

/// Verify that a tip's on-chain funding covers `amount`.
///
/// XMR/WOW: `get_address_txs(tip_address, tip_view_key)` → `classify_funding_amount`.
/// BTC/LTC: the address history, summing received-at vs sent-from over CONFIRMED
/// (`height > 0`) txs via the verbose-tx accessors.
///
/// This never returns an error: EVERY failure path (disabled chain, missing
/// address/view-key, upstream error, a hostile-amount rejection from the
/// verbose-tx converters) maps to [`FundingVerification::LwsError`], so the
/// caller only ever stamps `last_confirmation_check` and retries — status is
/// never mutated on a failure.
async fn verify_funding_amount(state: &AppState, tip: &SocialTipRow) -> FundingVerification {
    let asset = tip.asset.to_lowercase();
    match asset.as_str() {
        "xmr" | "wow" => {
            let lws = if asset == "xmr" {
                state.chains.xmr.as_ref()
            } else {
                state.chains.wow.as_ref()
            };
            let Some(lws) = lws else {
                warn!(tip_id = %tip.id, %asset, "verify: LWS client disabled — staying in pending_confirmation");
                return FundingVerification::LwsError;
            };
            let (Some(address), Some(view_key)) =
                (tip.tip_address.as_deref(), tip.tip_view_key.as_deref())
            else {
                warn!(tip_id = %tip.id, %asset, "verify: tip_address/tip_view_key missing — treating as LwsError");
                return FundingVerification::LwsError;
            };
            match lws.get_address_txs(address, view_key).await {
                Ok(txs) => classify_funding_amount(&txs, tip.amount),
                Err(e) => {
                    warn!(tip_id = %tip.id, %asset, error = %e, "verify: LWS get_address_txs failed — staying in pending_confirmation");
                    FundingVerification::LwsError
                }
            }
        }
        "btc" | "ltc" => {
            let electrum = if asset == "btc" {
                state.chains.btc.as_ref()
            } else {
                state.chains.ltc.as_ref()
            };
            let Some(electrum) = electrum else {
                warn!(tip_id = %tip.id, %asset, "verify: Electrum client disabled — staying in pending_confirmation");
                return FundingVerification::LwsError;
            };
            let Some(address) = tip.tip_address.as_deref() else {
                warn!(tip_id = %tip.id, %asset, "verify: tip_address missing — treating as LwsError");
                return FundingVerification::LwsError;
            };
            let history = match electrum.get_history(address).await {
                Ok(h) => h,
                Err(e) => {
                    warn!(tip_id = %tip.id, %asset, error = %e, "verify: Electrum get_history failed — staying in pending_confirmation");
                    return FundingVerification::LwsError;
                }
            };
            // Sum received-at-address and sent-from-address over CONFIRMED
            // (height > 0) history entries. A single-use tip address is a pure
            // RECIPIENT in its funding tx and a pure SPENDER in its sweep tx;
            // gating the sent-sum on `recv == 0` isolates the genuine sweep and
            // avoids public-ElectrumX's prevout-less "sent" heuristic misreading
            // funding change as a send (a false Drained that would block claims).
            let mut total_received: u64 = 0;
            let mut total_sent: u64 = 0;
            let mut confirmed_seen = 0usize;
            for entry in history.iter().filter(|e| e.height > 0) {
                confirmed_seen += 1;
                let tx = match electrum.get_transaction_verbose(&entry.tx_hash).await {
                    Ok(tx) => tx,
                    Err(e) => {
                        warn!(tip_id = %tip.id, tx_hash = %entry.tx_hash, error = %e, "verify: get_transaction_verbose failed — bailing this tick");
                        return FundingVerification::LwsError;
                    }
                };
                // Core's accessors are Result-returning (they reject hostile /
                // non-finite amounts). Any rejection bails the tick as an
                // LwsError-tier failure rather than mutating status.
                let recv = match tx.total_received_at(address) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(tip_id = %tip.id, tx_hash = %entry.tx_hash, error = %e, "verify: total_received_at rejected an amount — bailing this tick");
                        return FundingVerification::LwsError;
                    }
                };
                total_received = total_received.saturating_add(recv);
                if recv == 0 {
                    match tx.total_sent_from(address) {
                        Ok(Some(sent)) => total_sent = total_sent.saturating_add(sent),
                        Ok(None) => {}
                        Err(e) => {
                            warn!(tip_id = %tip.id, tx_hash = %entry.tx_hash, error = %e, "verify: total_sent_from rejected an amount — bailing this tick");
                            return FundingVerification::LwsError;
                        }
                    }
                }
            }
            if confirmed_seen == 0 {
                // History empty or all-mempool: no confirmed receipt yet.
                return FundingVerification::Unfunded;
            }
            let net = total_received.saturating_sub(total_sent);
            let expected_u64 = if tip.amount < 0 { 0 } else { tip.amount as u64 };
            if net < expected_u64 && total_sent > 0 {
                FundingVerification::Drained { net, total_sent }
            } else if net == 0 {
                FundingVerification::Unfunded
            } else if net >= expected_u64 {
                FundingVerification::Verified { observed: net }
            } else {
                FundingVerification::Short { observed: net }
            }
        }
        other => {
            // Only btc/ltc/xmr/wow can ever create a tip, so this is unreachable
            // in practice. Do NOT auto-verify an unknown asset (that would be a
            // money-safety hole) — treat it as an error so the row stays put.
            warn!(tip_id = %tip.id, asset = other, "verify: unsupported asset — staying in pending_confirmation");
            FundingVerification::LwsError
        }
    }
}

/// Amount-verify every `pending_confirmation` tip that has reached its
/// confirmation threshold.
///
/// Per-tip three-way branch:
///   - `Verified` → `mark_tip_funding_verified` (→ `pending`, claimable).
///   - `Short`    → `mark_tip_funding_mismatch` (→ `funding_mismatch`).
///   - `Unfunded` / `Drained` / `LwsError` → NO status mutation; only
///     `touch_tip_last_check` (rate-limit stamp), retried next poll.
///
/// The DB guards (`status = 'pending_confirmation' AND funding_amount_verified =
/// FALSE`) make the `mark_*` transitions idempotent, so a re-driven verifier
/// never double-processes a row.
#[instrument(skip(state))]
async fn process_pending_verifications(state: &AppState) -> Result<(), AppError> {
    let tips = state.db.get_tips_awaiting_amount_verification().await?;
    if tips.is_empty() {
        debug!("no tips awaiting funding-amount verification");
        return Ok(());
    }
    info!(count = tips.len(), "verifying tip funding amounts");

    for tip in &tips {
        match verify_funding_amount(state, tip).await {
            FundingVerification::Verified { observed } => {
                let observed_i64 = i64::try_from(observed).unwrap_or(i64::MAX);
                match state.db.mark_tip_funding_verified(tip.id, observed_i64).await {
                    Ok(Some(_updated)) => {
                        info!(
                            tip_id = %tip.id, asset = %tip.asset,
                            declared = tip.amount, observed = observed_i64,
                            "tip funding amount verified — now claimable"
                        );
                        // Public tips deliver by share URL: no recipient DM /
                        // announcement side-effect to fire here.
                    }
                    Ok(None) => debug!(tip_id = %tip.id, "verified: row no longer pending_confirmation — skipping"),
                    Err(e) => warn!(tip_id = %tip.id, error = %e, "mark_tip_funding_verified DB error"),
                }
            }
            FundingVerification::Short { observed } => {
                let observed_i64 = i64::try_from(observed).unwrap_or(i64::MAX);
                match state.db.mark_tip_funding_mismatch(tip.id, observed_i64).await {
                    Ok(Some(_updated)) => warn!(
                        tip_id = %tip.id, asset = %tip.asset,
                        declared = tip.amount, observed = observed_i64,
                        "tip funding mismatch — sender funded LESS than declared"
                    ),
                    Ok(None) => debug!(tip_id = %tip.id, "mismatch: row no longer pending_confirmation — skipping"),
                    Err(e) => warn!(tip_id = %tip.id, error = %e, "mark_tip_funding_mismatch DB error"),
                }
            }
            FundingVerification::Unfunded => {
                debug!(tip_id = %tip.id, asset = %tip.asset, "verify: Unfunded — staying in pending_confirmation");
                if let Err(e) = state.db.touch_tip_last_check(tip.id).await {
                    debug!(tip_id = %tip.id, error = %e, "touch_tip_last_check failed (Unfunded)");
                }
            }
            FundingVerification::Drained { net, total_sent } => {
                warn!(
                    tip_id = %tip.id, asset = %tip.asset,
                    declared = tip.amount, net_received = net, total_sent,
                    "verify: Drained — funded address has been (partially) emptied; not announcing"
                );
                if let Err(e) = state.db.touch_tip_last_check(tip.id).await {
                    debug!(tip_id = %tip.id, error = %e, "touch_tip_last_check failed (Drained)");
                }
            }
            FundingVerification::LwsError => {
                debug!(tip_id = %tip.id, asset = %tip.asset, "verify: LwsError — staying in pending_confirmation");
                if let Err(e) = state.db.touch_tip_last_check(tip.id).await {
                    debug!(tip_id = %tip.id, error = %e, "touch_tip_last_check failed (LwsError)");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Unit tests for the pure `classify_funding_amount` branch logic. The async
    //! DB-backed paths are covered by `tests/tips.rs` (gated on TEST_DATABASE_URL).
    use super::*;
    use crate::infra::lws::{AddressTx, AddressTxsResponse};

    fn tx(received: u64, sent: u64, height: u64, mempool: bool) -> AddressTx {
        AddressTx {
            hash: format!("h_{received}_{sent}_{height}"),
            height,
            timestamp: String::new(),
            total_received: received,
            total_sent: sent,
            mempool,
            unlock_time: 0,
            payment_id: None,
            spent_outputs: Vec::new(),
        }
    }

    fn resp(transactions: Vec<AddressTx>) -> AddressTxsResponse {
        AddressTxsResponse {
            transactions,
            total_received: 0,
            scanned_height: 0,
            blockchain_height: 0,
        }
    }

    #[test]
    fn exact_and_overpay_are_verified() {
        assert_eq!(
            classify_funding_amount(&resp(vec![tx(1_000, 0, 100, false)]), 1_000),
            FundingVerification::Verified { observed: 1_000 }
        );
        assert_eq!(
            classify_funding_amount(&resp(vec![tx(2_000, 0, 100, false)]), 1_000),
            FundingVerification::Verified { observed: 2_000 }
        );
    }

    #[test]
    fn short_receipt_is_short() {
        assert_eq!(
            classify_funding_amount(&resp(vec![tx(10, 0, 100, false)]), 1_000),
            FundingVerification::Short { observed: 10 }
        );
    }

    #[test]
    fn mempool_and_zero_height_do_not_count() {
        // Only-mempool → Unfunded.
        assert_eq!(
            classify_funding_amount(&resp(vec![tx(5_000, 0, 0, true)]), 1_000),
            FundingVerification::Unfunded
        );
        // height == 0 but mempool == false is excluded defensively.
        assert_eq!(
            classify_funding_amount(&resp(vec![tx(5_000, 0, 0, false)]), 1_000),
            FundingVerification::Unfunded
        );
        // A confirmed short tx plus a huge mempool tx stays Short (mempool excluded).
        assert_eq!(
            classify_funding_amount(
                &resp(vec![tx(100, 0, 100, false), tx(9_999_999, 0, 0, true)]),
                1_000
            ),
            FundingVerification::Short { observed: 100 }
        );
    }

    #[test]
    fn separate_then_subtract_marks_swept_as_drained() {
        // REGRESSION: funding (received=N) + sweep (sent=N) must net to 0 and be
        // Drained, not Verified — the separate-then-subtract guarantee.
        let r = classify_funding_amount(
            &resp(vec![tx(1_000, 0, 100, false), tx(0, 1_000, 110, false)]),
            1_000,
        );
        assert_eq!(r, FundingVerification::Drained { net: 0, total_sent: 1_000 });
    }

    #[test]
    fn no_txs_is_unfunded_not_drained() {
        assert_eq!(
            classify_funding_amount(&resp(vec![]), 1_000),
            FundingVerification::Unfunded
        );
    }

    #[test]
    fn lws_error_distinct_from_unfunded() {
        assert_ne!(FundingVerification::LwsError, FundingVerification::Unfunded);
    }
}
