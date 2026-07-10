//! Social-tips (public) DB access.
//!
//! The `social_tips` row plus its query methods on [`Database`]. PUBLIC tips
//! only — no targeted/recipient columns. Every status transition is a single
//! guarded `UPDATE ... WHERE status IN (...) ... RETURNING`, so concurrent
//! claims / sweeps / clawbacks race safely on the DB (the guards are the
//! money-safety surface; see each method).

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use tracing::instrument;
use uuid::Uuid;

use crate::error::AppError;
use crate::models::tip_status::TipStatus;

use super::Database;

/// Every column of `social_tips`, in declaration order. Used verbatim in
/// `SELECT` / `RETURNING` so [`SocialTipRow`]'s `FromRow` mapping can never
/// drift from a `SELECT *`.
pub(crate) const TIP_COLS: &str = "\
    id, sender_user_id, asset, amount, is_public, claim_key_hash, encrypted_key, \
    tip_address, funding_txid, status, funding_confirmations, funding_confirmed_at, \
    last_confirmation_check, confirmations_required, funding_amount_verified, \
    funding_amount_observed, funding_amount_verified_at, claimed_at, claimed_by_user_id, \
    clawed_back_at, sweep_txid, sweep_confirmed_at, sweep_block_height, sweep_block_hash, \
    sweep_confirmed_dm_sent_at, reorg_notified_at, tip_view_key, lws_registered_at, \
    lws_deactivated_at, created_at, updated_at";

/// A persisted public social tip. Field names/order match [`TIP_COLS`] (sqlx
/// `FromRow` maps by name).
#[derive(Debug, Clone, FromRow)]
pub struct SocialTipRow {
    pub id: Uuid,
    pub sender_user_id: Uuid,
    pub asset: String,
    pub amount: i64,
    pub is_public: bool,
    pub claim_key_hash: Option<String>,
    pub encrypted_key: Option<Vec<u8>>,
    pub tip_address: Option<String>,
    pub funding_txid: Option<String>,
    pub status: String,
    pub funding_confirmations: i32,
    pub funding_confirmed_at: Option<DateTime<Utc>>,
    pub last_confirmation_check: Option<DateTime<Utc>>,
    pub confirmations_required: i32,
    pub funding_amount_verified: bool,
    pub funding_amount_observed: Option<i64>,
    pub funding_amount_verified_at: Option<DateTime<Utc>>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub claimed_by_user_id: Option<Uuid>,
    pub clawed_back_at: Option<DateTime<Utc>>,
    pub sweep_txid: Option<String>,
    pub sweep_confirmed_at: Option<DateTime<Utc>>,
    pub sweep_block_height: Option<i32>,
    pub sweep_block_hash: Option<String>,
    pub sweep_confirmed_dm_sent_at: Option<DateTime<Utc>>,
    pub reorg_notified_at: Option<DateTime<Utc>>,
    pub tip_view_key: Option<String>,
    pub lws_registered_at: Option<DateTime<Utc>>,
    pub lws_deactivated_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Values for a fresh public tip. `status` is set by the caller
/// (`draft` for the two-phase flow, `pending_confirmation` when funding is
/// attached at create time).
pub struct NewSocialTip<'a> {
    pub sender_user_id: Uuid,
    pub asset: &'a str,
    pub amount: i64,
    pub claim_key_hash: Option<&'a str>,
    pub encrypted_key: Option<&'a [u8]>,
    pub tip_address: Option<&'a str>,
    pub funding_txid: Option<&'a str>,
    pub tip_view_key: Option<&'a str>,
    pub confirmations_required: i32,
}

impl Database {
    /// Fetch a tip by id, or `None`. The UUID is the public bearer token behind
    /// a share URL, so this read is intentionally not owner-scoped.
    #[instrument(skip(self))]
    pub async fn get_social_tip(&self, id: Uuid) -> Result<Option<SocialTipRow>, AppError> {
        let row = sqlx::query_as::<_, SocialTipRow>(&format!(
            "SELECT {TIP_COLS} FROM social_tips WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Insert a public tip in `status`. Always `is_public = TRUE`.
    #[instrument(skip(self, new))]
    async fn insert_social_tip(
        &self,
        new: NewSocialTip<'_>,
        status: TipStatus,
    ) -> Result<SocialTipRow, AppError> {
        let row = sqlx::query_as::<_, SocialTipRow>(&format!(
            "INSERT INTO social_tips \
             (sender_user_id, asset, amount, is_public, claim_key_hash, encrypted_key, \
              tip_address, funding_txid, status, confirmations_required, tip_view_key) \
             VALUES ($1, $2, $3, TRUE, $4, $5, $6, $7, $8, $9, $10) \
             RETURNING {TIP_COLS}"
        ))
        .bind(new.sender_user_id)
        .bind(new.asset)
        .bind(new.amount)
        .bind(new.claim_key_hash)
        .bind(new.encrypted_key)
        .bind(new.tip_address)
        .bind(new.funding_txid)
        .bind(status.as_str())
        .bind(new.confirmations_required)
        .bind(new.tip_view_key)
        .fetch_one(self.pool())
        .await?;
        Ok(row)
    }

    /// Two-phase create: a `draft` tip with no funding attached yet. The sender
    /// funds `tip_address` off-band, then calls attach-funding to advance it.
    #[instrument(skip(self, new))]
    pub async fn create_draft_social_tip(
        &self,
        new: NewSocialTip<'_>,
    ) -> Result<SocialTipRow, AppError> {
        debug_assert!(new.funding_txid.is_none(), "a draft has no funding_txid");
        self.insert_social_tip(new, TipStatus::Draft).await
    }

    /// Single-call create with funding already attached: lands in
    /// `pending_confirmation` so the funding verifier (not the caller) owns the
    /// transition to `pending`.
    #[instrument(skip(self, new))]
    pub async fn create_social_tip(
        &self,
        new: NewSocialTip<'_>,
    ) -> Result<SocialTipRow, AppError> {
        self.insert_social_tip(new, TipStatus::PendingConfirmation).await
    }

    /// All tips this user has sent, newest first (every status).
    #[instrument(skip(self))]
    pub async fn get_sent_social_tips(
        &self,
        sender_user_id: Uuid,
    ) -> Result<Vec<SocialTipRow>, AppError> {
        let rows = sqlx::query_as::<_, SocialTipRow>(&format!(
            "SELECT {TIP_COLS} FROM social_tips \
             WHERE sender_user_id = $1 ORDER BY created_at DESC"
        ))
        .bind(sender_user_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }

    /// Cancel a still-unfunded draft. Owner-scoped and `draft`-only, so it can
    /// never cancel a funded/claimed tip (that path is clawback). Returns the id
    /// if this call cancelled it; `None` if no such draft (wrong owner, wrong
    /// status, or unknown id).
    #[instrument(skip(self))]
    pub async fn cancel_draft_social_tip(
        &self,
        id: Uuid,
        sender_user_id: Uuid,
    ) -> Result<Option<Uuid>, AppError> {
        let cancelled = sqlx::query_scalar::<_, Uuid>(
            "UPDATE social_tips SET status = 'cancelled' \
             WHERE id = $1 AND sender_user_id = $2 AND status = 'draft' \
             RETURNING id",
        )
        .bind(id)
        .bind(sender_user_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(cancelled)
    }

    // ── Stage 3: money-in (attach funding + confirmation/amount verifier) ──────
    //
    // Every method below is a single guarded `UPDATE ... WHERE ... RETURNING`
    // (or a filtered SELECT for the worker). The WHERE guards are the
    // money-safety surface: the amount verifier only ever transitions a row it
    // still finds in `pending_confirmation` with `funding_amount_verified =
    // FALSE`, so an LWS/Electrum outage that re-drives the verifier can never
    // double-fire or clobber a claimed/clawed-back row.

    /// Attach a broadcast funding tx to a `draft` tip, advancing it into the
    /// funding lifecycle. Idempotent: attaching the SAME txid again is a no-op
    /// that returns the row; a DIFFERENT txid (or a non-draft row) is a
    /// [`AppError::ValidationError`]; an unknown / not-owned id is
    /// [`AppError::NotFound`].
    ///
    /// One atomic guarded UPDATE encodes all three legitimate outcomes:
    ///   1. `draft` + `funding_txid IS NULL` → attach and flip to
    ///      `pending_confirmation`.
    ///   2. row already carries the same `funding_txid` → the `funding_txid =
    ///      $3` arm matches, `COALESCE` keeps it, status stays (no-op).
    ///   3. anything else → no row, disambiguated by the follow-up SELECT.
    ///
    /// ALL non-draft tips land in `pending_confirmation` (never `pending`), so
    /// the funding-amount verifier — never the caller — owns the transition to
    /// claimable. `COALESCE(funding_txid, $3)` can never overwrite an existing
    /// txid, which is what makes the same-txid retry a true no-op.
    #[instrument(skip(self))]
    pub async fn attach_funding_to_tip(
        &self,
        tip_id: Uuid,
        sender_user_id: Uuid,
        funding_txid: &str,
    ) -> Result<SocialTipRow, AppError> {
        let target_status = TipStatus::PendingConfirmation.as_str();
        let result = sqlx::query_as::<_, SocialTipRow>(&format!(
            "UPDATE social_tips \
             SET funding_txid = COALESCE(funding_txid, $3), \
                 status = CASE \
                     WHEN status = 'draft' AND funding_txid IS NULL THEN $4 \
                     ELSE status END, \
                 updated_at = CASE \
                     WHEN status = 'draft' AND funding_txid IS NULL THEN NOW() \
                     ELSE updated_at END \
             WHERE id = $1 \
               AND sender_user_id = $2 \
               AND ((status = 'draft' AND funding_txid IS NULL) OR funding_txid = $3) \
             RETURNING {TIP_COLS}"
        ))
        .bind(tip_id)
        .bind(sender_user_id)
        .bind(funding_txid)
        .bind(target_status)
        .fetch_optional(self.pool())
        .await?;

        if let Some(tip) = result {
            return Ok(tip);
        }

        // The guarded UPDATE matched nothing. A single follow-up SELECT (error
        // path only) distinguishes "not your tip / doesn't exist" from "already
        // has a different funding_txid" from "wrong status".
        let current = sqlx::query_as::<_, SocialTipRow>(&format!(
            "SELECT {TIP_COLS} FROM social_tips WHERE id = $1 AND sender_user_id = $2"
        ))
        .bind(tip_id)
        .bind(sender_user_id)
        .fetch_optional(self.pool())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Tip {tip_id} not found or not yours")))?;

        if let Some(existing_txid) = current.funding_txid.as_ref() {
            if existing_txid != funding_txid {
                return Err(AppError::ValidationError(format!(
                    "Tip {tip_id} already has a different funding_txid attached"
                )));
            }
            // Same txid — a race where the UPDATE matched but a concurrent write
            // modified the row between statements. Return the current row as-is.
            return Ok(current);
        }

        Err(AppError::ValidationError(format!(
            "Tip {tip_id} is in status {} — funding can only be attached to drafts",
            current.status
        )))
    }

    /// Tips of `asset` that still need on-chain confirmation counting: in
    /// `pending`/`pending_confirmation`, with a non-zero threshold not yet
    /// reached, a funding txid attached, and not checked in the last 30s (per-row
    /// rate limit). XMR/WOW only in practice — BTC/LTC have
    /// `confirmations_required = 0` and are excluded by the `> 0` guard.
    #[instrument(skip(self))]
    pub async fn get_tips_pending_confirmation(
        &self,
        asset: &str,
    ) -> Result<Vec<SocialTipRow>, AppError> {
        let rows = sqlx::query_as::<_, SocialTipRow>(&format!(
            "SELECT {TIP_COLS} FROM social_tips \
             WHERE status IN ('pending', 'pending_confirmation') \
               AND asset = $1 \
               AND confirmations_required > 0 \
               AND funding_confirmations < confirmations_required \
               AND funding_txid IS NOT NULL \
               AND (last_confirmation_check IS NULL \
                    OR last_confirmation_check < NOW() - INTERVAL '30 seconds') \
             ORDER BY created_at ASC \
             LIMIT 50"
        ))
        .bind(asset)
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }

    /// Record the latest `funding_confirmations` and stamp `funding_confirmed_at`
    /// the first time the threshold is met. Deliberately does NOT flip status:
    /// the `pending_confirmation` → `pending` transition is owned by the
    /// funding-AMOUNT verifier (a tip with enough confirmations but a short
    /// receipt must land in `funding_mismatch`, never become claimable).
    #[instrument(skip(self))]
    pub async fn update_tip_confirmations(
        &self,
        tip_id: Uuid,
        confirmations: i32,
    ) -> Result<Option<SocialTipRow>, AppError> {
        let row = sqlx::query_as::<_, SocialTipRow>(&format!(
            "UPDATE social_tips \
             SET funding_confirmations = $2, \
                 last_confirmation_check = NOW(), \
                 funding_confirmed_at = CASE \
                     WHEN $2 >= confirmations_required AND funding_confirmed_at IS NULL \
                     THEN NOW() ELSE funding_confirmed_at END, \
                 updated_at = NOW() \
             WHERE id = $1 \
             RETURNING {TIP_COLS}"
        ))
        .bind(tip_id)
        .bind(confirmations)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Stamp `last_confirmation_check = NOW()` only, touching nothing else. The
    /// verifier calls this on its non-mutating branches (Unfunded / Drained /
    /// LwsError) so the 30s per-row rate-limit predicate actually starves a
    /// re-polled row during an outage instead of re-hitting it every cycle.
    #[instrument(skip(self))]
    pub async fn touch_tip_last_check(&self, tip_id: Uuid) -> Result<(), AppError> {
        sqlx::query("UPDATE social_tips SET last_confirmation_check = NOW() WHERE id = $1")
            .bind(tip_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Tips that have reached their confirmation threshold and await
    /// funding-amount verification: still `pending_confirmation`, not yet
    /// amount-verified, `funding_confirmations >= confirmations_required`, and
    /// past the 30s per-row rate limit. (BTC/LTC with threshold 0 qualify
    /// immediately.)
    #[instrument(skip(self))]
    pub async fn get_tips_awaiting_amount_verification(
        &self,
    ) -> Result<Vec<SocialTipRow>, AppError> {
        let rows = sqlx::query_as::<_, SocialTipRow>(&format!(
            "SELECT {TIP_COLS} FROM social_tips \
             WHERE status = 'pending_confirmation' \
               AND funding_amount_verified = FALSE \
               AND funding_confirmations >= confirmations_required \
               AND (last_confirmation_check IS NULL \
                    OR last_confirmation_check < NOW() - INTERVAL '30 seconds') \
             ORDER BY created_at ASC \
             LIMIT 50"
        ))
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }

    /// Mark funding amount-verified and flip `pending_confirmation` → `pending`
    /// (claimable). The `status = 'pending_confirmation' AND
    /// funding_amount_verified = FALSE` guard makes this idempotent: a second
    /// call (or a row clawed back mid-poll) returns `None` and the caller skips
    /// its side effects. `observed_amount` is the on-chain receipt total (>=
    /// `amount`), in atomic units.
    #[instrument(skip(self))]
    pub async fn mark_tip_funding_verified(
        &self,
        tip_id: Uuid,
        observed_amount: i64,
    ) -> Result<Option<SocialTipRow>, AppError> {
        let row = sqlx::query_as::<_, SocialTipRow>(&format!(
            "UPDATE social_tips \
             SET status = 'pending', \
                 funding_amount_verified = TRUE, \
                 funding_amount_observed = $2, \
                 funding_amount_verified_at = NOW(), \
                 updated_at = NOW() \
             WHERE id = $1 \
               AND status = 'pending_confirmation' \
               AND funding_amount_verified = FALSE \
             RETURNING {TIP_COLS}"
        ))
        .bind(tip_id)
        .bind(observed_amount)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Mark a short-funded tip: flip `pending_confirmation` → `funding_mismatch`
    /// (never claimable; the sender can claw it back). Same idempotency guard as
    /// [`mark_tip_funding_verified`]. `observed_amount` is the on-chain receipt
    /// total (< `amount`), in atomic units.
    #[instrument(skip(self))]
    pub async fn mark_tip_funding_mismatch(
        &self,
        tip_id: Uuid,
        observed_amount: i64,
    ) -> Result<Option<SocialTipRow>, AppError> {
        let row = sqlx::query_as::<_, SocialTipRow>(&format!(
            "UPDATE social_tips \
             SET status = 'funding_mismatch', \
                 funding_amount_verified = TRUE, \
                 funding_amount_observed = $2, \
                 funding_amount_verified_at = NOW(), \
                 updated_at = NOW() \
             WHERE id = $1 \
               AND status = 'pending_confirmation' \
               AND funding_amount_verified = FALSE \
             RETURNING {TIP_COLS}"
        ))
        .bind(tip_id)
        .bind(observed_amount)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    // ── Stage 4: money-out (claim / confirm-sweep / clawback + reconciler) ──────
    //
    // The HIGHEST money-safety surface. Every method below is a single guarded
    // `UPDATE ... WHERE ... RETURNING` and the WHERE guards are non-negotiable —
    // a wrong conjunct loses funds. Guards ported VERBATIM from the audited
    // legacy `smirk-backend/src/infra/db/social_tips.rs` (public subset: the
    // targeted/recipient branches are dropped, `is_public = TRUE` is kept).

    /// Lock a claimable tip into `claiming` and hand the claimer the encrypted
    /// key + tip address. THE DOUBLE-CLAIM GUARD — every conjunct is
    /// non-negotiable:
    ///   - `status IN ('pending', 'claiming')` (audit T1): without it a
    ///     `funding_mismatch` / `clawed_back` row would re-pass the UPDATE
    ///     because it still satisfies the confirmation/amount/sweep predicates —
    ///     a URL holder could curl `/claim` on an underfunded tip and sweep the
    ///     short amount before the sender's clawback wins.
    ///   - `funding_confirmations >= confirmations_required AND
    ///     funding_amount_verified = TRUE`: only a fully-funded, amount-verified
    ///     tip is claimable.
    ///   - `sweep_confirmed_at IS NULL`: never re-hand the key on a settled tip.
    ///   - `is_public = TRUE`: public-only port; a public tip's claim state is a
    ///     UX signal, not a cryptographic lock (whoever wins the on-chain sweep
    ///     race wins the tip). `claimed_by_user_id` is recorded for DM routing
    ///     only, carrying no exclusive rights.
    ///
    /// Returns `None` (not claimable) for a missing / non-claimable / already-
    /// swept row.
    #[instrument(skip(self))]
    pub async fn mark_tip_claiming(
        &self,
        tip_id: Uuid,
        claimed_by_user_id: Uuid,
    ) -> Result<Option<SocialTipRow>, AppError> {
        let tip = sqlx::query_as::<_, SocialTipRow>(&format!(
            "UPDATE social_tips \
             SET status = 'claiming', \
                 claimed_at = NOW(), \
                 claimed_by_user_id = $2, \
                 updated_at = NOW() \
             WHERE id = $1 \
               AND status IN ('pending', 'claiming') \
               AND funding_confirmations >= confirmations_required \
               AND funding_amount_verified = TRUE \
               AND sweep_confirmed_at IS NULL \
               AND is_public = TRUE \
             RETURNING {TIP_COLS}"
        ))
        .bind(tip_id)
        .bind(claimed_by_user_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(tip)
    }

    /// RECORD (not settle) the claimer's broadcast sweep txid, leaving the row in
    /// `claiming`. The reconciler — never this call — owns `claiming -> claimed`,
    /// and only once the sweep CONFIRMS on-chain. This closes the RBF-steal
    /// false-"claimed" vector: a URL holder who RBFs the recorded sweep can't
    /// trigger a premature settlement.
    ///
    /// First-recorder-wins + idempotent: the guard
    /// `(sweep_txid IS NULL OR sweep_txid = $3)` records the first txid and makes
    /// a second call with the SAME txid a no-op; a second call with a DIFFERENT
    /// txid does NOT overwrite (the UPDATE matches nothing) — junk-txid poisoning
    /// stays blocked. In that case the fallthrough SELECT returns the current
    /// row (with the WINNING first txid) so the caller renders live state; both
    /// the first and the different-second call therefore return `Some`.
    ///
    /// Returns `None` only when the tip doesn't exist or isn't in
    /// `claiming`/`claimed` (e.g. `/confirm-sweep` on a never-claimed tip).
    #[instrument(skip(self))]
    pub async fn confirm_tip_sweep(
        &self,
        tip_id: Uuid,
        claimer_user_id: Uuid,
        sweep_txid: &str,
    ) -> Result<Option<SocialTipRow>, AppError> {
        let recorded = sqlx::query_as::<_, SocialTipRow>(&format!(
            "UPDATE social_tips \
             SET sweep_txid = COALESCE(sweep_txid, $3), \
                 claimed_by_user_id = COALESCE(claimed_by_user_id, $2), \
                 claimed_at = COALESCE(claimed_at, NOW()), \
                 updated_at = NOW() \
             WHERE id = $1 \
               AND status = 'claiming' \
               AND sweep_confirmed_at IS NULL \
               AND is_public = TRUE \
               AND (sweep_txid IS NULL OR sweep_txid = $3) \
             RETURNING {TIP_COLS}"
        ))
        .bind(tip_id)
        .bind(claimer_user_id)
        .bind(sweep_txid)
        .fetch_optional(self.pool())
        .await?;

        if let Some(tip) = recorded {
            return Ok(Some(tip));
        }

        // Did not record (already settled, a DIFFERENT txid already recorded, or
        // not a claiming/claimed row): return the current row so the caller can
        // render live state — first-recorder's txid wins.
        let existing = sqlx::query_as::<_, SocialTipRow>(&format!(
            "SELECT {TIP_COLS} FROM social_tips \
             WHERE id = $1 AND status IN ('claiming', 'claimed')"
        ))
        .bind(tip_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(existing)
    }

    /// Sender reclaims the funds. Guard ported verbatim (evolved across two
    /// audits):
    ///   - `sender_user_id = $2`: only the sender can claw back.
    ///   - `status IN ('pending', 'pending_confirmation', 'claiming',
    ///     'funding_mismatch', 'cancelled')`: the 5-status set lets a sender
    ///     recover a tip racing a claimer (`claiming`), an underfunded tip
    ///     (`funding_mismatch`), and a GC-cancelled-but-still-funded draft
    ///     (`cancelled`).
    ///   - `sweep_confirmed_at IS NULL`: never roll back a settled `claimed` row.
    ///
    /// Returns `None` when no such clawable row (wrong owner, wrong status, or
    /// already settled).
    #[instrument(skip(self))]
    pub async fn clawback_social_tip(
        &self,
        tip_id: Uuid,
        sender_user_id: Uuid,
    ) -> Result<Option<SocialTipRow>, AppError> {
        let tip = sqlx::query_as::<_, SocialTipRow>(&format!(
            "UPDATE social_tips \
             SET status = 'clawed_back', \
                 clawed_back_at = NOW(), \
                 updated_at = NOW() \
             WHERE id = $1 \
               AND sender_user_id = $2 \
               AND status IN ( \
                 'pending', \
                 'pending_confirmation', \
                 'claiming', \
                 'funding_mismatch', \
                 'cancelled' \
               ) \
               AND sweep_confirmed_at IS NULL \
             RETURNING {TIP_COLS}"
        ))
        .bind(tip_id)
        .bind(sender_user_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(tip)
    }

    /// The SOLE new writer of `status = 'claimed'`. Settle a tip on-chain after
    /// its sweep confirmed to the per-asset depth.
    ///
    /// One-way lock: the `status = 'claiming' AND sweep_confirmed_at IS NULL`
    /// guard means the FIRST reconciler tick to observe the on-chain winner wins
    /// the transition; any later tick (or an instance that lost the advisory-lock
    /// race) gets `None` and fires no side effects.
    ///
    /// `claimed_by`: `Some` overwrites `claimed_by_user_id`; `None` PRESERVES it
    /// (the `CASE WHEN $5 IS NOT NULL` guard). This method can only set-or-keep,
    /// never clear — to NULL the attribution use `clear_claimed_by_on_settle`.
    #[instrument(skip(self))]
    pub async fn confirm_sweep_onchain(
        &self,
        tip_id: Uuid,
        winner_txid: &str,
        block_height: i32,
        block_hash: Option<&str>,
        claimed_by: Option<Uuid>,
    ) -> Result<Option<SocialTipRow>, AppError> {
        let tip = sqlx::query_as::<_, SocialTipRow>(&format!(
            "UPDATE social_tips \
             SET status = 'claimed', \
                 sweep_confirmed_at = NOW(), \
                 sweep_txid = $2, \
                 sweep_block_height = $3, \
                 sweep_block_hash = $4, \
                 claimed_by_user_id = CASE \
                     WHEN $5::uuid IS NOT NULL THEN $5 \
                     ELSE claimed_by_user_id END, \
                 updated_at = NOW() \
             WHERE id = $1 \
               AND status = 'claiming' \
               AND sweep_confirmed_at IS NULL \
             RETURNING {TIP_COLS}"
        ))
        .bind(tip_id)
        .bind(winner_txid)
        .bind(block_height)
        .bind(block_hash)
        .bind(claimed_by)
        .fetch_optional(self.pool())
        .await?;
        Ok(tip)
    }

    /// Settle to `claimed` AND NULL `claimed_by_user_id`. Used when the on-chain
    /// winner's txid doesn't match the recorded `sweep_txid` (RBF / unknown
    /// sweeper) or none was recorded — a public tip swept by a URL holder who
    /// isn't the recorded claimer. Same one-way `claiming -> claimed` lock as
    /// `confirm_sweep_onchain`; `None` if already settled.
    #[instrument(skip(self))]
    pub async fn clear_claimed_by_on_settle(
        &self,
        tip_id: Uuid,
        winner_txid: &str,
        block_height: i32,
        block_hash: Option<&str>,
    ) -> Result<Option<SocialTipRow>, AppError> {
        let tip = sqlx::query_as::<_, SocialTipRow>(&format!(
            "UPDATE social_tips \
             SET status = 'claimed', \
                 sweep_confirmed_at = NOW(), \
                 sweep_txid = $2, \
                 sweep_block_height = $3, \
                 sweep_block_hash = $4, \
                 claimed_by_user_id = NULL, \
                 updated_at = NOW() \
             WHERE id = $1 \
               AND status = 'claiming' \
               AND sweep_confirmed_at IS NULL \
             RETURNING {TIP_COLS}"
        ))
        .bind(tip_id)
        .bind(winner_txid)
        .bind(block_height)
        .bind(block_hash)
        .fetch_optional(self.pool())
        .await?;
        Ok(tip)
    }

    /// Revert a settled (`claimed`) tip back to `claiming` after a reorg orphaned
    /// its recorded sweep. Clearing `sweep_txid` is LOAD-BEARING: the next
    /// confirm cycle re-scans the address and records the NEW on-chain winner,
    /// not the orphaned one. Also clears `sweep_confirmed_dm_sent_at` so a fresh
    /// "claimed" notify can fire once re-confirmation lands. The
    /// `status = 'claimed' AND sweep_confirmed_at IS NOT NULL` guard is the only
    /// path off `claimed`; `None` if the row isn't settled.
    #[instrument(skip(self))]
    pub async fn revert_sweep_on_reorg(
        &self,
        tip_id: Uuid,
    ) -> Result<Option<SocialTipRow>, AppError> {
        let tip = sqlx::query_as::<_, SocialTipRow>(&format!(
            "UPDATE social_tips \
             SET status = 'claiming', \
                 sweep_confirmed_at = NULL, \
                 sweep_txid = NULL, \
                 sweep_block_height = NULL, \
                 sweep_block_hash = NULL, \
                 sweep_confirmed_dm_sent_at = NULL, \
                 updated_at = NOW() \
             WHERE id = $1 \
               AND status = 'claimed' \
               AND sweep_confirmed_at IS NOT NULL \
             RETURNING {TIP_COLS}"
        ))
        .bind(tip_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(tip)
    }

    /// Reconciler poll: `claiming` tips whose sweep hasn't confirmed yet. Includes
    /// rows with `sweep_txid IS NULL` — the reconciler scans the ADDRESS, not any
    /// recorded txid, since a public tip's recorded sweep may not be the on-chain
    /// winner (RBF / race). `funding_amount_verified = TRUE` keeps a
    /// `funding_mismatch`-adjacent row out. Rate-limited on `last_confirmation_check`
    /// (30s) so an outage doesn't burn one probe per row per cycle.
    #[instrument(skip(self))]
    pub async fn get_tips_awaiting_sweep_confirmation(
        &self,
        limit: i64,
    ) -> Result<Vec<SocialTipRow>, AppError> {
        let tips = sqlx::query_as::<_, SocialTipRow>(&format!(
            "SELECT {TIP_COLS} FROM social_tips \
             WHERE status = 'claiming' \
               AND sweep_confirmed_at IS NULL \
               AND funding_amount_verified = TRUE \
               AND (last_confirmation_check IS NULL \
                    OR last_confirmation_check < NOW() - INTERVAL '30 seconds') \
             ORDER BY claimed_at ASC \
             LIMIT $1"
        ))
        .bind(limit)
        .fetch_all(self.pool())
        .await?;
        Ok(tips)
    }

    /// Reorg-check poll: settled tips the reconciler settled ITSELF (they carry a
    /// `sweep_block_height` witness) and hasn't re-probed in the last 30s. Rows
    /// with `sweep_block_height IS NULL` are excluded on purpose (no recorded
    /// height to reorg-check against).
    #[instrument(skip(self))]
    pub async fn get_settled_tips_for_reorg_check(
        &self,
        limit: i64,
    ) -> Result<Vec<SocialTipRow>, AppError> {
        let tips = sqlx::query_as::<_, SocialTipRow>(&format!(
            "SELECT {TIP_COLS} FROM social_tips \
             WHERE status = 'claimed' \
               AND sweep_confirmed_at IS NOT NULL \
               AND sweep_block_height IS NOT NULL \
               AND (last_confirmation_check IS NULL \
                    OR last_confirmation_check < NOW() - INTERVAL '30 seconds') \
             ORDER BY sweep_confirmed_at ASC \
             LIMIT $1"
        ))
        .bind(limit)
        .fetch_all(self.pool())
        .await?;
        Ok(tips)
    }

    /// Exactly-once stamp for the reconciler-owned "tip claimed" notify. The
    /// `WHERE ... IS NULL` guard makes it idempotent so a retried cycle never
    /// re-stamps. (The notify itself is stubbed to a no-op in this port, but the
    /// stamp is preserved so re-enabling notifications stays exactly-once.)
    #[instrument(skip(self))]
    pub async fn stamp_sweep_confirmed_dm_sent(&self, tip_id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE social_tips \
             SET sweep_confirmed_dm_sent_at = NOW(), updated_at = NOW() \
             WHERE id = $1 AND sweep_confirmed_dm_sent_at IS NULL",
        )
        .bind(tip_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Exactly-once stamp for the reconciler-owned "claim reversed by reorg"
    /// notify. Same `WHERE ... IS NULL` idempotency as
    /// `stamp_sweep_confirmed_dm_sent`.
    #[instrument(skip(self))]
    pub async fn stamp_reorg_notified(&self, tip_id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE social_tips \
             SET reorg_notified_at = NOW(), updated_at = NOW() \
             WHERE id = $1 AND reorg_notified_at IS NULL",
        )
        .bind(tip_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }
}
