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
/// `FromRow` maps by name). Fields not read until later port stages are held
/// behind `allow(dead_code)`.
#[derive(Debug, Clone, FromRow)]
#[allow(dead_code)]
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
}
