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

impl Database {
    /// Fetch a tip by id, or `None`. The UUID is the public bearer token behind
    /// a share URL, so this read is intentionally not owner-scoped.
    #[instrument(skip(self))]
    #[allow(dead_code)] // consumed by the tips routes in the next stage
    pub async fn get_social_tip(&self, id: Uuid) -> Result<Option<SocialTipRow>, AppError> {
        let row = sqlx::query_as::<_, SocialTipRow>(&format!(
            "SELECT {TIP_COLS} FROM social_tips WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }
}
