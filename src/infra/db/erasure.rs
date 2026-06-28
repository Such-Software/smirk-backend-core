//! Self-service erasure queries (operator §5).
//!
//! Two-phase (request -> confirm) + grace, then a sweeper executes. Execution is
//! ONE fail-closed transaction: per-table policy (purge login_events, scrub audit
//! PII, cascade-delete the user) + tombstone + a hash-chained audit row, all
//! committing together. The schema's ON DELETE clauses (CASCADE for owned rows,
//! SET NULL for counterparty/audit links) make `DELETE FROM users` safe, so the
//! cascade does the structural delete; this layer adds the policy nuances the
//! cascade can't (purging the login (origin,asset,time) quasi-identifier and
//! scrubbing audit PII) and the tamper-evident audit.
//!
//! Scope (v1): the live primary. Crypto-shred of view-key backup residue is a
//! documented non-v1 item (decisions ledger); LWS de-registration is a documented
//! residual (operators run their own LWS). No view keys are stored here anyway
//! (the wallet forwards them per-request), so there is no at-rest view key to shred.

use chrono::{Duration, SubsecRound, Utc};
use tracing::instrument;
use uuid::Uuid;

use crate::error::AppError;
use crate::models::db::{ErasureRequest, NewAdminAudit};

use super::Database;

const COLS: &str = "id, user_id, subject_hash, status, requested_at, scheduled_for, \
     confirmed_at, completed_at, cancelled_at";

impl Database {
    /// The live (pending/confirmed) request for a user, if any.
    #[instrument(skip(self))]
    pub async fn active_erasure_request(
        &self,
        user_id: Uuid,
    ) -> Result<Option<ErasureRequest>, AppError> {
        let sql = format!(
            "SELECT {COLS} FROM erasure_requests \
             WHERE user_id = $1 AND status IN ('pending', 'confirmed')"
        );
        Ok(sqlx::query_as::<_, ErasureRequest>(&sql)
            .bind(user_id)
            .fetch_optional(self.pool())
            .await?)
    }

    /// Get-or-create the live request for a user (idempotent: one active request
    /// per user). `grace_hours` sets `scheduled_for`.
    #[instrument(skip(self, subject_hash))]
    pub async fn request_erasure(
        &self,
        user_id: Uuid,
        subject_hash: &str,
        grace_hours: i64,
    ) -> Result<ErasureRequest, AppError> {
        if let Some(existing) = self.active_erasure_request(user_id).await? {
            return Ok(existing);
        }
        let scheduled_for = (Utc::now() + Duration::hours(grace_hours)).trunc_subsecs(6);
        let sql = format!(
            "INSERT INTO erasure_requests (user_id, subject_hash, scheduled_for) \
             VALUES ($1, $2, $3) RETURNING {COLS}"
        );
        match sqlx::query_as::<_, ErasureRequest>(&sql)
            .bind(user_id)
            .bind(subject_hash)
            .bind(scheduled_for)
            .fetch_one(self.pool())
            .await
        {
            Ok(row) => Ok(row),
            // Lost the race against a concurrent request — return the winner.
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => self
                .active_erasure_request(user_id)
                .await?
                .ok_or_else(|| AppError::Internal("erasure request race".into())),
            Err(e) => Err(e.into()),
        }
    }

    /// Confirm a pending request owned by `user_id` (a second fresh proof). Starts
    /// the grace clock. Returns the updated row, or `None` if not pending/owned.
    #[instrument(skip(self))]
    pub async fn confirm_erasure_request(
        &self,
        id: Uuid,
        user_id: Uuid,
        grace_hours: i64,
    ) -> Result<Option<ErasureRequest>, AppError> {
        let scheduled_for = (Utc::now() + Duration::hours(grace_hours)).trunc_subsecs(6);
        let sql = format!(
            "UPDATE erasure_requests SET status = 'confirmed', confirmed_at = NOW(), \
             scheduled_for = $3 \
             WHERE id = $1 AND user_id = $2 AND status = 'pending' RETURNING {COLS}"
        );
        Ok(sqlx::query_as::<_, ErasureRequest>(&sql)
            .bind(id)
            .bind(user_id)
            .bind(scheduled_for)
            .fetch_optional(self.pool())
            .await?)
    }

    /// Cancel a live request owned by `user_id` (during grace). Returns the row,
    /// or `None` if not live/owned.
    #[instrument(skip(self))]
    pub async fn cancel_erasure_request(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ErasureRequest>, AppError> {
        let sql = format!(
            "UPDATE erasure_requests SET status = 'cancelled', cancelled_at = NOW() \
             WHERE id = $1 AND user_id = $2 AND status IN ('pending', 'confirmed') RETURNING {COLS}"
        );
        Ok(sqlx::query_as::<_, ErasureRequest>(&sql)
            .bind(id)
            .bind(user_id)
            .fetch_optional(self.pool())
            .await?)
    }

    /// Claim a batch of confirmed requests past their grace, for execution.
    /// `FOR UPDATE SKIP LOCKED` so only one node processes a given row.
    #[instrument(skip(self))]
    pub async fn due_erasure_requests(&self, limit: i64) -> Result<Vec<ErasureRequest>, AppError> {
        let sql = format!(
            "SELECT {COLS} FROM erasure_requests \
             WHERE status = 'confirmed' AND scheduled_for <= NOW() \
             ORDER BY scheduled_for ASC LIMIT $1 FOR UPDATE SKIP LOCKED"
        );
        Ok(sqlx::query_as::<_, ErasureRequest>(&sql)
            .bind(limit)
            .fetch_all(self.pool())
            .await?)
    }

    /// Execute a confirmed erasure in ONE fail-closed transaction: per-table
    /// policy + cascade delete + tombstone + hash-chained audit. `purge_login`
    /// chooses purge (default) vs anonymize for `login_events`.
    #[instrument(skip(self, secret))]
    pub async fn execute_erasure(
        &self,
        id: Uuid,
        user_id: Uuid,
        purge_login: bool,
        secret: &str,
    ) -> Result<(), AppError> {
        let mut tx = self.pool().begin().await?;

        // login_events: the (origin, asset, time) quasi-identifier — the cascade
        // only nulls user_id, so purge (default) or anonymize all three here.
        if purge_login {
            sqlx::query("DELETE FROM login_events WHERE user_id = $1")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        } else {
            sqlx::query(
                "UPDATE login_events SET user_id = NULL, origin = NULL, asset = 'redacted' \
                 WHERE user_id = $1",
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        }

        // audit_logs: retained for the security trail, but scrub this user's PII
        // (the cascade de-links user_id on the user delete below).
        sqlx::query(
            "UPDATE audit_logs SET ip_address = NULL, user_agent = NULL WHERE user_id = $1",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        // Structural delete: cascades wallets/sessions/user_keys/owned slatepacks;
        // SET NULL on counterparty/audit/login links (incl. this tombstone row).
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        // Tombstone (user_id was just nulled by the cascade).
        sqlx::query(
            "UPDATE erasure_requests SET status = 'completed', completed_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;

        self.append_admin_audit(
            &mut tx,
            &NewAdminAudit {
                action: "account_erasure_completed".into(),
                actor_kind: "user".into(),
                actor_pubkey_prefix: None,
                target: Some(id.to_string()),
                details: None,
                ip_address: None,
            },
            secret,
        )
        .await?;

        tx.commit().await?;
        Ok(())
    }
}
