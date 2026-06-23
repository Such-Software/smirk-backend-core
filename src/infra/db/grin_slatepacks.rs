//! Grin slatepack relay queries.
//!
//! Backs an interactive two-party Grin transaction by relaying slatepacks
//! between a sender and a recipient. The relay never holds key material; it
//! stores the opaque slatepack payloads and the lifecycle status. Explicit
//! column lists (no `SELECT *`) keep `FromRow` mapping stable as columns evolve.

use tracing::instrument;
use uuid::Uuid;

use crate::error::AppError;
use crate::models::db::{GrinSlatepack, NewGrinSlatepack, SlatepackStatus};

use super::Database;

/// Explicit `grin_slatepacks` columns (matches `GrinSlatepack` field names;
/// FromRow maps by name).
const GRIN_SLATEPACK_COLS: &str = "id, slate_id, sender_user_id, recipient_user_id, \
     recipient_address, slatepack_content, amount_nanogrin, status, response_slatepack, \
     created_at, updated_at, expires_at, finalized_at, tx_hash";

impl Database {
    /// Create a new slatepack relay entry. Starts in `PendingRecipient`: the
    /// recipient must add their response before the sender can finalize.
    #[instrument(skip(self, input), fields(slate_id = %input.slate_id))]
    pub async fn create_grin_slatepack(
        &self,
        input: NewGrinSlatepack,
    ) -> Result<GrinSlatepack, AppError> {
        let sql = format!(
            "INSERT INTO grin_slatepacks \
             (slate_id, sender_user_id, recipient_user_id, recipient_address, \
              slatepack_content, amount_nanogrin, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {GRIN_SLATEPACK_COLS}"
        );
        let slatepack = sqlx::query_as::<_, GrinSlatepack>(&sql)
            .bind(&input.slate_id)
            .bind(input.sender_user_id)
            .bind(input.recipient_user_id)
            .bind(&input.recipient_address)
            .bind(&input.slatepack_content)
            .bind(input.amount_nanogrin)
            .bind(input.expires_at)
            .fetch_one(self.pool())
            .await
            // slate_id is UNIQUE: a duplicate is a 409, never a second row that
            // the slate_id-keyed auth/state machine could be tricked across.
            .map_err(super::unique_violation_as(
                "a relay for this slate_id already exists",
            ))?;
        Ok(slatepack)
    }

    /// Fetch a slatepack by its slate ID.
    #[instrument(skip(self))]
    pub async fn get_slatepack_by_slate_id(
        &self,
        slate_id: &str,
    ) -> Result<Option<GrinSlatepack>, AppError> {
        let sql = format!("SELECT {GRIN_SLATEPACK_COLS} FROM grin_slatepacks WHERE slate_id = $1");
        Ok(sqlx::query_as::<_, GrinSlatepack>(&sql)
            .bind(slate_id)
            .fetch_optional(self.pool())
            .await?)
    }

    /// Fetch a slatepack by its row ID.
    #[instrument(skip(self))]
    pub async fn get_slatepack_by_id(&self, id: Uuid) -> Result<Option<GrinSlatepack>, AppError> {
        let sql = format!("SELECT {GRIN_SLATEPACK_COLS} FROM grin_slatepacks WHERE id = $1");
        Ok(sqlx::query_as::<_, GrinSlatepack>(&sql)
            .bind(id)
            .fetch_optional(self.pool())
            .await?)
    }

    /// List unexpired slatepacks awaiting a response from the given recipient.
    #[instrument(skip(self))]
    pub async fn get_pending_slatepacks_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<GrinSlatepack>, AppError> {
        let sql = format!(
            "SELECT {GRIN_SLATEPACK_COLS} FROM grin_slatepacks \
             WHERE recipient_user_id = $1 AND status = $2 AND expires_at > NOW() \
             ORDER BY created_at DESC"
        );
        Ok(sqlx::query_as::<_, GrinSlatepack>(&sql)
            .bind(user_id)
            .bind(SlatepackStatus::PendingRecipient)
            .fetch_all(self.pool())
            .await?)
    }

    /// Attach the recipient's response, advancing `PendingRecipient` →
    /// `PendingSender`. Targets the authorized row by primary key `id`, and the
    /// status + expiry preconditions live in the `WHERE` clause so the transition
    /// is atomic (no read-check-write race). `None` = the row no longer qualifies
    /// (wrong status / expired) → the caller maps it to a 409.
    #[instrument(skip(self, response_slatepack))]
    pub async fn add_slatepack_response(
        &self,
        id: Uuid,
        response_slatepack: &str,
    ) -> Result<Option<GrinSlatepack>, AppError> {
        let sql = format!(
            "UPDATE grin_slatepacks \
             SET response_slatepack = $2, status = $3, updated_at = NOW() \
             WHERE id = $1 AND status = $4 AND expires_at > NOW() \
             RETURNING {GRIN_SLATEPACK_COLS}"
        );
        Ok(sqlx::query_as::<_, GrinSlatepack>(&sql)
            .bind(id)
            .bind(response_slatepack)
            .bind(SlatepackStatus::PendingSender)
            .bind(SlatepackStatus::PendingRecipient)
            .fetch_optional(self.pool())
            .await?)
    }

    /// Mark a relay finalized once the sender has broadcast. Atomic: only from
    /// `PendingSender` and not expired, by primary key. `None` → 409.
    #[instrument(skip(self))]
    pub async fn finalize_slatepack(
        &self,
        id: Uuid,
        tx_hash: &str,
    ) -> Result<Option<GrinSlatepack>, AppError> {
        let sql = format!(
            "UPDATE grin_slatepacks \
             SET status = $2, tx_hash = $3, finalized_at = NOW(), updated_at = NOW() \
             WHERE id = $1 AND status = $4 AND expires_at > NOW() \
             RETURNING {GRIN_SLATEPACK_COLS}"
        );
        Ok(sqlx::query_as::<_, GrinSlatepack>(&sql)
            .bind(id)
            .bind(SlatepackStatus::Finalized)
            .bind(tx_hash)
            .bind(SlatepackStatus::PendingSender)
            .fetch_optional(self.pool())
            .await?)
    }

    /// Cancel a relay (by primary key). Atomic: only from an active state
    /// (`PendingRecipient`/`PendingSender`), so a finalized/cancelled/expired
    /// relay cannot be flipped. `None` → 409.
    #[instrument(skip(self))]
    pub async fn cancel_slatepack(&self, id: Uuid) -> Result<Option<GrinSlatepack>, AppError> {
        let sql = format!(
            "UPDATE grin_slatepacks \
             SET status = $2, updated_at = NOW() \
             WHERE id = $1 AND status IN ($3, $4) RETURNING {GRIN_SLATEPACK_COLS}"
        );
        Ok(sqlx::query_as::<_, GrinSlatepack>(&sql)
            .bind(id)
            .bind(SlatepackStatus::Cancelled)
            .bind(SlatepackStatus::PendingRecipient)
            .bind(SlatepackStatus::PendingSender)
            .fetch_optional(self.pool())
            .await?)
    }

    /// Expire pending slatepacks whose `expires_at` has passed. Returns the
    /// number of rows affected.
    #[instrument(skip(self))]
    pub async fn expire_old_slatepacks(&self) -> Result<u64, AppError> {
        let result = sqlx::query(
            "UPDATE grin_slatepacks SET status = $1, updated_at = NOW() \
             WHERE status IN ($2, $3) AND expires_at < NOW()",
        )
        .bind(SlatepackStatus::Expired)
        .bind(SlatepackStatus::PendingRecipient)
        .bind(SlatepackStatus::PendingSender)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }
}
