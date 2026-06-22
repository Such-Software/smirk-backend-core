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
            .await?;
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

    /// Attach the recipient's response slatepack, advancing the relay to
    /// `PendingSender` so the sender can finalize.
    #[instrument(skip(self, response_slatepack))]
    pub async fn add_slatepack_response(
        &self,
        slate_id: &str,
        response_slatepack: &str,
    ) -> Result<GrinSlatepack, AppError> {
        let sql = format!(
            "UPDATE grin_slatepacks \
             SET response_slatepack = $2, status = $3, updated_at = NOW() \
             WHERE slate_id = $1 RETURNING {GRIN_SLATEPACK_COLS}"
        );
        let slatepack = sqlx::query_as::<_, GrinSlatepack>(&sql)
            .bind(slate_id)
            .bind(response_slatepack)
            .bind(SlatepackStatus::PendingSender)
            .fetch_one(self.pool())
            .await?;
        Ok(slatepack)
    }

    /// Mark a slatepack as finalized once the transaction is broadcast.
    #[instrument(skip(self))]
    pub async fn finalize_slatepack(
        &self,
        slate_id: &str,
        tx_hash: &str,
    ) -> Result<GrinSlatepack, AppError> {
        let sql = format!(
            "UPDATE grin_slatepacks \
             SET status = $2, tx_hash = $3, finalized_at = NOW(), updated_at = NOW() \
             WHERE slate_id = $1 RETURNING {GRIN_SLATEPACK_COLS}"
        );
        let slatepack = sqlx::query_as::<_, GrinSlatepack>(&sql)
            .bind(slate_id)
            .bind(SlatepackStatus::Finalized)
            .bind(tx_hash)
            .fetch_one(self.pool())
            .await?;
        Ok(slatepack)
    }

    /// Cancel a slatepack relay.
    #[instrument(skip(self))]
    pub async fn cancel_slatepack(&self, slate_id: &str) -> Result<GrinSlatepack, AppError> {
        let sql = format!(
            "UPDATE grin_slatepacks \
             SET status = $2, updated_at = NOW() \
             WHERE slate_id = $1 RETURNING {GRIN_SLATEPACK_COLS}"
        );
        let slatepack = sqlx::query_as::<_, GrinSlatepack>(&sql)
            .bind(slate_id)
            .bind(SlatepackStatus::Cancelled)
            .fetch_one(self.pool())
            .await?;
        Ok(slatepack)
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
