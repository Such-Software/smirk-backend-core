//! Session queries.
//!
//! Sessions back JWT refresh tokens. `refresh_token_hash` arrives already
//! peppered from `core::session::hash_refresh_token`, so it is stored and
//! looked up exactly as given. Active lookups filter out revoked and expired
//! rows. Explicit column lists (no `SELECT *`) keep the refresh path lean.

use tracing::instrument;
use uuid::Uuid;

use crate::error::AppError;
use crate::models::db::{NewSession, Session};

use super::Database;

/// Explicit `sessions` columns (matches `Session` field names; FromRow maps by name).
const SESSION_COLS: &str = "id, user_id, refresh_token_hash, platform, device_info, \
     ip_address, created_at, expires_at, revoked_at, last_used_at";

impl Database {
    /// Create a new session. `refresh_token_hash` is already peppered by the caller.
    #[instrument(skip(self, input), fields(user_id = %input.user_id, platform = %input.platform))]
    pub async fn create_session(&self, input: NewSession) -> Result<Session, AppError> {
        let sql = format!(
            "INSERT INTO sessions \
             (user_id, refresh_token_hash, platform, device_info, ip_address, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING {SESSION_COLS}"
        );
        let session = sqlx::query_as::<_, Session>(&sql)
            .bind(input.user_id)
            .bind(&input.refresh_token_hash)
            .bind(&input.platform)
            .bind(&input.device_info)
            .bind(input.ip_address)
            .bind(input.expires_at)
            .fetch_one(self.pool())
            .await?;
        Ok(session)
    }

    /// Look up an active (non-revoked, non-expired) session by refresh token hash.
    /// The hash is already peppered by the caller; do not pepper it here.
    #[instrument(skip(self, token_hash))]
    pub async fn get_session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<Session>, AppError> {
        let sql = format!(
            "SELECT {SESSION_COLS} FROM sessions \
             WHERE refresh_token_hash = $1 \
               AND revoked_at IS NULL \
               AND expires_at > NOW()"
        );
        Ok(sqlx::query_as::<_, Session>(&sql)
            .bind(token_hash)
            .fetch_optional(self.pool())
            .await?)
    }

    /// Update a session's `last_used_at` timestamp.
    #[instrument(skip(self))]
    pub async fn touch_session(&self, session_id: Uuid) -> Result<(), AppError> {
        sqlx::query("UPDATE sessions SET last_used_at = NOW() WHERE id = $1")
            .bind(session_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Revoke a session. Returns `true` if it was active (and is now revoked),
    /// `false` if it was already revoked — disambiguating refresh-token races.
    #[instrument(skip(self))]
    pub async fn revoke_session(&self, session_id: Uuid) -> Result<bool, AppError> {
        let result = sqlx::query(
            "UPDATE sessions SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(session_id)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Revoke all active sessions for a user. Returns the number revoked.
    #[instrument(skip(self))]
    pub async fn revoke_all_user_sessions(&self, user_id: Uuid) -> Result<u64, AppError> {
        let result = sqlx::query(
            "UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }

    /// Delete expired sessions. Returns the number removed.
    #[instrument(skip(self))]
    pub async fn cleanup_expired_sessions(&self) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at < NOW()")
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected())
    }
}
