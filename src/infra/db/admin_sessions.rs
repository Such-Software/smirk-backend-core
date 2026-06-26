//! Admin session queries.
//!
//! Admin sessions live in their own table (never user `sessions`). The guard
//! looks a session up by the access token's `jti`; refresh and logout act by
//! session id; revoking a key cascades to every session it owns. A lookup only
//! returns a session that is neither revoked nor expired.

use tracing::instrument;
use uuid::Uuid;

use crate::error::AppError;
use crate::models::db::{AdminSession, NewAdminAudit, NewAdminSession};

use super::Database;

const COLS: &str = "id, admin_key_id, pubkey, refresh_token_hash, access_jti, \
     device_info, ip_address, created_at, expires_at, revoked_at";

impl Database {
    /// Persist a new admin session.
    #[instrument(skip(self, input), fields(admin_key_id = %input.admin_key_id))]
    pub async fn create_admin_session(
        &self,
        input: NewAdminSession,
    ) -> Result<AdminSession, AppError> {
        let sql = format!(
            "INSERT INTO admin_sessions \
             (id, admin_key_id, pubkey, refresh_token_hash, access_jti, device_info, ip_address, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING {COLS}"
        );
        let s = sqlx::query_as::<_, AdminSession>(&sql)
            .bind(input.id)
            .bind(input.admin_key_id)
            .bind(&input.pubkey)
            .bind(&input.refresh_token_hash)
            .bind(&input.access_jti)
            .bind(&input.device_info)
            .bind(input.ip_address)
            .bind(input.expires_at)
            .fetch_one(self.pool())
            .await?;
        Ok(s)
    }

    /// Create a session AND append its login audit row in ONE transaction, so
    /// the audit write is fail-closed: if it fails, the session is not created.
    #[instrument(skip(self, session, audit, secret), fields(admin_key_id = %session.admin_key_id))]
    pub async fn create_admin_session_audited(
        &self,
        session: NewAdminSession,
        audit: &NewAdminAudit,
        secret: &str,
    ) -> Result<AdminSession, AppError> {
        let mut tx = self.pool().begin().await?;
        let sql = format!(
            "INSERT INTO admin_sessions \
             (id, admin_key_id, pubkey, refresh_token_hash, access_jti, device_info, ip_address, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING {COLS}"
        );
        let row = sqlx::query_as::<_, AdminSession>(&sql)
            .bind(session.id)
            .bind(session.admin_key_id)
            .bind(&session.pubkey)
            .bind(&session.refresh_token_hash)
            .bind(&session.access_jti)
            .bind(&session.device_info)
            .bind(session.ip_address)
            .bind(session.expires_at)
            .fetch_one(&mut *tx)
            .await?;
        self.append_admin_audit(&mut tx, audit, secret).await?;
        tx.commit().await?;
        Ok(row)
    }

    /// The live session whose access token carries `jti` (not revoked/expired).
    #[instrument(skip(self, jti))]
    pub async fn find_active_admin_session_by_jti(
        &self,
        jti: &str,
    ) -> Result<Option<AdminSession>, AppError> {
        let sql = format!(
            "SELECT {COLS} FROM admin_sessions \
             WHERE access_jti = $1 AND revoked_at IS NULL AND expires_at > NOW()"
        );
        let s = sqlx::query_as::<_, AdminSession>(&sql)
            .bind(jti)
            .fetch_optional(self.pool())
            .await?;
        Ok(s)
    }

    /// The live session with this id (used by the refresh path).
    #[instrument(skip(self))]
    pub async fn find_active_admin_session_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<AdminSession>, AppError> {
        let sql = format!(
            "SELECT {COLS} FROM admin_sessions \
             WHERE id = $1 AND revoked_at IS NULL AND expires_at > NOW()"
        );
        let s = sqlx::query_as::<_, AdminSession>(&sql)
            .bind(id)
            .fetch_optional(self.pool())
            .await?;
        Ok(s)
    }

    /// Rotate the access `jti` on refresh (the old access token stops matching).
    /// Returns the updated row, or `None` if the session is no longer live.
    #[instrument(skip(self, new_jti))]
    pub async fn rotate_admin_session_jti(
        &self,
        id: Uuid,
        new_jti: &str,
    ) -> Result<Option<AdminSession>, AppError> {
        let sql = format!(
            "UPDATE admin_sessions SET access_jti = $2 \
             WHERE id = $1 AND revoked_at IS NULL AND expires_at > NOW() RETURNING {COLS}"
        );
        let s = sqlx::query_as::<_, AdminSession>(&sql)
            .bind(id)
            .bind(new_jti)
            .fetch_optional(self.pool())
            .await?;
        Ok(s)
    }

    /// Revoke a single session (logout). Returns true if a live row was revoked.
    #[instrument(skip(self))]
    pub async fn revoke_admin_session(&self, id: Uuid) -> Result<bool, AppError> {
        let res = sqlx::query(
            "UPDATE admin_sessions SET revoked_at = NOW() \
             WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(id)
        .execute(self.pool())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Revoke every live session owned by an admin key (key-revocation cascade).
    /// Returns the number revoked.
    #[instrument(skip(self))]
    pub async fn revoke_admin_sessions_for_key(&self, admin_key_id: Uuid) -> Result<u64, AppError> {
        let res = sqlx::query(
            "UPDATE admin_sessions SET revoked_at = NOW() \
             WHERE admin_key_id = $1 AND revoked_at IS NULL",
        )
        .bind(admin_key_id)
        .execute(self.pool())
        .await?;
        Ok(res.rows_affected())
    }

    /// Delete expired/revoked admin sessions older than now (hygiene sweep).
    #[instrument(skip(self))]
    pub async fn delete_dead_admin_sessions(&self) -> Result<u64, AppError> {
        let res = sqlx::query(
            "DELETE FROM admin_sessions WHERE expires_at <= NOW() OR revoked_at IS NOT NULL",
        )
        .execute(self.pool())
        .await?;
        Ok(res.rows_affected())
    }
}
