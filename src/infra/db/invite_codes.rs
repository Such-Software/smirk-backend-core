//! Registration invite-code queries — one of the composable registration gates.
//!
//! Single-use, operator-minted. Only `sha256(code)` is stored (the raw code is a
//! bearer secret, shown once at mint time). Redemption is an atomic
//! single-statement claim (`UPDATE ... WHERE used_at IS NULL ... RETURNING`) so
//! two concurrent registrations presenting the same code can never both succeed.

use chrono::{DateTime, Utc};
use tracing::instrument;
use uuid::Uuid;

use crate::core::invite::{generate_invite_code, hash_invite_code};
use crate::error::AppError;
use crate::models::db::NewAdminAudit;

use super::Database;

/// A row of the invite-code table for the admin console. Never carries a usable raw
/// code (only the hash prefix is exposed by the handler).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InviteCodeRow {
    pub code_hash: String,
    pub created_at: DateTime<Utc>,
    pub label: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub used_at: Option<DateTime<Utc>>,
    pub used_by: Option<Uuid>,
}

impl Database {
    /// Store a freshly-minted code by its `sha256` hash with an optional operator
    /// `label`. A duplicate hash (re-mint of the same raw code — astronomically
    /// unlikely for a 128-bit code) surfaces as a unique-violation error.
    #[instrument(skip(self, code_hash))]
    pub async fn insert_invite_code(
        &self,
        code_hash: &str,
        label: Option<&str>,
    ) -> Result<(), AppError> {
        sqlx::query("INSERT INTO invite_codes (code_hash, label) VALUES ($1, $2)")
            .bind(code_hash)
            .bind(label)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Atomically redeem a single-use code by its hash. Returns `true` iff a
    /// still-unused, unexpired code was consumed by THIS call. The
    /// `WHERE used_at IS NULL` predicate and `RETURNING` make check-and-consume a
    /// single statement, so concurrent redemptions race safely — exactly one wins.
    #[instrument(skip(self, code_hash))]
    pub async fn claim_invite_code(&self, code_hash: &str) -> Result<bool, AppError> {
        let claimed = sqlx::query_scalar::<_, String>(
            "UPDATE invite_codes SET used_at = NOW() \
             WHERE code_hash = $1 AND used_at IS NULL \
               AND (expires_at IS NULL OR expires_at > NOW()) \
             RETURNING code_hash",
        )
        .bind(code_hash)
        .fetch_optional(self.pool())
        .await?;
        Ok(claimed.is_some())
    }

    /// Count of still-spendable (unused, unexpired) codes — for `smirk-admin doctor`.
    #[instrument(skip(self))]
    pub async fn unused_invite_code_count(&self) -> Result<i64, AppError> {
        Ok(sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM invite_codes \
             WHERE used_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())",
        )
        .fetch_one(self.pool())
        .await?)
    }

    /// List invite codes newest-first (admin console). Never returns raw codes — the
    /// handler exposes only a hash prefix + status.
    pub async fn list_invite_codes(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<InviteCodeRow>, AppError> {
        Ok(sqlx::query_as::<_, InviteCodeRow>(
            "SELECT code_hash, created_at, label, expires_at, used_at, used_by \
             FROM invite_codes ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool())
        .await?)
    }

    /// Mint `count` single-use invite codes + append one audit entry in a single tx.
    /// Returns the RAW codes (bearer secrets, shown once — only the hash is stored).
    #[instrument(skip(self, audit, secret))]
    pub async fn mint_invites_audited(
        &self,
        count: u32,
        label: Option<&str>,
        audit: &NewAdminAudit,
        secret: &str,
    ) -> Result<Vec<String>, AppError> {
        let mut tx = self.pool().begin().await?;
        let mut codes = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let code = generate_invite_code();
            sqlx::query("INSERT INTO invite_codes (code_hash, label) VALUES ($1, $2)")
                .bind(hash_invite_code(&code))
                .bind(label)
                .execute(&mut *tx)
                .await?;
            codes.push(code);
        }
        self.append_admin_audit(&mut *tx, audit, secret).await?;
        tx.commit().await?;
        Ok(codes)
    }
}
