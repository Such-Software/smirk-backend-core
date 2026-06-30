//! Registration invite-code queries — one of the composable registration gates.
//!
//! Single-use, operator-minted. Only `sha256(code)` is stored (the raw code is a
//! bearer secret, shown once at mint time). Redemption is an atomic
//! single-statement claim (`UPDATE ... WHERE used_at IS NULL ... RETURNING`) so
//! two concurrent registrations presenting the same code can never both succeed.

use tracing::instrument;

use crate::error::AppError;

use super::Database;

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
}
