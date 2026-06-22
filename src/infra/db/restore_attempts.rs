//! Restore-attempt tracking for abuse prevention.
//!
//! Both the seed fingerprint and the client IP are stored only as keyed hashes
//! (peppered fingerprint, salted IP), never raw — so this abuse-evidence table
//! is not itself a seed-existence oracle or an IP log. A retention sweep ages
//! rows out.

use tracing::instrument;

use crate::error::AppError;

use super::Database;

impl Database {
    /// Record a restore attempt. `fingerprint` and `ip` are raw; both are
    /// keyed-hashed here before storage.
    #[instrument(skip(self, fingerprint, ip))]
    pub async fn record_restore_attempt(
        &self,
        fingerprint: &str,
        ip: Option<&str>,
        success: bool,
    ) -> Result<(), AppError> {
        let fp = self.pepper("restore_fingerprint", fingerprint);
        let ip_hash = ip.map(|v| self.hash_ip(v));
        sqlx::query(
            "INSERT INTO restore_attempts (fingerprint, ip_hash, success) VALUES ($1, $2, $3)",
        )
        .bind(fp)
        .bind(ip_hash)
        .bind(success)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Failed restore attempts for a fingerprint in the last hour.
    #[instrument(skip(self, fingerprint))]
    pub async fn count_failed_restore_attempts(&self, fingerprint: &str) -> Result<i64, AppError> {
        let fp = self.pepper("restore_fingerprint", fingerprint);
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM restore_attempts \
             WHERE fingerprint = $1 AND success = FALSE \
               AND created_at > NOW() - INTERVAL '1 hour'",
        )
        .bind(fp)
        .fetch_one(self.pool())
        .await?;
        Ok(count)
    }

    /// All restore attempts from an IP in the last hour.
    #[instrument(skip(self, ip))]
    pub async fn count_ip_restore_attempts(&self, ip: &str) -> Result<i64, AppError> {
        let ip_hash = self.hash_ip(ip);
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM restore_attempts \
             WHERE ip_hash = $1 AND created_at > NOW() - INTERVAL '1 hour'",
        )
        .bind(ip_hash)
        .fetch_one(self.pool())
        .await?;
        Ok(count)
    }

    /// Retention sweep: delete attempts older than 7 days.
    #[instrument(skip(self))]
    pub async fn cleanup_old_restore_attempts(&self) -> Result<u64, AppError> {
        let result = sqlx::query(
            "DELETE FROM restore_attempts WHERE created_at < NOW() - INTERVAL '7 days'",
        )
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }
}
