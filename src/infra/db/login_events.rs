//! Login event analytics.
//!
//! Privacy-minded: the client IP is stored only as a salted hash (via
//! [`Database::hash_ip`]), never raw. Rows carry a soft FK to the user so they
//! can be purged on erasure; a retention sweep removes old rows.

use sqlx::FromRow;
use tracing::instrument;
use uuid::Uuid;

use crate::error::AppError;

use super::Database;

/// Aggregated login stats (analytics / optional public landing).
#[derive(Debug, FromRow)]
pub struct LoginStats {
    pub asset: String,
    pub platform: String,
    pub login_count: i64,
    pub unique_users: i64,
}

impl Database {
    /// Record a login event. `ip` is the raw client IP; it is salted-hashed here.
    #[instrument(skip(self, origin, ip))]
    pub async fn record_login_event(
        &self,
        user_id: Option<Uuid>,
        asset: &str,
        platform: &str,
        origin: Option<&str>,
        ip: Option<&str>,
    ) -> Result<(), AppError> {
        let ip_hash = ip.map(|v| self.hash_ip(v));
        sqlx::query(
            "INSERT INTO login_events (user_id, asset, platform, origin, ip_hash) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(user_id)
        .bind(asset)
        .bind(platform)
        .bind(origin)
        .bind(ip_hash)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Login counts grouped by asset + platform over the last `days`.
    #[instrument(skip(self))]
    pub async fn get_login_counts_recent(&self, days: i32) -> Result<Vec<LoginStats>, AppError> {
        let stats = sqlx::query_as::<_, LoginStats>(
            "SELECT asset, platform, COUNT(*) AS login_count, \
                    COUNT(DISTINCT user_id) AS unique_users \
             FROM login_events \
             WHERE created_at > NOW() - INTERVAL '1 day' * $1 \
             GROUP BY asset, platform \
             ORDER BY login_count DESC",
        )
        .bind(days)
        .fetch_all(self.pool())
        .await?;
        Ok(stats)
    }

    /// Erasure: purge a user's login events (default per the erasure policy).
    #[instrument(skip(self))]
    pub async fn delete_login_events_for_user(&self, user_id: Uuid) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM login_events WHERE user_id = $1")
            .bind(user_id)
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected())
    }

    /// Retention sweep: delete events older than `days`.
    #[instrument(skip(self))]
    pub async fn cleanup_old_login_events(&self, days: i32) -> Result<u64, AppError> {
        let result = sqlx::query(
            "DELETE FROM login_events WHERE created_at < NOW() - INTERVAL '1 day' * $1",
        )
        .bind(days)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }
}
