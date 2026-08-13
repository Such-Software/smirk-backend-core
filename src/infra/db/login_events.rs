//! Login event analytics.
//!
//! Privacy-minded: no client IP is stored here at all. The salted `ip_hash` this
//! table used to carry was never read by anything (the per-IP governor is
//! in-memory and the restore limiter keys on `restore_attempts.ip_hash`), so it
//! was retained personal data with no purpose; [`Database::run_retention_sweep`]
//! also NULLs any values earlier builds wrote. Rows carry a soft FK to the user
//! so they can be purged on erasure, and the sweep ages the rest out.

use std::sync::atomic::{AtomicBool, Ordering};

use sqlx::FromRow;
use tracing::instrument;
use uuid::Uuid;

use crate::error::AppError;

use super::Database;

/// Ceiling on a configured retention window, in days (~2700 years). A nonsense
/// operator value must widen the window, never push `NOW() - interval` out of
/// the timestamp range, which would abort the sweep instead of keeping rows.
const MAX_RETENTION_DAYS: u64 = 1_000_000;

/// Latched once the legacy `ip_hash` scrub has nothing left to do, so a converged
/// deployment stops paying for a scan of an unindexed column every tick.
static IP_HASH_SCRUB_DONE: AtomicBool = AtomicBool::new(false);

/// Days as the `int` `make_interval` wants, saturating rather than wrapping.
fn interval_days(days: u64) -> i32 {
    days.min(MAX_RETENTION_DAYS) as i32
}

/// Aggregated login stats (analytics / optional public landing).
#[derive(Debug, FromRow)]
pub struct LoginStats {
    pub asset: String,
    pub platform: String,
    pub login_count: i64,
    pub unique_users: i64,
}

impl Database {
    /// Record a login event.
    ///
    /// `_ip` is accepted and deliberately dropped: the sign-in call sites already
    /// hold the peer address, but nothing ever consumed the hash this used to
    /// store, and an unread per-user IP hash is retention without a purpose.
    /// Abuse control that does need an IP reads `restore_attempts.ip_hash` or the
    /// in-memory governor.
    #[instrument(skip(self, origin, _ip))]
    pub async fn record_login_event(
        &self,
        user_id: Option<Uuid>,
        asset: &str,
        platform: &str,
        origin: Option<&str>,
        _ip: Option<&str>,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO login_events (user_id, asset, platform, origin) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(user_id)
        .bind(asset)
        .bind(platform)
        .bind(origin)
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

    /// Retention: delete login events older than `days`, at most `batch` per call.
    ///
    /// `days == 0` means keep forever and a non-positive `batch` is likewise a
    /// no-op: an absent or zero operator setting must never be read as "delete
    /// everything", so both directions fail towards keeping data. The bound
    /// matters because the table is unpartitioned: one unbounded DELETE over a
    /// year of backlog would hold row locks for the whole pass.
    #[instrument(skip(self))]
    pub async fn cleanup_old_login_events(&self, days: u64, batch: i64) -> Result<u64, AppError> {
        if days == 0 || batch <= 0 {
            return Ok(0);
        }
        let result = sqlx::query(
            "DELETE FROM login_events WHERE id IN ( \
                 SELECT id FROM login_events \
                 WHERE created_at < NOW() - make_interval(days => $1) \
                 ORDER BY created_at LIMIT $2 FOR UPDATE SKIP LOCKED)",
        )
        .bind(interval_days(days))
        .bind(batch)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }

    /// Retention: delete `audit_logs` rows older than `days`, same bounds and same
    /// keep-forever-on-zero rule as the login sweep.
    ///
    /// Deliberately NOT `admin_audit_logs`: that is a MAC'd hash chain whose
    /// verifier walks every row, so a deletion there is indistinguishable from
    /// tampering. Operator forensics is a separate policy from user retention.
    #[instrument(skip(self))]
    pub async fn cleanup_old_audit_logs(&self, days: u64, batch: i64) -> Result<u64, AppError> {
        if days == 0 || batch <= 0 {
            return Ok(0);
        }
        let result = sqlx::query(
            "DELETE FROM audit_logs WHERE id IN ( \
                 SELECT id FROM audit_logs \
                 WHERE created_at < NOW() - make_interval(days => $1) \
                 ORDER BY created_at LIMIT $2 FOR UPDATE SKIP LOCKED)",
        )
        .bind(interval_days(days))
        .bind(batch)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }

    /// NULL any `ip_hash` left by builds that still wrote one, `batch` rows per
    /// call. Covers rows the anonymizing erasure branch leaves behind too: it
    /// clears `user_id`/`origin`/`asset` but not this column. Unconditional
    /// (not retention-gated), because with retention set to keep-forever those
    /// hashes would otherwise never go away.
    #[instrument(skip(self))]
    pub async fn scrub_legacy_login_ip_hashes(&self, batch: i64) -> Result<u64, AppError> {
        if batch <= 0 || IP_HASH_SCRUB_DONE.load(Ordering::Relaxed) {
            return Ok(0);
        }
        let result = sqlx::query(
            "UPDATE login_events SET ip_hash = NULL WHERE id IN ( \
                 SELECT id FROM login_events WHERE ip_hash IS NOT NULL LIMIT $1)",
        )
        .bind(batch)
        .execute(self.pool())
        .await?;
        let scrubbed = result.rows_affected();
        // Short of a full batch means the LIMIT was never reached, so nothing is
        // left to scrub and later passes can skip the scan.
        if scrubbed < batch as u64 {
            IP_HASH_SCRUB_DONE.store(true, Ordering::Relaxed);
        }
        Ok(scrubbed)
    }

    /// One retention pass: age out `login_events` and `audit_logs` per the
    /// operator's configured windows, then scrub any legacy `ip_hash`. Returns the
    /// rows deleted, for the caller to log.
    ///
    /// Each statement is capped at `batch` rows, so a backlog drains over
    /// successive ticks instead of in one long-running lock. An error aborts the
    /// pass and is reported to the caller, which retries on the next tick.
    #[instrument(skip(self))]
    pub async fn run_retention_sweep(
        &self,
        login_events_days: u64,
        audit_days: u64,
        batch: i64,
    ) -> Result<u64, AppError> {
        let logins = self
            .cleanup_old_login_events(login_events_days, batch)
            .await?;
        let audits = self.cleanup_old_audit_logs(audit_days, batch).await?;
        let scrubbed = self.scrub_legacy_login_ip_hashes(batch).await?;
        if scrubbed > 0 {
            tracing::info!(rows = scrubbed, "scrubbed legacy login_events.ip_hash");
        }
        Ok(logins + audits)
    }
}

#[cfg(test)]
mod tests {
    use super::interval_days;

    #[test]
    fn interval_days_saturates_instead_of_wrapping() {
        assert_eq!(interval_days(0), 0);
        assert_eq!(interval_days(90), 90);
        // A nonsense-large window must clamp to something Postgres can subtract
        // from NOW(), never wrap negative (which would delete everything).
        assert_eq!(interval_days(u64::MAX), 1_000_000);
    }
}
