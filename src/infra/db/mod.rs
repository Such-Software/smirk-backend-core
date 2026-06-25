//! Database access layer.
//!
//! `Database` wraps the connection pool and the secrets needed to pepper
//! identity values at rest. Per-entity query methods are implemented on it in
//! sibling modules (`users`, ...). Identity values (`pubkey_hash`,
//! `seed_fingerprint`) are peppered inside these methods so the plaintext never
//! reaches a column and the peppering cannot drift between call sites.

mod admin_keys;
mod audit;
mod challenges;
mod grin_slatepacks;
mod login_events;
mod restore_attempts;
mod sessions;
mod user_keys;
mod users;

pub use challenges::ConsumedChallenge;
pub use login_events::LoginStats;

use sqlx::PgPool;

use crate::core::crypto::pepper::peppered_hex;
use crate::error::AppError;

/// Connection pool + at-rest peppering secrets. Does not derive `Debug`.
#[derive(Clone)]
pub struct Database {
    pool: PgPool,
    /// HMAC pepper for identity columns (pubkey_hash, seed_fingerprint).
    identity_pepper: String,
    /// Salt for hashing client IPs in analytics/abuse tables.
    ip_salt: String,
}

impl Database {
    pub fn new(pool: PgPool, identity_pepper: String, ip_salt: String) -> Self {
        Self {
            pool,
            identity_pepper,
            ip_salt,
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Salted hash of a client IP for analytics/abuse tables (never store raw).
    pub(crate) fn hash_ip(&self, ip: &str) -> String {
        peppered_hex(&self.ip_salt, "ip", ip)
    }

    /// Pepper an identity value for storage/lookup (see [`peppered_hex`]).
    fn pepper(&self, domain: &str, value: &str) -> String {
        peppered_hex(&self.identity_pepper, domain, value)
    }

    /// Liveness check against the database.
    pub async fn health_check(&self) -> Result<bool, AppError> {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await?;
        Ok(true)
    }
}

/// Map a unique-constraint violation to a 409 CONFLICT with `msg`; pass other
/// errors through. Shared by the entity query modules.
pub(crate) fn unique_violation_as(msg: &'static str) -> impl Fn(sqlx::Error) -> AppError {
    move |e| match &e {
        sqlx::Error::Database(db_err) if db_err.is_unique_violation() => {
            AppError::Conflict(msg.to_string())
        }
        _ => AppError::from(e),
    }
}
