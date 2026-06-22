//! Database access layer.
//!
//! `Database` wraps the connection pool and the secrets needed to pepper
//! identity values at rest. Per-entity query methods are implemented on it in
//! sibling modules (`users`, ...). Identity values (`pubkey_hash`,
//! `seed_fingerprint`) are peppered inside these methods so the plaintext never
//! reaches a column and the peppering cannot drift between call sites.

mod users;

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

    /// Salt for IP hashing (used by login_events / restore_attempts).
    pub fn ip_salt(&self) -> &str {
        &self.ip_salt
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
