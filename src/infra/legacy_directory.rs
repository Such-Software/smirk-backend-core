//! Read-only lookup into the legacy (v0.2.x) database, for sign-in migration.
//!
//! The two deployments do not share a database, and they never shared one. The
//! legacy instance holds 134 identities whose keys the v3 instance has never
//! seen, so pointing the website at v3 would refuse every one of them: nothing
//! in `smirk_v3_db` can match a key that only exists in `smirk_db`.
//!
//! Neither of the obvious join keys works. `users.pubkey_hash` is a plain
//! `sha256(public_key)` on legacy and an HMAC under `identity_pepper` on v3, so
//! the columns are not comparable. Usernames are worse than useless: 14 of the
//! 16 handles exist in BOTH databases while only 6 users share a raw key, so
//! merging by name would hand one person's keys to a different account.
//!
//! What IS reliable is the public key a signature just proved control of. This
//! module looks up exactly that, and only that. A caller arrives holding a
//! verified signature; we answer whether the legacy instance knows that key.
//!
//! **This capability is OFF unless a legacy URL is configured.** With no URL the
//! directory is constructed disabled, every lookup answers `None`, and sign-in
//! behaves exactly as it does today. It is meant to be switched off again once
//! the tail of legacy users has migrated, which happens on its own as each signs
//! in: the path is self-draining rather than a one-shot copy.

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use tracing::{info, instrument, warn};

use crate::error::AppError;

/// One asset key as the legacy instance stored it.
#[derive(Debug, Clone)]
pub struct LegacyKey {
    pub asset: String,
    pub public_key: String,
    pub public_spend_key: Option<String>,
}

/// A legacy identity, resolved by a key its owner just proved control of.
#[derive(Debug, Clone)]
pub struct LegacyIdentity {
    /// The handle held on the legacy instance. The caller decides whether it can
    /// be carried over; it is NOT automatically free on v3.
    pub username: Option<String>,
    /// Every asset key the legacy instance holds for this user.
    pub keys: Vec<LegacyKey>,
}

impl LegacyIdentity {
    /// This identity's key for `asset`, if the legacy instance had one.
    pub fn key_for(&self, asset: &str) -> Option<&LegacyKey> {
        self.keys.iter().find(|k| k.asset == asset)
    }
}

/// Read-only handle to the legacy database. Disabled unless configured.
#[derive(Clone)]
pub struct LegacyDirectory {
    pool: Option<PgPool>,
}

impl LegacyDirectory {
    /// An explicitly-off directory. Every lookup answers `None`.
    pub fn disabled() -> Self {
        Self { pool: None }
    }

    /// Connect when a URL is configured, otherwise stay off.
    ///
    /// A bad URL is reported and then treated as off. Sign-in migration is a
    /// transitional convenience, so it must never be able to stop the service
    /// from starting: the failure mode is "legacy users wait", not "nobody
    /// serves".
    pub async fn connect(database_url: Option<&str>) -> Self {
        let Some(url) = database_url.filter(|u| !u.trim().is_empty()) else {
            info!("legacy sign-in migration: disabled (no legacy database configured)");
            return Self::disabled();
        };

        // A small pool on purpose: this path runs once per legacy user, ever. The
        // short timeout matters because this runs during boot, and the default
        // would stall startup for 30s on a URL that points nowhere.
        match PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(url)
            .await
        {
            Ok(pool) => {
                info!("legacy sign-in migration: enabled");
                Self { pool: Some(pool) }
            }
            Err(e) => {
                warn!(error = %e, "legacy sign-in migration: could not connect, staying disabled");
                Self::disabled()
            }
        }
    }

    /// Whether lookups can resolve anything.
    pub fn is_enabled(&self) -> bool {
        self.pool.is_some()
    }

    /// Resolve the legacy identity owning `public_key` for `asset`.
    ///
    /// `public_key` must be a value whose control the caller has ALREADY proven.
    /// The match is verbatim against the stored key, so nothing is re-encoded or
    /// re-hashed on either side, and a caller cannot use this to enumerate: it
    /// answers only about a key they could already sign for.
    #[instrument(skip(self, public_key), fields(asset = %asset))]
    pub async fn find_by_proven_key(
        &self,
        asset: &str,
        public_key: &str,
    ) -> Result<Option<LegacyIdentity>, AppError> {
        let Some(pool) = self.pool.as_ref() else {
            return Ok(None);
        };

        let owner = sqlx::query(
            "SELECT u.id, u.username FROM users u \
             JOIN user_keys k ON k.user_id = u.id \
             WHERE k.asset::text = $1 AND k.public_key = $2",
        )
        .bind(asset)
        .bind(public_key)
        .fetch_optional(pool)
        .await?;

        let Some(owner) = owner else {
            return Ok(None);
        };
        let user_id: uuid::Uuid = owner.try_get("id")?;
        let username: Option<String> = owner.try_get("username")?;

        let rows = sqlx::query(
            "SELECT asset::text AS asset, public_key, public_spend_key \
             FROM user_keys WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;

        let mut keys = Vec::with_capacity(rows.len());
        for r in rows {
            keys.push(LegacyKey {
                asset: r.try_get("asset")?,
                public_key: r.try_get("public_key")?,
                public_spend_key: r.try_get("public_spend_key")?,
            });
        }

        Ok(Some(LegacyIdentity { username, keys }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The capability is closed unless it is configured open.
    #[tokio::test]
    async fn absent_configuration_leaves_the_directory_disabled() {
        for url in [None, Some(""), Some("   ")] {
            let dir = LegacyDirectory::connect(url).await;
            assert!(!dir.is_enabled(), "url {url:?} must not enable the lookup");
        }
    }

    /// A disabled directory resolves nothing, rather than erroring. Sign-in has
    /// to behave exactly as it did before the capability existed.
    #[tokio::test]
    async fn a_disabled_directory_resolves_nothing() {
        let dir = LegacyDirectory::disabled();
        let found = dir.find_by_proven_key("btc", &"a".repeat(66)).await;
        assert!(matches!(found, Ok(None)));
    }

    /// An unreachable legacy database degrades to "off", never to a failed boot.
    #[tokio::test]
    async fn an_unreachable_database_degrades_to_disabled() {
        // Port 1 is reserved and nothing listens there.
        let dir = LegacyDirectory::connect(Some("postgres://u:p@127.0.0.1:1/nope")).await;
        assert!(!dir.is_enabled());
    }

    #[test]
    fn key_for_selects_by_asset() {
        let id = LegacyIdentity {
            username: None,
            keys: vec![
                LegacyKey {
                    asset: "btc".into(),
                    public_key: "bb".into(),
                    public_spend_key: None,
                },
                LegacyKey {
                    asset: "xmr".into(),
                    public_key: "xx".into(),
                    public_spend_key: Some("ss".into()),
                },
            ],
        };
        assert_eq!(id.key_for("xmr").map(|k| k.public_key.as_str()), Some("xx"));
        assert!(id.key_for("ltc").is_none());
    }
}
