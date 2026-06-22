//! User queries.
//!
//! Identity is Nostr-native: `pubkey_hash` and `seed_fingerprint` are peppered
//! inside these methods before they touch a column, so callers pass plaintext
//! and the at-rest values are non-reproducible without the server pepper.
//! Explicit column lists (no `SELECT *`) keep the hot auth lookups lean.

use tracing::instrument;
use uuid::Uuid;

use crate::error::AppError;
use crate::models::db::{NewUser, User};

use super::Database;

/// Explicit `users` columns (matches `User` field names; FromRow maps by name).
const USER_COLS: &str = "id, username, pubkey_hash, nostr_pubkey, wallet_birthday, \
     seed_fingerprint, xmr_start_height, wow_start_height, created_at, updated_at, last_seen_at";

impl Database {
    /// Create a new user. `pubkey_hash` / `seed_fingerprint` are peppered here.
    #[instrument(skip(self, input))]
    pub async fn create_user(&self, input: NewUser) -> Result<User, AppError> {
        let pubkey_hash = input
            .pubkey_hash
            .as_deref()
            .map(|v| self.pepper("pubkey_hash", v));
        let seed_fingerprint = input
            .seed_fingerprint
            .as_deref()
            .map(|v| self.pepper("seed_fingerprint", v));

        let sql = format!(
            "INSERT INTO users \
             (username, pubkey_hash, nostr_pubkey, wallet_birthday, seed_fingerprint, \
              xmr_start_height, wow_start_height) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {USER_COLS}"
        );
        let user = sqlx::query_as::<_, User>(&sql)
            .bind(&input.username)
            .bind(&pubkey_hash)
            .bind(&input.nostr_pubkey)
            .bind(input.wallet_birthday)
            .bind(&seed_fingerprint)
            .bind(input.xmr_start_height)
            .bind(input.wow_start_height)
            .fetch_one(self.pool())
            .await?;
        Ok(user)
    }

    #[instrument(skip(self))]
    pub async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>, AppError> {
        let sql = format!("SELECT {USER_COLS} FROM users WHERE id = $1");
        Ok(sqlx::query_as::<_, User>(&sql)
            .bind(id)
            .fetch_optional(self.pool())
            .await?)
    }

    /// Alias for [`Database::get_user_by_id`].
    pub async fn get_user(&self, user_id: Uuid) -> Result<Option<User>, AppError> {
        self.get_user_by_id(user_id).await
    }

    /// Look up by the wallet identity pubkey hash (peppered).
    #[instrument(skip(self, pubkey_hash))]
    pub async fn get_user_by_pubkey_hash(
        &self,
        pubkey_hash: &str,
    ) -> Result<Option<User>, AppError> {
        let peppered = self.pepper("pubkey_hash", pubkey_hash);
        let sql = format!("SELECT {USER_COLS} FROM users WHERE pubkey_hash = $1");
        Ok(sqlx::query_as::<_, User>(&sql)
            .bind(peppered)
            .fetch_optional(self.pool())
            .await?)
    }

    /// Look up by seed fingerprint (peppered) for restore validation.
    #[instrument(skip(self, fingerprint))]
    pub async fn get_user_by_seed_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<Option<User>, AppError> {
        let peppered = self.pepper("seed_fingerprint", fingerprint);
        let sql = format!("SELECT {USER_COLS} FROM users WHERE seed_fingerprint = $1");
        Ok(sqlx::query_as::<_, User>(&sql)
            .bind(peppered)
            .fetch_optional(self.pool())
            .await?)
    }

    #[instrument(skip(self))]
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, AppError> {
        let sql = format!("SELECT {USER_COLS} FROM users WHERE username = $1");
        Ok(sqlx::query_as::<_, User>(&sql)
            .bind(username)
            .fetch_optional(self.pool())
            .await?)
    }

    /// Find a user by their linked Nostr pubkey (x-only hex; not peppered — it is
    /// public and discoverable via NIP-05). `None` if unlinked.
    #[instrument(skip(self))]
    pub async fn find_user_by_nostr_pubkey(
        &self,
        nostr_pubkey: &str,
    ) -> Result<Option<User>, AppError> {
        let sql = format!("SELECT {USER_COLS} FROM users WHERE nostr_pubkey = $1");
        Ok(sqlx::query_as::<_, User>(&sql)
            .bind(nostr_pubkey)
            .fetch_optional(self.pool())
            .await?)
    }

    /// Replace a user's `pubkey_hash` (derivation-scheme rotation, keyed by the
    /// unchanged `seed_fingerprint`). Peppered.
    #[instrument(skip(self, new_pubkey_hash))]
    pub async fn update_pubkey_hash(
        &self,
        user_id: Uuid,
        new_pubkey_hash: &str,
    ) -> Result<(), AppError> {
        let peppered = self.pepper("pubkey_hash", new_pubkey_hash);
        sqlx::query("UPDATE users SET pubkey_hash = $1, updated_at = NOW() WHERE id = $2")
            .bind(peppered)
            .bind(user_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Link a Nostr pubkey to a user (NIP-98 sign-in). The UNIQUE constraint is
    /// the atomic claim; a collision surfaces as 409 CONFLICT.
    #[instrument(skip(self))]
    pub async fn set_nostr_pubkey(
        &self,
        user_id: Uuid,
        nostr_pubkey: &str,
    ) -> Result<(), AppError> {
        sqlx::query("UPDATE users SET nostr_pubkey = $2, updated_at = NOW() WHERE id = $1")
            .bind(user_id)
            .bind(nostr_pubkey)
            .execute(self.pool())
            .await
            .map_err(unique_violation_as(
                "That Nostr identity is already linked to another account",
            ))?;
        Ok(())
    }

    /// Get or create a user by pubkey hash (extension registration). For an
    /// existing user, backfills only NULL `wallet_birthday` / `seed_fingerprint`
    /// / chain start-heights; never overwrites an existing value.
    #[instrument(skip(self, pubkey_hash, seed_fingerprint))]
    pub async fn get_or_create_user_by_pubkey_hash(
        &self,
        pubkey_hash: &str,
        username: Option<String>,
        wallet_birthday: Option<chrono::DateTime<chrono::Utc>>,
        seed_fingerprint: Option<String>,
        xmr_start_height: Option<i64>,
        wow_start_height: Option<i64>,
    ) -> Result<User, AppError> {
        if let Some(existing) = self.get_user_by_pubkey_hash(pubkey_hash).await? {
            let needs = existing.wallet_birthday.is_none() && wallet_birthday.is_some()
                || existing.seed_fingerprint.is_none() && seed_fingerprint.is_some()
                || existing.xmr_start_height.is_none() && xmr_start_height.is_some()
                || existing.wow_start_height.is_none() && wow_start_height.is_some();
            if !needs {
                return Ok(existing);
            }

            let peppered_fp = seed_fingerprint
                .as_deref()
                .map(|v| self.pepper("seed_fingerprint", v));
            let sql = format!(
                "UPDATE users SET \
                   wallet_birthday  = COALESCE(wallet_birthday, $2), \
                   seed_fingerprint = COALESCE(seed_fingerprint, $3), \
                   xmr_start_height = COALESCE(xmr_start_height, $4), \
                   wow_start_height = COALESCE(wow_start_height, $5), \
                   updated_at = NOW() \
                 WHERE id = $1 RETURNING {USER_COLS}"
            );
            let updated = sqlx::query_as::<_, User>(&sql)
                .bind(existing.id)
                .bind(wallet_birthday)
                .bind(peppered_fp)
                .bind(xmr_start_height)
                .bind(wow_start_height)
                .fetch_one(self.pool())
                .await?;
            return Ok(updated);
        }

        self.create_user(NewUser {
            username,
            pubkey_hash: Some(pubkey_hash.to_string()),
            nostr_pubkey: None,
            wallet_birthday,
            seed_fingerprint,
            xmr_start_height,
            wow_start_height,
        })
        .await
    }

    /// Update a user's username. UNIQUE collision -> 409 CONFLICT.
    #[instrument(skip(self))]
    pub async fn update_username(
        &self,
        user_id: Uuid,
        username: Option<String>,
    ) -> Result<User, AppError> {
        let sql = format!("UPDATE users SET username = $2, updated_at = NOW() WHERE id = $1 RETURNING {USER_COLS}");
        let user = sqlx::query_as::<_, User>(&sql)
            .bind(user_id)
            .bind(&username)
            .fetch_one(self.pool())
            .await
            .map_err(unique_violation_as("That username is not available"))?;
        Ok(user)
    }

    /// Set a user's username (non-null convenience wrapper).
    pub async fn set_username(&self, user_id: Uuid, username: &str) -> Result<User, AppError> {
        self.update_username(user_id, Some(username.to_string()))
            .await
    }

    #[instrument(skip(self))]
    pub async fn update_user_last_seen(&self, user_id: Uuid) -> Result<(), AppError> {
        sqlx::query("UPDATE users SET last_seen_at = NOW() WHERE id = $1")
            .bind(user_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Count registered wallets (users with a pubkey_hash).
    #[instrument(skip(self))]
    pub async fn get_user_count(&self) -> Result<i64, AppError> {
        Ok(
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE pubkey_hash IS NOT NULL")
                .fetch_one(self.pool())
                .await?,
        )
    }
}

/// Map a unique-constraint violation to a 409 CONFLICT with `msg`; pass other
/// errors through.
fn unique_violation_as(msg: &'static str) -> impl Fn(sqlx::Error) -> AppError {
    move |e| match &e {
        sqlx::Error::Database(db_err) if db_err.is_unique_violation() => {
            AppError::Conflict(msg.to_string())
        }
        _ => AppError::from(e),
    }
}
