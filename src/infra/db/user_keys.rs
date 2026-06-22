//! User key queries.
//!
//! Per-asset public keys let others send to a user. Each `(user_id, asset,
//! key_type)` is unique; upserts replace the public material in place.
//! Explicit column lists (no `SELECT *`) keep the row shape stable.

use tracing::instrument;
use uuid::Uuid;

use crate::error::AppError;
use crate::models::db::{AssetType, NewUserKey, UserKey};

use super::Database;

/// Explicit `user_keys` columns (matches `UserKey` field names; FromRow maps by name).
const USER_KEY_COLS: &str =
    "id, user_id, asset, public_key, public_spend_key, key_type, created_at, updated_at";

impl Database {
    /// Create or update a user's public key for an asset. The UNIQUE
    /// `(user_id, asset, key_type)` constraint drives the upsert.
    #[instrument(skip(self, input), fields(user_id = %input.user_id, asset = %input.asset))]
    pub async fn upsert_user_key(&self, input: NewUserKey) -> Result<UserKey, AppError> {
        let sql = format!(
            "INSERT INTO user_keys (user_id, asset, public_key, public_spend_key, key_type) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (user_id, asset, key_type) DO UPDATE SET \
                public_key = EXCLUDED.public_key, \
                public_spend_key = EXCLUDED.public_spend_key, \
                updated_at = NOW() \
             RETURNING {USER_KEY_COLS}"
        );
        let key = sqlx::query_as::<_, UserKey>(&sql)
            .bind(input.user_id)
            .bind(input.asset)
            .bind(&input.public_key)
            .bind(&input.public_spend_key)
            .bind(&input.key_type)
            .fetch_one(self.pool())
            .await?;
        Ok(key)
    }

    /// List all of a user's keys, ordered by asset.
    #[instrument(skip(self))]
    pub async fn get_user_keys(&self, user_id: Uuid) -> Result<Vec<UserKey>, AppError> {
        let sql =
            format!("SELECT {USER_KEY_COLS} FROM user_keys WHERE user_id = $1 ORDER BY asset");
        let keys = sqlx::query_as::<_, UserKey>(&sql)
            .bind(user_id)
            .fetch_all(self.pool())
            .await?;
        Ok(keys)
    }

    /// Fetch a user's primary key for an asset.
    #[instrument(skip(self))]
    pub async fn get_user_key(
        &self,
        user_id: Uuid,
        asset: AssetType,
    ) -> Result<Option<UserKey>, AppError> {
        let sql = format!(
            "SELECT {USER_KEY_COLS} FROM user_keys \
             WHERE user_id = $1 AND asset = $2 AND key_type = 'primary'"
        );
        let key = sqlx::query_as::<_, UserKey>(&sql)
            .bind(user_id)
            .bind(asset)
            .fetch_optional(self.pool())
            .await?;
        Ok(key)
    }

    /// Delete a user's primary key for an asset. Returns `true` if a row was removed.
    #[instrument(skip(self))]
    pub async fn delete_user_key(&self, user_id: Uuid, asset: AssetType) -> Result<bool, AppError> {
        let result = sqlx::query(
            "DELETE FROM user_keys WHERE user_id = $1 AND asset = $2 AND key_type = 'primary'",
        )
        .bind(user_id)
        .bind(asset)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected() > 0)
    }
}
