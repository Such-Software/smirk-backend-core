//! Admin allowlist queries.
//!
//! Every read of an active key re-verifies its integrity MAC, and every write
//! that changes a covered field recomputes it, so MAC handling cannot drift or
//! be forgotten by a caller. A MAC mismatch on read is treated as "not
//! authorized" (fail-closed) and logged as tamper evidence. Timestamps bound by
//! the MAC are truncated to microseconds (Postgres' resolution) so the value
//! signed at write equals the value read back.

use chrono::{SubsecRound, Utc};
use tracing::instrument;
use uuid::Uuid;

use crate::core::crypto::admin_mac::{
    compute_admin_key_mac, verify_admin_key_mac, AdminKeyMacInput,
};
use crate::error::AppError;
use crate::models::db::{AdminKey, NewAdminKey};

use super::{unique_violation_as, Database};

/// Explicit `admin_keys` columns (FromRow maps by name).
const COLS: &str = "id, pubkey, label, scope, created_at, created_by_kind, \
     activated_at, activation_deadline, revoked_at, last_used_at, integrity_mac";

fn mac_input<'a>(k: &'a AdminKey) -> AdminKeyMacInput<'a> {
    AdminKeyMacInput {
        id: k.id,
        pubkey: &k.pubkey,
        scope: &k.scope,
        created_at: k.created_at,
        activated_at: k.activated_at,
        revoked_at: k.revoked_at,
    }
}

impl Database {
    /// Add an allowlist entry (pending — `activated_at` NULL until first login).
    /// Fails 409 if an active key with this pubkey already exists.
    #[instrument(skip(self, secret))]
    pub async fn create_admin_key(
        &self,
        input: NewAdminKey,
        secret: &str,
    ) -> Result<AdminKey, AppError> {
        let id = Uuid::new_v4();
        let created_at = Utc::now().trunc_subsecs(6);
        let mac = compute_admin_key_mac(
            secret,
            &AdminKeyMacInput {
                id,
                pubkey: &input.pubkey,
                scope: &input.scope,
                created_at,
                activated_at: None,
                revoked_at: None,
            },
        );
        let sql = format!(
            "INSERT INTO admin_keys \
             (id, pubkey, label, scope, created_at, created_by_kind, activation_deadline, integrity_mac) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING {COLS}"
        );
        let key = sqlx::query_as::<_, AdminKey>(&sql)
            .bind(id)
            .bind(&input.pubkey)
            .bind(&input.label)
            .bind(&input.scope)
            .bind(created_at)
            .bind(&input.created_by_kind)
            .bind(input.activation_deadline)
            .bind(&mac)
            .fetch_one(self.pool())
            .await
            .map_err(unique_violation_as(
                "an active admin key with this pubkey already exists",
            ))?;
        Ok(key)
    }

    /// The active (non-revoked) allowlist entry for `pubkey`, IF its integrity
    /// MAC verifies. A mismatch returns `None` (fail-closed) and logs tampering.
    #[instrument(skip(self, secret))]
    pub async fn get_active_admin_key(
        &self,
        pubkey: &str,
        secret: &str,
    ) -> Result<Option<AdminKey>, AppError> {
        let sql = format!("SELECT {COLS} FROM admin_keys WHERE pubkey = $1 AND revoked_at IS NULL");
        let row = sqlx::query_as::<_, AdminKey>(&sql)
            .bind(pubkey)
            .fetch_optional(self.pool())
            .await?;
        match row {
            Some(key) if verify_admin_key_mac(secret, &mac_input(&key), &key.integrity_mac) => {
                Ok(Some(key))
            }
            Some(key) => {
                tracing::error!(
                    admin_key_id = %key.id,
                    "admin_keys integrity MAC mismatch — row tampered; rejecting"
                );
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// All allowlist entries (active, pending, revoked), newest first.
    #[instrument(skip(self))]
    pub async fn list_admin_keys(&self) -> Result<Vec<AdminKey>, AppError> {
        let sql = format!("SELECT {COLS} FROM admin_keys ORDER BY created_at DESC");
        let rows = sqlx::query_as::<_, AdminKey>(&sql)
            .fetch_all(self.pool())
            .await?;
        Ok(rows)
    }

    /// Count live (active + pending) keys — backs the `ADMIN_MAX_KEYS` cap.
    #[instrument(skip(self))]
    pub async fn count_live_admin_keys(&self) -> Result<i64, AppError> {
        let n = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM admin_keys WHERE revoked_at IS NULL",
        )
        .fetch_one(self.pool())
        .await?;
        Ok(n)
    }

    /// Bump `last_used_at` (not covered by the integrity MAC, so no recompute).
    #[instrument(skip(self))]
    pub async fn touch_admin_key_last_used(&self, id: Uuid) -> Result<(), AppError> {
        sqlx::query("UPDATE admin_keys SET last_used_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Mark a pending key activated (first successful login). Recomputes the MAC.
    /// Returns the updated row, or `None` if not pending (already active/revoked).
    #[instrument(skip(self, secret))]
    pub async fn activate_admin_key(
        &self,
        id: Uuid,
        secret: &str,
    ) -> Result<Option<AdminKey>, AppError> {
        let mut tx = self.pool().begin().await?;
        let sel = format!(
            "SELECT {COLS} FROM admin_keys \
             WHERE id = $1 AND revoked_at IS NULL AND activated_at IS NULL FOR UPDATE"
        );
        let Some(key) = sqlx::query_as::<_, AdminKey>(&sel)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
        else {
            tx.rollback().await?;
            return Ok(None);
        };
        let activated_at = Utc::now().trunc_subsecs(6);
        let mac = compute_admin_key_mac(
            secret,
            &AdminKeyMacInput {
                activated_at: Some(activated_at),
                ..mac_input(&key)
            },
        );
        let upd = format!(
            "UPDATE admin_keys SET activated_at = $2, integrity_mac = $3 WHERE id = $1 RETURNING {COLS}"
        );
        let updated = sqlx::query_as::<_, AdminKey>(&upd)
            .bind(id)
            .bind(activated_at)
            .bind(&mac)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(updated))
    }

    /// Soft-revoke a key (recomputing the MAC over the new `revoked_at`). Returns
    /// the updated row, or `None` if it was already revoked / does not exist.
    #[instrument(skip(self, secret))]
    pub async fn revoke_admin_key(
        &self,
        id: Uuid,
        secret: &str,
    ) -> Result<Option<AdminKey>, AppError> {
        let mut tx = self.pool().begin().await?;
        let sel = format!(
            "SELECT {COLS} FROM admin_keys WHERE id = $1 AND revoked_at IS NULL FOR UPDATE"
        );
        let Some(key) = sqlx::query_as::<_, AdminKey>(&sel)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
        else {
            tx.rollback().await?;
            return Ok(None);
        };
        let revoked_at = Utc::now().trunc_subsecs(6);
        let mac = compute_admin_key_mac(
            secret,
            &AdminKeyMacInput {
                revoked_at: Some(revoked_at),
                ..mac_input(&key)
            },
        );
        let upd = format!(
            "UPDATE admin_keys SET revoked_at = $2, integrity_mac = $3 WHERE id = $1 RETURNING {COLS}"
        );
        let updated = sqlx::query_as::<_, AdminKey>(&upd)
            .bind(id)
            .bind(revoked_at)
            .bind(&mac)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(updated))
    }
}
