//! Admin allowlist queries.
//!
//! Every read of an active key re-verifies its integrity MAC, and every write
//! that changes a covered field recomputes it, so MAC handling cannot drift or
//! be forgotten by a caller. A MAC mismatch on read is treated as "not
//! authorized" (fail-closed) and logged as tamper evidence. Timestamps bound by
//! the MAC are truncated to microseconds (Postgres' resolution) so the value
//! signed at write equals the value read back.

use chrono::{SubsecRound, Utc};
use sqlx::PgConnection;
use tracing::instrument;
use uuid::Uuid;

use crate::core::crypto::admin_mac::{
    compute_admin_key_mac, verify_admin_key_mac, AdminKeyMacInput,
};
use crate::error::AppError;
use crate::models::db::{AdminKey, NewAdminAudit, NewAdminKey};

use super::{unique_violation_as, Database};

/// Explicit `admin_keys` columns (FromRow maps by name).
const COLS: &str = "id, pubkey, label, scope, created_at, created_by_kind, \
     activated_at, activation_deadline, revoked_at, last_used_at, integrity_mac";

/// Advisory-lock key serializing all admin-key mutations (add/revoke/rotate, and
/// bootstrap), so the count-based guards (the `ADMIN_MAX_KEYS` cap, the last-key
/// floor, the single-bootstrap guard) are evaluated and acted on atomically
/// rather than as racy check-then-mutate.
pub(crate) const ADMIN_KEYS_LOCK_KEY: i64 = 0x5311_4D17_4B59_0001;

/// Outcome of an audited key add.
pub enum AddKeyOutcome {
    Created(AdminKey),
    /// The live-key cap (`ADMIN_MAX_KEYS`) is already reached.
    CapReached,
}

/// Outcome of a network key revoke.
pub enum RevokeKeyOutcome {
    Revoked(AdminKey),
    NotFound,
    /// Refused: revoking would leave the allowlist with no live key (a lockout).
    WouldEmptyAllowlist,
}

fn mac_input<'a>(k: &'a AdminKey) -> AdminKeyMacInput<'a> {
    AdminKeyMacInput {
        id: k.id,
        pubkey: &k.pubkey,
        scope: &k.scope,
        created_at: k.created_at,
        activated_at: k.activated_at,
        activation_deadline: k.activation_deadline,
        revoked_at: k.revoked_at,
    }
}

impl Database {
    /// Add an allowlist entry (pending — `activated_at` NULL until first login).
    /// Fails 409 if an active key with this pubkey already exists.
    #[instrument(skip(self, input, secret))]
    pub async fn create_admin_key(
        &self,
        input: NewAdminKey,
        secret: &str,
    ) -> Result<AdminKey, AppError> {
        let mut conn = self.pool().acquire().await?;
        insert_admin_key(&mut conn, &input, secret).await
    }

    /// Add an allowlist entry AND append its audit row in ONE transaction, so the
    /// audit write is fail-closed (a failed audit rolls back the key creation).
    #[instrument(skip(self, input, audit, secret))]
    pub async fn create_admin_key_audited(
        &self,
        input: NewAdminKey,
        audit: &NewAdminAudit,
        secret: &str,
        max_live: i64,
    ) -> Result<AddKeyOutcome, AppError> {
        let mut tx = self.pool().begin().await?;
        admin_keys_mutate_lock(&mut tx).await?;
        // Count under the lock so the cap can't be raced by concurrent adds.
        let live = live_key_count(&mut tx).await?;
        if live >= max_live {
            tx.rollback().await?;
            return Ok(AddKeyOutcome::CapReached);
        }
        let key = insert_admin_key(&mut tx, &input, secret).await?;
        self.append_admin_audit(&mut tx, audit, secret).await?;
        tx.commit().await?;
        Ok(AddKeyOutcome::Created(key))
    }

    /// The active (non-revoked) allowlist entry for `pubkey`, IF its integrity
    /// MAC verifies. A mismatch returns `None` (fail-closed) and logs tampering.
    /// `pubkey` is skipped from the span — the surface keeps only prefixes, no
    /// full keys, in logs/audit (no social graph).
    #[instrument(skip(self, pubkey, secret))]
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

    /// Soft-revoke a key, revoke ALL its sessions, and append the audit row — all
    /// in ONE transaction (so a revoked admin's still-valid access token is
    /// rejected on its next call, and the audit is fail-closed). When
    /// `keep_min_live` is set, refuses (atomically) to revoke the last live key.
    #[instrument(skip(self, audit, secret))]
    pub async fn revoke_admin_key_full(
        &self,
        id: Uuid,
        audit: &NewAdminAudit,
        secret: &str,
        keep_min_live: bool,
    ) -> Result<RevokeKeyOutcome, AppError> {
        let mut tx = self.pool().begin().await?;
        admin_keys_mutate_lock(&mut tx).await?;
        // Floor check INSIDE the locked tx: two concurrent revokes cannot both
        // pass and empty the allowlist (a network lockout).
        if keep_min_live && live_key_count(&mut tx).await? <= 1 {
            tx.rollback().await?;
            return Ok(RevokeKeyOutcome::WouldEmptyAllowlist);
        }
        let sel = format!(
            "SELECT {COLS} FROM admin_keys WHERE id = $1 AND revoked_at IS NULL FOR UPDATE"
        );
        let Some(key) = sqlx::query_as::<_, AdminKey>(&sel)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
        else {
            tx.rollback().await?;
            return Ok(RevokeKeyOutcome::NotFound);
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
        sqlx::query(
            "UPDATE admin_sessions SET revoked_at = NOW() \
             WHERE admin_key_id = $1 AND revoked_at IS NULL",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        self.append_admin_audit(&mut tx, audit, secret).await?;
        tx.commit().await?;
        Ok(RevokeKeyOutcome::Revoked(updated))
    }

    /// Atomically rotate a key: revoke `old_id` (+ its sessions), create a fresh
    /// pending key from `new`, and audit — all in one transaction. This is the
    /// in-band recovery for a compromised solo key (add+revoke, so it never leaves
    /// the allowlist empty). Returns the new key, or `None` if `old_id` was
    /// already revoked / does not exist; 409 if the new pubkey is already active.
    #[instrument(skip(self, new, audit, secret))]
    pub async fn rotate_admin_key(
        &self,
        old_id: Uuid,
        new: NewAdminKey,
        audit: &NewAdminAudit,
        secret: &str,
    ) -> Result<Option<AdminKey>, AppError> {
        let mut tx = self.pool().begin().await?;
        admin_keys_mutate_lock(&mut tx).await?;
        let sel = format!(
            "SELECT {COLS} FROM admin_keys WHERE id = $1 AND revoked_at IS NULL FOR UPDATE"
        );
        let Some(old) = sqlx::query_as::<_, AdminKey>(&sel)
            .bind(old_id)
            .fetch_optional(&mut *tx)
            .await?
        else {
            tx.rollback().await?;
            return Ok(None);
        };
        let revoked_at = Utc::now().trunc_subsecs(6);
        let old_mac = compute_admin_key_mac(
            secret,
            &AdminKeyMacInput {
                revoked_at: Some(revoked_at),
                ..mac_input(&old)
            },
        );
        sqlx::query("UPDATE admin_keys SET revoked_at = $2, integrity_mac = $3 WHERE id = $1")
            .bind(old_id)
            .bind(revoked_at)
            .bind(&old_mac)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE admin_sessions SET revoked_at = NOW() \
             WHERE admin_key_id = $1 AND revoked_at IS NULL",
        )
        .bind(old_id)
        .execute(&mut *tx)
        .await?;
        let created = insert_admin_key(&mut tx, &new, secret).await?;
        self.append_admin_audit(&mut tx, audit, secret).await?;
        tx.commit().await?;
        Ok(Some(created))
    }
}

/// Insert a pending allowlist entry on `conn` (so it can share a caller's
/// transaction). Computes the integrity MAC over the exact stored values. 409 if
/// an active key with this pubkey already exists.
async fn insert_admin_key(
    conn: &mut PgConnection,
    input: &NewAdminKey,
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
            activation_deadline: input.activation_deadline,
            revoked_at: None,
        },
    );
    let sql = format!(
        "INSERT INTO admin_keys \
         (id, pubkey, label, scope, created_at, created_by_kind, activation_deadline, integrity_mac) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING {COLS}"
    );
    sqlx::query_as::<_, AdminKey>(&sql)
        .bind(id)
        .bind(&input.pubkey)
        .bind(&input.label)
        .bind(&input.scope)
        .bind(created_at)
        .bind(&input.created_by_kind)
        .bind(input.activation_deadline)
        .bind(&mac)
        .fetch_one(&mut *conn)
        .await
        .map_err(unique_violation_as(
            "an active admin key with this pubkey already exists",
        ))
}

/// Take the admin-keys mutation advisory lock (transaction-scoped). Serializes
/// add/revoke/rotate so the cap and last-key floor are race-free.
pub(crate) async fn admin_keys_mutate_lock(conn: &mut PgConnection) -> Result<(), AppError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ADMIN_KEYS_LOCK_KEY)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Count live (non-revoked) keys on `conn` (so it reflects the locked tx).
async fn live_key_count(conn: &mut PgConnection) -> Result<i64, AppError> {
    let n =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM admin_keys WHERE revoked_at IS NULL")
            .fetch_one(&mut *conn)
            .await?;
    Ok(n)
}
