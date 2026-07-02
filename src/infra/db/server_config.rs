//! First-run bootstrap latch (operator §3.2).
//!
//! The latch is an explicit, MAC-protected singleton — bootstrap mode is NOT
//! inferred from "no admin keys". The MAC (keyed by `ADMIN_KEY_INTEGRITY_SECRET`,
//! over `setup_state|bootstrap_completed_at`) means a DB-write attacker who
//! restores a pre-bootstrap backup or flips the state to re-open trust-on-first-
//! use produces a mismatch the boot path detects (`SetupState::Tampered`) and
//! fails closed on. The supported bootstrap is the CLI (`smirk-admin setup`),
//! which inserts the first admin AND latches in one transaction.

use chrono::{SubsecRound, Utc};
use tracing::instrument;

use crate::core::crypto::pepper::peppered_hex;
use crate::error::AppError;
use crate::models::db::{NewAdminAudit, NewAdminKey, ServerConfig};

use super::admin_keys::AddKeyOutcome;
use super::Database;

/// Resolved bootstrap state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupState {
    /// No latch row yet (a brand-new database).
    Fresh,
    /// Latch present + valid, not yet bootstrapped.
    Uninitialized,
    /// Latch present + valid, bootstrap complete.
    Locked,
    /// Latch present but its MAC does not verify — tamper / restore-to-pre-boot.
    Tampered,
}

/// `HMAC(secret, "server_config" ‖ setup_state ‖ bootstrap_completed_at)`.
fn latch_mac(secret: &str, setup_state: &str, completed_at_micros: Option<i64>) -> String {
    let completed = completed_at_micros
        .map(|m| m.to_string())
        .unwrap_or_else(|| "null".to_string());
    peppered_hex(
        secret,
        "server_config",
        &format!("{setup_state}\u{1f}{completed}"),
    )
}

fn verify_latch(secret: &str, c: &ServerConfig) -> bool {
    use subtle::ConstantTimeEq;
    let expected = latch_mac(
        secret,
        &c.setup_state,
        c.bootstrap_completed_at.map(|t| t.timestamp_micros()),
    );
    expected.as_bytes().ct_eq(c.integrity_mac.as_bytes()).into()
}

impl Database {
    /// Read + verify the bootstrap latch.
    #[instrument(skip(self, secret))]
    pub async fn read_setup_state(&self, secret: &str) -> Result<SetupState, AppError> {
        let row = sqlx::query_as::<_, ServerConfig>(
            "SELECT id, setup_state, bootstrap_completed_at, locked_at, updated_at, integrity_mac \
             FROM server_config WHERE id = 1",
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(match row {
            None => SetupState::Fresh,
            Some(c) if !verify_latch(secret, &c) => SetupState::Tampered,
            Some(c) if c.setup_state == "locked" => SetupState::Locked,
            Some(_) => SetupState::Uninitialized,
        })
    }

    /// Whether the DB already holds user data (drives migration adoption: a live
    /// deployment must latch `locked` so it never exposes a setup window).
    #[instrument(skip(self))]
    pub async fn has_any_users(&self) -> Result<bool, AppError> {
        let exists = sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM users)")
            .fetch_one(self.pool())
            .await?;
        Ok(exists)
    }

    /// Whether the DB has any admin key (live or revoked) — i.e. it was once
    /// bootstrapped. Used so a deleted latch row on a CLI-bootstrapped instance
    /// re-adopts `locked` instead of silently dropping to `uninitialized`.
    #[instrument(skip(self))]
    pub async fn has_any_admin_keys(&self) -> Result<bool, AppError> {
        let exists = sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM admin_keys)")
            .fetch_one(self.pool())
            .await?;
        Ok(exists)
    }

    /// Create the latch row if absent. `locked` adopts an existing deployment
    /// (state=locked, completed/locked now); otherwise a fresh install begins
    /// `uninitialized`. No-op if the row already exists.
    #[instrument(skip(self, secret))]
    pub async fn init_server_config(&self, secret: &str, locked: bool) -> Result<(), AppError> {
        let now = Utc::now().trunc_subsecs(6);
        let (state, completed, locked_at) = if locked {
            ("locked", Some(now), Some(now))
        } else {
            ("uninitialized", None, None)
        };
        let mac = latch_mac(
            secret,
            state,
            completed.map(|t: chrono::DateTime<Utc>| t.timestamp_micros()),
        );
        sqlx::query(
            "INSERT INTO server_config (id, setup_state, bootstrap_completed_at, locked_at, integrity_mac) \
             VALUES (1, $1, $2, $3, $4) ON CONFLICT (id) DO NOTHING",
        )
        .bind(state)
        .bind(completed)
        .bind(locked_at)
        .bind(&mac)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Headless bootstrap (CLI): insert the FIRST admin (active) and latch
    /// `locked`, in ONE transaction + a hash-chained audit row. Refuses if ANY
    /// live admin key already exists — active OR pending — so `setup` composes
    /// cleanly with `create-admin-wallet` (which registers a pending key + latches)
    /// instead of seeding a confusing second admin. The adopt-existing-deployment
    /// path is unaffected: a deployment with users but no admin keys has no live
    /// key, so bootstrap still proceeds to seed the first admin.
    #[instrument(skip(self, secret))]
    pub async fn bootstrap_admin(&self, pubkey: &str, secret: &str) -> Result<(), AppError> {
        use crate::core::crypto::admin_mac::{compute_admin_key_mac, AdminKeyMacInput};
        let mut tx = self.pool().begin().await?;
        // Serialize with all admin-key mutations so two concurrent `setup` runs
        // cannot both pass the single-bootstrap guard and seed two admins.
        super::admin_keys::admin_keys_mutate_lock(&mut tx).await?;

        let has_admin = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM admin_keys WHERE revoked_at IS NULL)",
        )
        .fetch_one(&mut *tx)
        .await?;
        if has_admin {
            tx.rollback().await?;
            return Err(AppError::Conflict(
                "an admin key already exists (active or pending); use add-key, or \
                 create-admin-wallet to add another generated key"
                    .into(),
            ));
        }

        // Insert an already-ACTIVE admin (bootstrap, not pending-first-login).
        let id = uuid::Uuid::new_v4();
        let now = Utc::now().trunc_subsecs(6);
        let mac = compute_admin_key_mac(
            secret,
            &AdminKeyMacInput {
                id,
                pubkey,
                scope: "admin",
                created_at: now,
                activated_at: Some(now),
                activation_deadline: None,
                revoked_at: None,
            },
        );
        sqlx::query(
            "INSERT INTO admin_keys \
             (id, pubkey, label, scope, created_at, created_by_kind, activated_at, integrity_mac) \
             VALUES ($1, $2, 'bootstrap', 'admin', $3, 'bootstrap', $3, $4)",
        )
        .bind(id)
        .bind(pubkey)
        .bind(now)
        .bind(&mac)
        .execute(&mut *tx)
        .await
        .map_err(super::unique_violation_as(
            "an active admin key with this pubkey already exists",
        ))?;

        // Latch locked (upsert so adoption rows also become bootstrapped).
        let latch = latch_mac(secret, "locked", Some(now.timestamp_micros()));
        sqlx::query(
            "INSERT INTO server_config (id, setup_state, bootstrap_completed_at, locked_at, integrity_mac) \
             VALUES (1, 'locked', $1, $1, $2) \
             ON CONFLICT (id) DO UPDATE SET setup_state = 'locked', \
                bootstrap_completed_at = $1, locked_at = $1, updated_at = NOW(), integrity_mac = $2",
        )
        .bind(now)
        .bind(&latch)
        .execute(&mut *tx)
        .await?;

        self.append_admin_audit(
            &mut tx,
            &NewAdminAudit {
                action: "bootstrap".into(),
                actor_kind: "bootstrap".into(),
                actor_pubkey_prefix: Some(pubkey.chars().take(16).collect()),
                target: None,
                details: None,
                ip_address: None,
            },
            secret,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Register a generated PENDING admin key and, if the instance is not yet
    /// bootstrapped, latch `locked` in the SAME transaction — so `create-admin-
    /// wallet` on a fresh instance is a COMPLETE first-run bootstrap (key + latch),
    /// not a key without a latch that leaves setup half-open (the bug this fixes).
    /// Keeps pending semantics: the generated key activates on its holder's first
    /// login (unlike `bootstrap_admin`, which seeds an already-active key from an
    /// operator's own pubkey). On an already-locked instance this is a plain pending
    /// add (no re-latch). FAILS CLOSED on a tampered latch (defers to `reset-setup`,
    /// mirroring the boot path) rather than silently healing it. Serialized with all
    /// admin-key mutations via the advisory lock, so it cannot race `bootstrap_admin`.
    ///
    /// Returns the add outcome and whether it latched (true = this call bootstrapped
    /// a fresh instance). NOTE: `CapReached` returns `latched = false` WITHOUT
    /// inserting or latching, so a caller passing a finite cap must treat that as
    /// "instance still un-bootstrapped".
    #[instrument(skip(self, input, audit, secret))]
    pub async fn create_admin_key_bootstrapping(
        &self,
        input: NewAdminKey,
        audit: &NewAdminAudit,
        secret: &str,
        max_live: i64,
    ) -> Result<(AddKeyOutcome, bool), AppError> {
        let mut tx = self.pool().begin().await?;
        super::admin_keys::admin_keys_mutate_lock(&mut tx).await?;

        // Resolve the latch state up front (under the lock). A missing row (Fresh)
        // or a valid `uninitialized` row means "bootstrap now"; a valid `locked` row
        // means "already bootstrapped, just add the key". A MAC-INVALID row is a
        // tamper / restore-to-pre-bootstrap: FAIL CLOSED here exactly like the boot
        // path, instead of silently re-stamping a valid `locked` latch over it and
        // erasing the tamper evidence. The operator must acknowledge the recovery
        // with `reset-setup --i-understand` first.
        let cfg = sqlx::query_as::<_, ServerConfig>(
            "SELECT id, setup_state, bootstrap_completed_at, locked_at, updated_at, integrity_mac \
             FROM server_config WHERE id = 1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        if matches!(&cfg, Some(c) if !verify_latch(secret, c)) {
            tx.rollback().await?;
            return Err(AppError::Conflict(
                "server_config bootstrap latch MAC invalid (tamper or restore-to-pre-bootstrap); \
                 run `reset-setup --i-understand` first if this is intentional"
                    .into(),
            ));
        }
        // Past the tamper gate, a present row is MAC-valid, so this is genuinely
        // "already locked" only for a real `locked` state.
        let already_locked = matches!(&cfg, Some(c) if c.setup_state == "locked");

        // Cap check under the lock (the CLI passes i64::MAX — effectively no cap).
        let live = super::admin_keys::live_key_count(&mut tx).await?;
        if live >= max_live {
            tx.rollback().await?;
            return Ok((AddKeyOutcome::CapReached, false));
        }

        let key = super::admin_keys::insert_admin_key(&mut tx, &input, secret).await?;

        // Latch `locked` unless already validly locked (so additional generated keys
        // do not re-stamp bootstrap_completed_at). INVARIANT: latching with only a
        // PENDING key (zero active admins) is safe ONLY because no runtime path gates
        // on `setup_state` — admin login authorizes on a pending key and activates it
        // on first use (see api/admin.rs). Do NOT add a "reject unless Locked && >=1
        // active admin" gate: it would make this state an unrecoverable lockout (the
        // login that would activate the key is the one such a gate would block).
        let latched = if already_locked {
            false
        } else {
            let now = Utc::now().trunc_subsecs(6);
            let latch = latch_mac(secret, "locked", Some(now.timestamp_micros()));
            sqlx::query(
                "INSERT INTO server_config (id, setup_state, bootstrap_completed_at, locked_at, integrity_mac) \
                 VALUES (1, 'locked', $1, $1, $2) \
                 ON CONFLICT (id) DO UPDATE SET setup_state = 'locked', \
                    bootstrap_completed_at = $1, locked_at = $1, updated_at = NOW(), integrity_mac = $2",
            )
            .bind(now)
            .bind(&latch)
            .execute(&mut *tx)
            .await?;
            true
        };

        self.append_admin_audit(&mut tx, audit, secret).await?;
        tx.commit().await?;
        Ok((AddKeyOutcome::Created(key), latched))
    }

    /// Reset the latch to `uninitialized` (shell `reset-setup` only). Recomputes
    /// the MAC so it verifies again; existing admin keys are left untouched, so
    /// recovery cannot worsen a lockout. Takes the admin-keys advisory lock so all
    /// latch writers (`bootstrap_admin`, `create_admin_key_bootstrapping`) serialize
    /// on one lock — a concurrent reset can't tear a check-then-latch.
    ///
    /// Recovery note: keys are preserved, so if a LIVE key still exists after the
    /// reset, `setup` stays refused (its guard rejects any live key). Recover by
    /// re-running `create-admin-wallet` (adds a fresh key + re-latches), or by
    /// `revoke-key`-ing the stale key(s) and then running `setup`.
    #[instrument(skip(self, secret))]
    pub async fn reset_setup(&self, secret: &str) -> Result<(), AppError> {
        let mut tx = self.pool().begin().await?;
        super::admin_keys::admin_keys_mutate_lock(&mut tx).await?;
        let mac = latch_mac(secret, "uninitialized", None);
        sqlx::query(
            "INSERT INTO server_config (id, setup_state, bootstrap_completed_at, locked_at, integrity_mac) \
             VALUES (1, 'uninitialized', NULL, NULL, $1) \
             ON CONFLICT (id) DO UPDATE SET setup_state = 'uninitialized', \
                bootstrap_completed_at = NULL, locked_at = NULL, updated_at = NOW(), integrity_mac = $1",
        )
        .bind(&mac)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
