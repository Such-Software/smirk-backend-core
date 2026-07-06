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

use super::{unique_violation_as, Database};

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

    /// Whether an x-only pubkey (canonical lowercase hex) is linked to any user —
    /// the fast membership check behind the relay write-admission policy. No PII
    /// returned, so it is safe to call per inbound relay event.
    #[instrument(skip(self, nostr_pubkey))]
    pub async fn is_registered_npub(&self, nostr_pubkey: &str) -> Result<bool, AppError> {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM users WHERE nostr_pubkey = $1)",
        )
        .bind(nostr_pubkey)
        .fetch_one(self.pool())
        .await?;
        Ok(exists)
    }

    /// Whether ANY of `pubkeys` (canonical lowercase hex) is a registered npub —
    /// a single batched query, so resolving an event's recipient `p` tags costs
    /// one round-trip instead of one-per-tag (no N+1 blowup on a crafted event).
    #[instrument(skip(self, pubkeys))]
    pub async fn any_registered_npub(&self, pubkeys: &[String]) -> Result<bool, AppError> {
        if pubkeys.is_empty() {
            return Ok(false);
        }
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM users WHERE nostr_pubkey = ANY($1))",
        )
        .bind(pubkeys)
        .fetch_one(self.pool())
        .await?;
        Ok(exists)
    }

    /// Whether an x-only pubkey (canonical lowercase hex) is a registered npub
    /// with a CURRENTLY-ACTIVE premium subscription — the membership check behind
    /// the `premium-post` relay policy. Not peppered (npub is public); safe per
    /// inbound relay event.
    #[instrument(skip(self, nostr_pubkey))]
    pub async fn is_premium_npub(&self, nostr_pubkey: &str) -> Result<bool, AppError> {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM users \
             WHERE nostr_pubkey = $1 AND premium_until IS NOT NULL AND premium_until > NOW())",
        )
        .bind(nostr_pubkey)
        .fetch_one(self.pool())
        .await?;
        Ok(exists)
    }

    /// Extend a user's premium window by `days`, stacking from the later of `NOW()`
    /// and the current expiry (so an early renewal never shortens the window).
    /// Returns the new expiry.
    #[instrument(skip(self))]
    pub async fn extend_premium(
        &self,
        user_id: Uuid,
        days: i32,
    ) -> Result<chrono::DateTime<chrono::Utc>, AppError> {
        let until = sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
            "UPDATE users SET \
               premium_until = GREATEST(COALESCE(premium_until, NOW()), NOW()) \
                             + make_interval(days => $2), \
               updated_at = NOW() \
             WHERE id = $1 RETURNING premium_until",
        )
        .bind(user_id)
        .bind(days)
        .fetch_one(self.pool())
        .await?;
        Ok(until)
    }

    /// A user's current premium expiry (`None` if never premium / lapsed to NULL).
    #[instrument(skip(self))]
    pub async fn get_premium_until(
        &self,
        user_id: Uuid,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, AppError> {
        let until = sqlx::query_scalar::<_, Option<chrono::DateTime<chrono::Utc>>>(
            "SELECT premium_until FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(self.pool())
        .await?
        .flatten();
        Ok(until)
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

    /// Get-or-create a user keyed by their **Nostr pubkey**: the npub-native
    /// registration path for the self-sovereign backend (no BTC signature).
    /// `nostr_pubkey` is lowercase x-only hex, stored RAW (public, never peppered,
    /// mirroring [`find_user_by_nostr_pubkey`]).
    ///
    /// DEDUP is load-bearing: a wallet may already have a row from the BTC path or
    /// a prior link, joined only by `seed_fingerprint` (derivation-independent). A
    /// naive insert would collide on the `seed_fingerprint` UNIQUE and split one
    /// wallet into two identities. So, in order:
    ///   1. npub already known -> that user (COALESCE-backfill the optional fields).
    ///   2. else `seed_fingerprint` matches an existing row -> MERGE: backfill the
    ///      npub onto THAT row. If the row already carries a DIFFERENT npub the
    ///      wallet is already registered under another identity -> fail closed.
    ///   3. else create a fresh npub-keyed row (`pubkey_hash` NULL).
    #[instrument(skip(self))]
    pub async fn get_or_create_user_by_nostr_pubkey(
        &self,
        nostr_pubkey: &str,
        username: Option<String>,
        wallet_birthday: Option<chrono::DateTime<chrono::Utc>>,
        seed_fingerprint: Option<String>,
        xmr_start_height: Option<i64>,
        wow_start_height: Option<i64>,
    ) -> Result<User, AppError> {
        // 1. Known npub -> that user, backfilling any newly-supplied optionals.
        if let Some(existing) = self.find_user_by_nostr_pubkey(nostr_pubkey).await? {
            return self
                .backfill_optionals(
                    existing,
                    wallet_birthday,
                    seed_fingerprint,
                    xmr_start_height,
                    wow_start_height,
                )
                .await;
        }

        // 2. DEDUP: same seed already has a row (BTC-anchored or link-less) -> MERGE
        //    the npub onto it rather than split the identity.
        if let Some(fp) = seed_fingerprint.as_deref() {
            if let Some(existing) = self.get_user_by_seed_fingerprint(fp).await? {
                match existing.nostr_pubkey.as_deref() {
                    Some(pk) if pk == nostr_pubkey => {
                        // Row already carries this npub (find-by-npub missed only if
                        // the columns disagree) so treat as the known user.
                        return self
                            .backfill_optionals(
                                existing,
                                wallet_birthday,
                                None,
                                xmr_start_height,
                                wow_start_height,
                            )
                            .await;
                    }
                    Some(_) => {
                        // Same seed, different npub on file (e.g. a rotation): do not
                        // silently re-point on an unauthenticated register.
                        return Err(AppError::Conflict(
                            "This wallet is already registered under a different Nostr identity. Sign in instead."
                                .into(),
                        ));
                    }
                    None => {
                        // SECURITY: the seed_fingerprint is a lookup handle, not
                        // a credential — the client transmits it unauthenticated on
                        // /auth/check-restore and register, and it is stored server-
                        // side. Binding an npub onto a pre-existing (BTC-anchored /
                        // link-less) row on a fingerprint MATCH ALONE would let anyone
                        // who learns a victim's fingerprint take over that account and
                        // be issued a session for it. The BTC rotation path guards the
                        // identical "known fingerprint at a new key" operation behind a
                        // signature over the ON-FILE key; this register endpoint proves
                        // control only of the NEW npub, never the on-file key, so it
                        // MUST NOT re-point the row. Fail closed exactly like the
                        // different-npub arm above: the wallet links its npub through
                        // the authenticated POST /auth/nostr/link flow (which requires
                        // an existing session proving the on-file key) instead.
                        return Err(AppError::Conflict(
                            "This wallet already has an account. Sign in with your existing \
                             credentials and link your Nostr identity from settings."
                                .into(),
                        ));
                    }
                }
            }
        }

        // 3. Fresh npub-keyed identity (no BTC anchor).
        self.create_user(NewUser {
            username,
            pubkey_hash: None,
            nostr_pubkey: Some(nostr_pubkey.to_string()),
            wallet_birthday,
            seed_fingerprint,
            xmr_start_height,
            wow_start_height,
        })
        .await
    }

    /// COALESCE-backfill only the NULL optional fields on an existing user row,
    /// returning it unchanged when nothing is newly supplied. Shared by the
    /// BTC and npub get-or-create paths.
    async fn backfill_optionals(
        &self,
        existing: User,
        wallet_birthday: Option<chrono::DateTime<chrono::Utc>>,
        seed_fingerprint: Option<String>,
        xmr_start_height: Option<i64>,
        wow_start_height: Option<i64>,
    ) -> Result<User, AppError> {
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
        Ok(updated)
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

    /// Count registered wallets. A wallet is anchored by EITHER a BTC pubkey_hash
    /// (legacy/BTC path) OR a nostr_pubkey (npub-native path), so count both; an
    /// npub-only user is still a registered wallet.
    #[instrument(skip(self))]
    pub async fn get_user_count(&self) -> Result<i64, AppError> {
        Ok(sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE pubkey_hash IS NOT NULL OR nostr_pubkey IS NOT NULL",
        )
        .fetch_one(self.pool())
        .await?)
    }
}
