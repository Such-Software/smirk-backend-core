//! Unified server-nonce (challenge) store.
//!
//! Backs every server-issued single-use nonce for signed actions (admin login,
//! first-run setup, self-service erasure). Issuance mints a random nonce bound to
//! a `purpose` (and an optional `subject`); consumption is a single atomic
//! `DELETE ... RETURNING`, so a nonce is honoured at most once even under
//! concurrent or multi-node races. The caller pairs this with
//! [`crate::core::crypto::nip98::verify_signed_action`], which proves the signed
//! event commits to the same nonce + purpose.

use rand::RngCore;
use tracing::instrument;

use crate::error::AppError;

use super::Database;

/// Nonce length in bytes (hex-encoded to 64 chars). 256 bits — unguessable.
const NONCE_BYTES: usize = 32;

/// A successfully consumed challenge. `subject` is whatever was bound at issue
/// (e.g. a target pubkey or erasure id), or `None` if none was bound.
#[derive(Debug, Clone)]
pub struct ConsumedChallenge {
    pub subject: Option<String>,
}

impl Database {
    /// Mint a single-use nonce for `purpose`, valid for `ttl_secs`. Returns the
    /// nonce (hex) to hand to the client; `subject` optionally binds it to a
    /// target the verify step can cross-check.
    #[instrument(skip(self, subject))]
    pub async fn issue_challenge(
        &self,
        purpose: &str,
        subject: Option<&str>,
        ttl_secs: i64,
    ) -> Result<String, AppError> {
        let mut bytes = [0u8; NONCE_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let nonce = hex::encode(bytes);

        sqlx::query(
            "INSERT INTO challenges (nonce, purpose, subject, expires_at) \
             VALUES ($1, $2, $3, NOW() + make_interval(secs => $4))",
        )
        .bind(&nonce)
        .bind(purpose)
        .bind(subject)
        .bind(ttl_secs as f64)
        .execute(self.pool())
        .await?;
        Ok(nonce)
    }

    /// Atomically consume `(nonce, purpose)` if present and unexpired. Returns
    /// the consumed challenge, or `None` for an unknown / wrong-purpose / expired
    /// / already-used nonce — all of which the caller must treat as rejection.
    #[instrument(skip(self, nonce))]
    pub async fn consume_challenge(
        &self,
        nonce: &str,
        purpose: &str,
    ) -> Result<Option<ConsumedChallenge>, AppError> {
        // One atomic step: the delete IS the check, so two racers cannot both win.
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "DELETE FROM challenges \
             WHERE nonce = $1 AND purpose = $2 AND expires_at > NOW() \
             RETURNING subject",
        )
        .bind(nonce)
        .bind(purpose)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|(subject,)| ConsumedChallenge { subject }))
    }

    /// Delete expired challenges. Run periodically to bound the table; the
    /// consume query already ignores expired rows, so this is hygiene only.
    #[instrument(skip(self))]
    pub async fn delete_expired_challenges(&self) -> Result<u64, AppError> {
        let res = sqlx::query("DELETE FROM challenges WHERE expires_at <= NOW()")
            .execute(self.pool())
            .await?;
        Ok(res.rows_affected())
    }
}
