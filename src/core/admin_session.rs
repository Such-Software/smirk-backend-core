//! Admin session JWTs — cryptographically distinct from user sessions.
//!
//! Admin tokens are signed with a dedicated `ADMIN_JWT_SECRET` and carry a
//! distinct audience (`smirk-admin`) plus an explicit `scope`, so a user token
//! can never be presented on the admin plane and vice versa. Verification reuses
//! the centralized strict [`crate::core::session::strict_validation`] (HS256
//! pinned, zero leeway, `aud` required) — `Validation::default()` is never used.
//! Access tokens are short-lived (15 min) and carry a `jti` recorded in the
//! `admin_sessions` row, so a soft-revoked admin's still-valid token is rejected
//! at the next call; refresh tokens (8 h) bind a session id.

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::core::session::strict_validation;
use crate::error::AppError;

const ADMIN_ACCESS_AUD: &str = "smirk-admin";
const ADMIN_REFRESH_AUD: &str = "smirk-admin-refresh";
const ADMIN_SCOPE: &str = "admin";
const ACCESS_TTL_MINUTES: i64 = 15;
const REFRESH_TTL_HOURS: i64 = 8;

/// Admin access-token claims. `sub` is the admin **pubkey** (not a UUID) so the
/// live allowlist re-check in the guard is meaningful.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAccessClaims {
    pub sub: String,
    pub aud: String,
    pub scope: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
}

/// Admin refresh-token claims. `sid` is the `admin_sessions` row id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminRefreshClaims {
    pub sub: String,
    pub aud: String,
    pub sid: String,
    pub iat: i64,
    pub exp: i64,
}

/// Decoded admin access token: the pubkey to re-authorize and the `jti` to look
/// up the live session row.
#[derive(Debug, Clone)]
pub struct AdminAccessInfo {
    pub pubkey: String,
    pub jti: String,
}

/// A freshly minted admin token pair. `access_jti` must be recorded in the
/// session row so the guard can match (and revocation can invalidate) it.
#[derive(Debug, Clone)]
pub struct AdminTokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub access_jti: String,
    pub expires_in: i64,
}

/// Mints and verifies admin JWTs under a dedicated secret.
#[derive(Clone)]
pub struct AdminSessionManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    access_validation: jsonwebtoken::Validation,
    refresh_validation: jsonwebtoken::Validation,
}

impl AdminSessionManager {
    /// `admin_jwt_secret` must be >= 32 bytes (enforced by config validation when
    /// the admin surface is enabled).
    pub fn new(admin_jwt_secret: &str) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(admin_jwt_secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(admin_jwt_secret.as_bytes()),
            access_validation: strict_validation(ADMIN_ACCESS_AUD),
            refresh_validation: strict_validation(ADMIN_REFRESH_AUD),
        }
    }

    /// Mint an access + refresh pair for `admin_pubkey`, binding the refresh
    /// token to `session_id`. Returns the pair plus the access `jti` to persist.
    pub fn create_token_pair(
        &self,
        admin_pubkey: &str,
        session_id: Uuid,
    ) -> Result<AdminTokenPair, AppError> {
        let now = Utc::now();
        let jti = Uuid::new_v4().to_string();
        let header = Header::new(Algorithm::HS256);

        let access = AdminAccessClaims {
            sub: admin_pubkey.to_string(),
            aud: ADMIN_ACCESS_AUD.to_string(),
            scope: ADMIN_SCOPE.to_string(),
            jti: jti.clone(),
            iat: now.timestamp(),
            exp: (now + Duration::minutes(ACCESS_TTL_MINUTES)).timestamp(),
        };
        let access_token = encode(&header, &access, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("admin access token: {e}")))?;

        let refresh = AdminRefreshClaims {
            sub: admin_pubkey.to_string(),
            aud: ADMIN_REFRESH_AUD.to_string(),
            sid: session_id.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::hours(REFRESH_TTL_HOURS)).timestamp(),
        };
        let refresh_token = encode(&header, &refresh, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("admin refresh token: {e}")))?;

        Ok(AdminTokenPair {
            access_token,
            refresh_token,
            access_jti: jti,
            expires_in: ACCESS_TTL_MINUTES * 60,
        })
    }

    /// Verify an admin access token. Beyond the strict `aud` check, the `scope`
    /// is re-asserted. The error is a literal (never the inner Display) so the
    /// token cannot become an oracle.
    pub fn verify_access(&self, token: &str) -> Result<AdminAccessInfo, AppError> {
        let data = decode::<AdminAccessClaims>(token, &self.decoding_key, &self.access_validation)
            .map_err(|_| AppError::AuthError("Invalid or expired admin token".into()))?;
        if data.claims.scope != ADMIN_SCOPE {
            return Err(AppError::AuthError("Invalid or expired admin token".into()));
        }
        Ok(AdminAccessInfo {
            pubkey: data.claims.sub,
            jti: data.claims.jti,
        })
    }

    /// Verify an admin refresh token, returning `(admin_pubkey, session_id)`.
    pub fn verify_refresh(&self, token: &str) -> Result<(String, Uuid), AppError> {
        let data =
            decode::<AdminRefreshClaims>(token, &self.decoding_key, &self.refresh_validation)
                .map_err(|_| AppError::AuthError("Invalid or expired admin token".into()))?;
        let sid = Uuid::parse_str(&data.claims.sid)
            .map_err(|_| AppError::AuthError("Invalid or expired admin token".into()))?;
        Ok((data.claims.sub, sid))
    }

    pub fn access_ttl_secs(&self) -> i64 {
        ACCESS_TTL_MINUTES * 60
    }

    pub fn refresh_ttl(&self) -> Duration {
        Duration::hours(REFRESH_TTL_HOURS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::session::{Platform, SessionManager};

    const ADMIN_SECRET: &str = "admin-jwt-secret-at-least-32-bytes-long!!";
    const PK: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn mint_and_verify_roundtrip() {
        let m = AdminSessionManager::new(ADMIN_SECRET);
        let sid = Uuid::new_v4();
        let pair = m.create_token_pair(PK, sid).unwrap();

        let info = m.verify_access(&pair.access_token).unwrap();
        assert_eq!(info.pubkey, PK);
        assert_eq!(info.jti, pair.access_jti);

        let (pk, got_sid) = m.verify_refresh(&pair.refresh_token).unwrap();
        assert_eq!(pk, PK);
        assert_eq!(got_sid, sid);
    }

    #[test]
    fn user_access_token_fails_admin_decode() {
        // A user token (distinct secret + audience) must not verify as admin.
        let user = SessionManager::new("user-jwt-secret-at-least-32-bytes-long!", 24);
        let pair = user
            .create_token_pair(Uuid::new_v4(), Platform::Web, Uuid::new_v4())
            .unwrap();
        let admin = AdminSessionManager::new(ADMIN_SECRET);
        assert!(admin.verify_access(&pair.access_token).is_err());
    }

    #[test]
    fn admin_access_not_accepted_as_refresh() {
        let m = AdminSessionManager::new(ADMIN_SECRET);
        let pair = m.create_token_pair(PK, Uuid::new_v4()).unwrap();
        // Distinct audiences within the admin secret too.
        assert!(m.verify_refresh(&pair.access_token).is_err());
        assert!(m.verify_access(&pair.refresh_token).is_err());
    }

    #[test]
    fn wrong_audience_fails() {
        // A token with the right secret/alg but a foreign audience must fail.
        let claims = AdminAccessClaims {
            sub: PK.into(),
            aud: "some-other-aud".into(),
            scope: ADMIN_SCOPE.into(),
            jti: Uuid::new_v4().to_string(),
            iat: Utc::now().timestamp(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp(),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(ADMIN_SECRET.as_bytes()),
        )
        .unwrap();
        let m = AdminSessionManager::new(ADMIN_SECRET);
        assert!(m.verify_access(&token).is_err());
    }

    #[test]
    fn wrong_algorithm_fails() {
        // HS512 token must be rejected (HS256 pinned, no alg confusion).
        let claims = AdminAccessClaims {
            sub: PK.into(),
            aud: ADMIN_ACCESS_AUD.into(),
            scope: ADMIN_SCOPE.into(),
            jti: Uuid::new_v4().to_string(),
            iat: Utc::now().timestamp(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp(),
        };
        let token = encode(
            &Header::new(Algorithm::HS512),
            &claims,
            &EncodingKey::from_secret(ADMIN_SECRET.as_bytes()),
        )
        .unwrap();
        let m = AdminSessionManager::new(ADMIN_SECRET);
        assert!(m.verify_access(&token).is_err());
    }

    #[test]
    fn expired_token_fails_with_zero_leeway() {
        let claims = AdminAccessClaims {
            sub: PK.into(),
            aud: ADMIN_ACCESS_AUD.into(),
            scope: ADMIN_SCOPE.into(),
            jti: Uuid::new_v4().to_string(),
            iat: (Utc::now() - Duration::hours(1)).timestamp(),
            exp: (Utc::now() - Duration::minutes(1)).timestamp(),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(ADMIN_SECRET.as_bytes()),
        )
        .unwrap();
        let m = AdminSessionManager::new(ADMIN_SECRET);
        assert!(m.verify_access(&token).is_err());
    }

    #[test]
    fn scope_must_be_admin() {
        // Right aud/alg/secret but a non-admin scope is rejected.
        let claims = AdminAccessClaims {
            sub: PK.into(),
            aud: ADMIN_ACCESS_AUD.into(),
            scope: "user".into(),
            jti: Uuid::new_v4().to_string(),
            iat: Utc::now().timestamp(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp(),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(ADMIN_SECRET.as_bytes()),
        )
        .unwrap();
        let m = AdminSessionManager::new(ADMIN_SECRET);
        assert!(m.verify_access(&token).is_err());
    }
}
