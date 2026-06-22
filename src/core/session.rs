//! Session and JWT management.
//!
//! Access and refresh tokens are HS256 JWTs. Verification is strict: the
//! algorithm is pinned to HS256 (no `alg` confusion), `exp`/`sub`/`aud` are
//! required, clock leeway is zero, and access vs refresh tokens carry distinct
//! audiences so one can never be presented as the other. Refresh tokens are
//! also tracked in the database (by a peppered hash) for rotation/revocation.

use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::error::AppError;

/// Audience for access tokens. Distinct from the refresh audience so a refresh
/// token can never be accepted on an access-protected route, and vice versa.
const ACCESS_AUD: &str = "smirk:access";
/// Audience for refresh tokens.
const REFRESH_AUD: &str = "smirk:refresh";

/// JWT claims for access tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Subject (user ID).
    pub sub: String,
    /// Audience (token type).
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    /// Client kind: extension | web | nostr.
    pub platform: String,
}

/// JWT claims for refresh tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    /// Subject (user ID).
    pub sub: String,
    /// Audience (token type).
    pub aud: String,
    /// Session ID (for revocation).
    pub sid: String,
    pub iat: i64,
    pub exp: i64,
}

/// Decoded access-token information.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub user_id: Uuid,
    pub platform: String,
}

/// Session token pair.
#[derive(Debug, Clone, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

/// Client kind a session was created from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Extension,
    Web,
    Nostr,
}

impl Platform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Extension => "extension",
            Platform::Web => "web",
            Platform::Nostr => "nostr",
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Platform {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "extension" => Ok(Platform::Extension),
            "web" => Ok(Platform::Web),
            "nostr" => Ok(Platform::Nostr),
            _ => Err(AppError::ValidationError(format!(
                "Invalid platform: {}",
                s
            ))),
        }
    }
}

/// Challenge for website ("Sign in with your wallet") auth.
#[derive(Debug, Clone)]
pub struct WebChallenge {
    pub nonce: String,
    pub created_at: chrono::DateTime<Utc>,
    pub origin: String,
    pub expires_at: chrono::DateTime<Utc>,
}

impl WebChallenge {
    pub fn new(origin: String) -> Self {
        let now = Utc::now();
        let nonce_bytes: [u8; 32] = rand::random();
        Self {
            nonce: hex::encode(nonce_bytes),
            created_at: now,
            origin,
            expires_at: now + Duration::minutes(5),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn message(&self) -> String {
        format!(
            "Smirk Authentication Challenge\nNonce: {}\nOrigin: {}\nTimestamp: {}",
            self.nonce,
            self.origin,
            self.created_at.timestamp()
        )
    }
}

/// Creates and verifies session JWTs.
#[derive(Clone)]
pub struct SessionManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    access_validation: Validation,
    refresh_validation: Validation,
    access_token_expiry_hours: i64,
    refresh_token_expiry_days: i64,
}

fn strict_validation(audience: &str) -> Validation {
    let mut v = Validation::new(Algorithm::HS256);
    v.leeway = 0;
    v.validate_exp = true;
    v.set_required_spec_claims(&["exp", "sub", "aud"]);
    v.set_audience(&[audience]);
    v
}

impl SessionManager {
    /// `jwt_secret` must be >= 32 bytes (enforced by config validation).
    pub fn new(jwt_secret: &str, access_token_expiry_hours: u64) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(jwt_secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(jwt_secret.as_bytes()),
            access_validation: strict_validation(ACCESS_AUD),
            refresh_validation: strict_validation(REFRESH_AUD),
            access_token_expiry_hours: access_token_expiry_hours as i64,
            refresh_token_expiry_days: 30,
        }
    }

    /// Mint an access + refresh token pair. `session_id` ties the refresh token
    /// to a revocable DB session row.
    pub fn create_token_pair(
        &self,
        user_id: Uuid,
        platform: Platform,
        session_id: Uuid,
    ) -> Result<TokenPair, AppError> {
        let now = Utc::now();
        let access_exp = now + Duration::hours(self.access_token_expiry_hours);
        let refresh_exp = now + Duration::days(self.refresh_token_expiry_days);
        let header = Header::new(Algorithm::HS256);

        let access_claims = AccessTokenClaims {
            sub: user_id.to_string(),
            aud: ACCESS_AUD.to_string(),
            iat: now.timestamp(),
            exp: access_exp.timestamp(),
            platform: platform.to_string(),
        };
        let access_token = encode(&header, &access_claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("Failed to create access token: {}", e)))?;

        let refresh_claims = RefreshTokenClaims {
            sub: user_id.to_string(),
            aud: REFRESH_AUD.to_string(),
            sid: session_id.to_string(),
            iat: now.timestamp(),
            exp: refresh_exp.timestamp(),
        };
        let refresh_token = encode(&header, &refresh_claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("Failed to create refresh token: {}", e)))?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: self.access_token_expiry_hours * 3600,
        })
    }

    /// Verify an access token. The error message is a literal (never the inner
    /// `jsonwebtoken` Display) so it cannot become an auth oracle.
    pub fn verify_access_token(&self, token: &str) -> Result<TokenInfo, AppError> {
        let data = decode::<AccessTokenClaims>(token, &self.decoding_key, &self.access_validation)
            .map_err(|_| AppError::AuthError("Invalid or expired token".into()))?;
        let user_id = Uuid::parse_str(&data.claims.sub)
            .map_err(|_| AppError::AuthError("Invalid or expired token".into()))?;
        Ok(TokenInfo {
            user_id,
            platform: data.claims.platform,
        })
    }

    /// Verify a refresh token, returning `(user_id, session_id)`.
    pub fn verify_refresh_token(&self, token: &str) -> Result<(Uuid, Uuid), AppError> {
        let data =
            decode::<RefreshTokenClaims>(token, &self.decoding_key, &self.refresh_validation)
                .map_err(|_| AppError::AuthError("Invalid or expired token".into()))?;
        let user_id = Uuid::parse_str(&data.claims.sub)
            .map_err(|_| AppError::AuthError("Invalid or expired token".into()))?;
        let session_id = Uuid::parse_str(&data.claims.sid)
            .map_err(|_| AppError::AuthError("Invalid or expired token".into()))?;
        Ok((user_id, session_id))
    }

    pub fn refresh_token_expiry(&self) -> Duration {
        Duration::days(self.refresh_token_expiry_days)
    }
}

/// Peppered hash of a refresh token for storage. HMAC-SHA256 with the server
/// pepper makes a stolen DB row non-reversible and non-correlatable without the
/// pepper. We store the hash, never the token.
pub fn hash_refresh_token(token: &str, pepper: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(pepper.as_bytes()).expect("HMAC accepts any key length");
    mac.update(token.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-key-at-least-32-bytes-long!!";

    #[test]
    fn create_and_verify_access_and_refresh() {
        let m = SessionManager::new(SECRET, 24);
        let uid = Uuid::new_v4();
        let sid = Uuid::new_v4();
        let pair = m.create_token_pair(uid, Platform::Extension, sid).unwrap();

        let info = m.verify_access_token(&pair.access_token).unwrap();
        assert_eq!(info.user_id, uid);
        assert_eq!(info.platform, "extension");

        let (u, s) = m.verify_refresh_token(&pair.refresh_token).unwrap();
        assert_eq!(u, uid);
        assert_eq!(s, sid);
    }

    #[test]
    fn access_token_is_not_accepted_as_refresh() {
        let m = SessionManager::new(SECRET, 24);
        let pair = m
            .create_token_pair(Uuid::new_v4(), Platform::Web, Uuid::new_v4())
            .unwrap();
        // Distinct audiences: an access token must fail refresh validation.
        assert!(m.verify_refresh_token(&pair.access_token).is_err());
    }

    #[test]
    fn refresh_token_is_not_accepted_as_access() {
        let m = SessionManager::new(SECRET, 24);
        let pair = m
            .create_token_pair(Uuid::new_v4(), Platform::Nostr, Uuid::new_v4())
            .unwrap();
        assert!(m.verify_access_token(&pair.refresh_token).is_err());
    }

    #[test]
    fn tampered_access_token_rejected() {
        let m = SessionManager::new(SECRET, 24);
        let pair = m
            .create_token_pair(Uuid::new_v4(), Platform::Extension, Uuid::new_v4())
            .unwrap();
        let mut t = pair.access_token;
        t.pop();
        t.push(if t.ends_with('a') { 'b' } else { 'a' });
        assert!(m.verify_access_token(&t).is_err());
    }

    #[test]
    fn peppered_hash_is_deterministic_and_keyed() {
        let a = hash_refresh_token("token", "pepper-A");
        assert_eq!(a, hash_refresh_token("token", "pepper-A"));
        assert_ne!(a, "token");
        // Different pepper -> different hash (DB compromise without pepper is useless).
        assert_ne!(a, hash_refresh_token("token", "pepper-B"));
    }

    #[test]
    fn platform_roundtrips() {
        use std::str::FromStr;
        for p in [Platform::Extension, Platform::Web, Platform::Nostr] {
            assert_eq!(Platform::from_str(p.as_str()).unwrap(), p);
        }
        assert!(Platform::from_str("carrier-pigeon").is_err());
    }
}
