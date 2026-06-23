//! Grin Owner API v3 secure transport: ECDH (secp256k1) handshake + AES-256-GCM,
//! plus the plain node JSON-RPC path. All request/response framing lives here.
//!
//! Hardening vs. the reference: session init is TOCTOU-free (re-checked under the
//! write lock); the AES-GCM nonce counter advances with `checked_add` and is
//! never reused; the ECDH shared key, the wallet password, and response bodies
//! are never logged or interpolated into errors; every response read is bounded.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use futures::StreamExt;
use k256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use rand::rngs::OsRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;

use super::{GrinClient, SecureSession, MAX_GRIN_BODY_BYTES};
use crate::error::AppError;

/// JSON-RPC request frame.
#[derive(Serialize)]
struct JsonRpcRequest<'a, T> {
    jsonrpc: &'static str,
    id: u32,
    method: &'a str,
    params: T,
}

impl<'a, T> JsonRpcRequest<'a, T> {
    fn new(method: &'a str, params: T) -> Self {
        Self {
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
        }
    }
}

/// Standard JSON-RPC envelope wrapping Grin's `{"Ok": _}` / `{"Err": _}` result.
#[derive(Deserialize)]
struct RpcEnvelope<R> {
    result: Option<GrinOk<R>>,
    error: Option<JsonRpcError>,
}

/// Grin's externally-tagged result. Deserializing `R` directly (no
/// `serde_json::Value` intermediate) avoids cloning a large `ViewWallet`.
#[derive(Deserialize)]
enum GrinOk<R> {
    Ok(R),
    #[allow(dead_code)]
    Err(serde_json::Value),
}

/// Only the numeric code is read; the (untrusted) message is intentionally not.
#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
}

/// The `{nonce, body_enc}` payload of an `encrypted_request_v3` exchange.
#[derive(Deserialize)]
struct EncryptedParts {
    nonce: String,
    body_enc: String,
}

impl GrinClient {
    /// Ensure the ECDH/AES-GCM session exists. TOCTOU-free: the existence check
    /// is repeated under the write lock, so concurrent first-callers perform at
    /// most one handshake.
    async fn ensure_session(&self) -> Result<(), AppError> {
        if self.secure_session.read().await.is_some() {
            return Ok(());
        }
        let mut guard = self.secure_session.write().await;
        if guard.is_some() {
            return Ok(());
        }

        // Our ephemeral secp256k1 keypair; Grin expects a COMPRESSED pubkey hex.
        let client_secret = EphemeralSecret::random(&mut OsRng);
        let client_pubkey_hex =
            hex::encode(client_secret.public_key().to_encoded_point(true).as_bytes());

        let body = JsonRpcRequest::new(
            "init_secure_api",
            json!({ "ecdh_pubkey": client_pubkey_hex }),
        );
        let bytes = self
            .post_capped(
                &self.owner_api_url,
                Some(("grin", self.owner_api_secret.expose())),
                &body,
            )
            .await?;

        // init_secure_api result is `{"Ok": "<server pubkey hex>"}`.
        let env: RpcEnvelope<String> = serde_json::from_slice(&bytes)
            .map_err(|_| AppError::NodeError("grin init_secure_api: invalid response".into()))?;
        if let Some(e) = env.error {
            return Err(AppError::NodeError(format!(
                "grin init_secure_api error {}",
                e.code
            )));
        }
        let server_pubkey_hex = match env.result {
            Some(GrinOk::Ok(s)) => s,
            _ => {
                return Err(AppError::NodeError(
                    "grin init_secure_api: no result".into(),
                ))
            }
        };

        let server_pubkey = PublicKey::from_sec1_bytes(
            &hex::decode(&server_pubkey_hex)
                .map_err(|_| AppError::NodeError("grin: invalid server pubkey hex".into()))?,
        )
        .map_err(|_| AppError::NodeError("grin: invalid server pubkey".into()))?;

        // Grin uses the raw ECDH x-coordinate directly as the AES-256 key.
        let shared = client_secret.diffie_hellman(&server_pubkey);
        let shared_key: [u8; 32] = *shared.raw_secret_bytes().as_ref();

        *guard = Some(SecureSession {
            shared_key,
            nonce_counter: 0,
        });
        Ok(())
    }

    /// Make an encrypted Owner-API call and deserialize the result as `R`.
    pub(super) async fn owner_rpc<T, R>(&self, method: &str, params: T) -> Result<R, AppError>
    where
        T: Serialize,
        R: DeserializeOwned,
    {
        self.ensure_session().await?;

        let inner_json = serde_json::to_string(&JsonRpcRequest::new(method, params))
            .map_err(|_| AppError::NodeError("grin: failed to encode request".into()))?;

        // Encrypt under the write lock (advances the nonce counter).
        let encrypted = {
            let mut guard = self.secure_session.write().await;
            let session = guard
                .as_mut()
                .ok_or_else(|| AppError::NodeError("grin secure session missing".into()))?;
            encrypt(session, &inner_json)?
        };

        let wrapper = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "encrypted_request_v3",
            "params": { "nonce": encrypted.nonce, "body_enc": encrypted.body_enc },
        });
        let bytes = self
            .post_capped(
                &self.owner_api_url,
                Some(("grin", self.owner_api_secret.expose())),
                &wrapper,
            )
            .await?;

        let outer: RpcEnvelope<EncryptedParts> = serde_json::from_slice(&bytes)
            .map_err(|_| AppError::NodeError("grin owner API: invalid response".into()))?;
        if let Some(e) = outer.error {
            // -32001 = secure session expired: clear it so the next call re-handshakes.
            if e.code == -32001 {
                *self.secure_session.write().await = None;
                return Err(AppError::NodeError(
                    "grin secure session expired, retry".into(),
                ));
            }
            return Err(AppError::NodeError(format!(
                "grin owner API error {}",
                e.code
            )));
        }
        let parts = match outer.result {
            Some(GrinOk::Ok(p)) => p,
            _ => return Err(AppError::NodeError("grin owner API: no result".into())),
        };

        let decrypted = {
            let guard = self.secure_session.read().await;
            let session = guard
                .as_ref()
                .ok_or_else(|| AppError::NodeError("grin secure session missing".into()))?;
            decrypt(session, &parts.nonce, &parts.body_enc)?
        };

        let inner: RpcEnvelope<R> = serde_json::from_str(&decrypted)
            .map_err(|_| AppError::NodeError("grin wallet: invalid response".into()))?;
        envelope_into_result(inner, "grin wallet")
    }

    /// Make a plain (unencrypted) node JSON-RPC call and deserialize as `R`.
    pub(super) async fn node_rpc<T, R>(
        &self,
        url: &str,
        auth: Option<(&str, &str)>,
        method: &str,
        params: T,
    ) -> Result<R, AppError>
    where
        T: Serialize,
        R: DeserializeOwned,
    {
        let bytes = self
            .post_capped(url, auth, &JsonRpcRequest::new(method, params))
            .await?;
        let env: RpcEnvelope<R> = serde_json::from_slice(&bytes)
            .map_err(|_| AppError::NodeError("grin node: invalid response".into()))?;
        envelope_into_result(env, "grin node")
    }

    /// POST a JSON body (optionally basic-auth'd) and return the size-capped
    /// response bytes. The body is never logged or echoed into an error.
    async fn post_capped<B: Serialize>(
        &self,
        url: &str,
        auth: Option<(&str, &str)>,
        body: &B,
    ) -> Result<Vec<u8>, AppError> {
        let mut req = self.http.post(url).json(body);
        if let Some((user, pass)) = auth {
            req = req.basic_auth(user, Some(pass));
        }
        let resp = req.send().await.map_err(|e| {
            // Transport-level error (connect/DNS/timeout) — not a response body.
            AppError::NodeError(format!("grin request failed: {e}"))
        })?;
        if !resp.status().is_success() {
            return Err(AppError::NodeError(format!(
                "grin HTTP {}",
                resp.status().as_u16()
            )));
        }
        read_capped(resp, MAX_GRIN_BODY_BYTES).await
    }
}

/// Map a parsed envelope to `R`, surfacing errors with a static label + code
/// only (never the untrusted error body).
fn envelope_into_result<R>(env: RpcEnvelope<R>, what: &str) -> Result<R, AppError> {
    if let Some(e) = env.error {
        return Err(AppError::NodeError(format!("{what} error {}", e.code)));
    }
    match env.result {
        Some(GrinOk::Ok(r)) => Ok(r),
        Some(GrinOk::Err(_)) => Err(AppError::NodeError(format!("{what} returned an error"))),
        None => Err(AppError::NodeError(format!("{what}: empty result"))),
    }
}

/// Encrypt a plaintext request body under the session key. Advances the nonce
/// counter with `checked_add` so it can never wrap and reuse a nonce.
fn encrypt(session: &mut SecureSession, plaintext: &str) -> Result<EncryptedParts, AppError> {
    let counter = session.nonce_counter;
    session.nonce_counter = counter
        .checked_add(1)
        .ok_or_else(|| AppError::NodeError("grin nonce counter exhausted".into()))?;

    // 12-byte AES-GCM nonce: 4 zero bytes || 8-byte big-endian counter.
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&counter.to_be_bytes());

    let cipher = Aes256Gcm::new_from_slice(&session.shared_key)
        .map_err(|_| AppError::NodeError("grin: cipher init failed".into()))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
        .map_err(|_| AppError::NodeError("grin: encryption failed".into()))?;

    Ok(EncryptedParts {
        nonce: hex::encode(nonce_bytes),
        body_enc: base64::engine::general_purpose::STANDARD.encode(ciphertext),
    })
}

/// Decrypt an encrypted response body under the session key.
fn decrypt(
    session: &SecureSession,
    nonce_hex: &str,
    body_enc_b64: &str,
) -> Result<String, AppError> {
    let nonce_bytes = hex::decode(nonce_hex)
        .map_err(|_| AppError::NodeError("grin: invalid nonce hex".into()))?;
    if nonce_bytes.len() != 12 {
        return Err(AppError::NodeError("grin: invalid nonce length".into()));
    }
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(body_enc_b64)
        .map_err(|_| AppError::NodeError("grin: invalid ciphertext".into()))?;

    let cipher = Aes256Gcm::new_from_slice(&session.shared_key)
        .map_err(|_| AppError::NodeError("grin: cipher init failed".into()))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_slice())
        .map_err(|_| AppError::NodeError("grin: decryption failed".into()))?;

    String::from_utf8(plaintext).map_err(|_| AppError::NodeError("grin: non-UTF8 response".into()))
}

/// Read a response body, enforcing `cap` as bytes arrive (content-length is
/// attacker-asserted, so it is not trusted).
async fn read_capped(resp: reqwest::Response, cap: usize) -> Result<Vec<u8>, AppError> {
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| AppError::NodeError("grin read failed".into()))?;
        if buf.len().saturating_add(chunk.len()) > cap {
            return Err(AppError::NodeError(
                "grin response exceeded size limit".into(),
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> SecureSession {
        SecureSession {
            shared_key: [7u8; 32],
            nonce_counter: 0,
        }
    }

    #[test]
    fn encrypt_decrypt_round_trips() {
        let mut s = session();
        let parts = encrypt(&mut s, r#"{"hello":"grin"}"#).unwrap();
        // Decryption uses the same key + the nonce carried on the wire.
        let out = decrypt(&s, &parts.nonce, &parts.body_enc).unwrap();
        assert_eq!(out, r#"{"hello":"grin"}"#);
    }

    #[test]
    fn nonce_counter_advances_and_is_unique() {
        let mut s = session();
        let a = encrypt(&mut s, "a").unwrap();
        let b = encrypt(&mut s, "b").unwrap();
        assert_ne!(a.nonce, b.nonce, "each message must use a fresh nonce");
        assert_eq!(s.nonce_counter, 2);
        // First nonce is 4 zero bytes || counter 0.
        assert_eq!(a.nonce, "000000000000000000000000");
        assert_eq!(b.nonce, "000000000000000000000001");
    }

    #[test]
    fn nonce_exhaustion_errors_not_panics() {
        let mut s = SecureSession {
            shared_key: [1u8; 32],
            nonce_counter: u64::MAX,
        };
        // checked_add overflow -> Err, never a wrap/panic (would reuse a nonce).
        assert!(encrypt(&mut s, "x").is_err());
    }

    #[test]
    fn decrypt_rejects_bad_nonce_and_ciphertext() {
        let s = session();
        assert!(decrypt(&s, "zz", "AAAA").is_err()); // bad hex
        assert!(decrypt(&s, "00", "AAAA").is_err()); // wrong nonce length
        assert!(decrypt(&s, "000000000000000000000000", "!!!!").is_err()); // bad b64
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let mut s = session();
        let parts = encrypt(&mut s, "secret").unwrap();
        let other = SecureSession {
            shared_key: [9u8; 32],
            nonce_counter: 0,
        };
        // GCM auth tag must reject decryption under a different key.
        assert!(decrypt(&other, &parts.nonce, &parts.body_enc).is_err());
    }

    #[test]
    fn envelope_maps_ok_err_empty() {
        let ok: RpcEnvelope<u64> = serde_json::from_str(r#"{"result":{"Ok":42}}"#).unwrap();
        assert_eq!(envelope_into_result(ok, "t").unwrap(), 42);

        let err: RpcEnvelope<u64> = serde_json::from_str(r#"{"result":{"Err":"nope"}}"#).unwrap();
        assert!(envelope_into_result(err, "t").is_err());

        let rpc_err: RpcEnvelope<u64> =
            serde_json::from_str(r#"{"error":{"code":-32000,"message":"boom"}}"#).unwrap();
        let e = envelope_into_result(rpc_err, "t").unwrap_err();
        // The untrusted message is not surfaced; only a static label + code.
        match e {
            AppError::NodeError(m) => {
                assert!(m.contains("-32000"));
                assert!(!m.contains("boom"));
            }
            other => panic!("expected NodeError, got {other:?}"),
        }
    }
}
