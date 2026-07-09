//! grin-lws (Grin light-wallet-server) client.
//!
//! A faithful mirror of the Monero/Wownero [`LwsClient`](crate::infra::lws::LwsClient).
//! grin-lws scans the chain for registered `rewind_hash` view credentials and
//! answers register / balance / unspent-output / height queries; this module is a
//! hardened client of that service. Even though grin-lws is expected on loopback,
//! every response is treated as hostile:
//!
//!   * a single shared `reqwest::Client` with request + connect timeouts;
//!   * each response body is read through a **streaming size cap** and parsed with
//!     `serde_json::from_slice` — no byte-indexing of an untrusted body;
//!   * non-success responses map to a generic [`AppError::NodeError`] tagged with
//!     a static endpoint label + status — the response body is never interpolated
//!     into a log or error;
//!   * the admin key is held in a redacting [`Secret`] and skipped in tracing.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;
use tracing::instrument;

use super::types::*;
use crate::config::GrinLwsConfig;
use crate::core::secret::Secret;
use crate::error::AppError;

/// Per-request deadline.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// TCP connect deadline.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Hard cap on any grin-lws response body (enforced while streaming).
const MAX_GRIN_LWS_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Client for a grin-lws instance. Cheap to clone (`reqwest::Client` is an `Arc`
/// internally), so it lives directly in the cloneable [`ChainClients`].
#[derive(Clone)]
pub struct GrinLwsClient {
    user_url: String,
    /// Reserved for the bearer-gated admin API (`list_accounts` / `rescan`),
    /// mirroring the monero-lws admin surface; not yet driven by a client method.
    #[allow(dead_code)]
    admin_url: Option<String>,
    #[allow(dead_code)]
    admin_key: Secret,
    http: reqwest::Client,
}

impl GrinLwsClient {
    /// Construct a client with a shared timeout-bounded HTTP client.
    pub fn new(cfg: &GrinLwsConfig) -> Result<Self, AppError> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|_| AppError::NodeError("failed to build grin-lws HTTP client".into()))?;
        Ok(Self {
            user_url: cfg.url.clone(),
            admin_url: cfg.admin_url.clone(),
            admin_key: Secret::new(cfg.admin_key.clone()),
            http,
        })
    }

    // ── user API ────────────────────────────────────────────────────────────

    /// `POST /register` — add a `rewind_hash` view credential to the scan set
    /// (idempotent). `start_height` is the wallet birthday; omit for the tip.
    #[instrument(skip(self, rewind_hash))]
    pub async fn register(
        &self,
        rewind_hash: &str,
        start_height: Option<u64>,
    ) -> Result<GrinLwsRegister, AppError> {
        let url = format!("{}/register", self.user_url);
        let body = RegisterBody {
            rewind_hash: rewind_hash.to_string(),
            start_height,
        };
        self.post_json(url, "register", &body).await
    }

    /// `POST /get_balance` — the account's unspent total + scan progress.
    #[instrument(skip(self, rewind_hash))]
    pub async fn get_balance(&self, rewind_hash: &str) -> Result<GrinLwsBalance, AppError> {
        let url = format!("{}/get_balance", self.user_url);
        let body = RewindHashBody {
            rewind_hash: rewind_hash.to_string(),
        };
        self.post_json(url, "get_balance", &body).await
    }

    /// `POST /get_unspent_outs` — the spendable set WITH derivation paths.
    #[instrument(skip(self, rewind_hash))]
    pub async fn get_unspent_outs(
        &self,
        rewind_hash: &str,
    ) -> Result<GrinLwsUnspentOuts, AppError> {
        let url = format!("{}/get_unspent_outs", self.user_url);
        let body = RewindHashBody {
            rewind_hash: rewind_hash.to_string(),
        };
        self.post_json(url, "get_unspent_outs", &body).await
    }

    /// `GET /height` — current chain tip height.
    #[instrument(skip(self))]
    pub async fn get_height(&self) -> Result<u64, AppError> {
        #[derive(Deserialize)]
        struct HeightResponse {
            height: u64,
        }
        let url = format!("{}/height", self.user_url);
        let resp: HeightResponse = self.get_json(url, "height").await?;
        Ok(resp.height)
    }

    /// Liveness probe — reaches grin-lws (`GET /height`), discarding the result.
    pub async fn health_check(&self) -> Result<(), AppError> {
        self.get_height().await?;
        Ok(())
    }

    // ── internal HTTP helpers ─────────────────────────────────────────────────

    /// POST a JSON body and deserialize a successful response from a size-capped
    /// buffer. Non-success → generic `NodeError` (no body interpolation).
    async fn post_json<B, R>(
        &self,
        url: String,
        label: &'static str,
        body: &B,
    ) -> Result<R, AppError>
    where
        B: Serialize,
        R: DeserializeOwned,
    {
        let resp = self.http.post(&url).json(body).send().await.map_err(|e| {
            // Transport-level failure (connect/DNS/timeout) — not a response
            // body. Safe to log privately; redacted from the client response.
            AppError::NodeError(format!("grin-lws {label} request failed: {e}"))
        })?;
        if !resp.status().is_success() {
            return Err(self.node_err_status(label, resp.status()));
        }
        let bytes = read_capped(resp, MAX_GRIN_LWS_BODY_BYTES).await?;
        serde_json::from_slice::<R>(&bytes).map_err(|_| self.node_err(label, "invalid response"))
    }

    /// GET and deserialize a successful response from a size-capped buffer.
    /// Non-success → generic `NodeError` (no body interpolation).
    async fn get_json<R>(&self, url: String, label: &'static str) -> Result<R, AppError>
    where
        R: DeserializeOwned,
    {
        let resp = self.http.get(&url).send().await.map_err(|e| {
            // Transport-level failure (connect/DNS/timeout) — not a response
            // body. Safe to log privately; redacted from the client response.
            AppError::NodeError(format!("grin-lws {label} request failed: {e}"))
        })?;
        if !resp.status().is_success() {
            return Err(self.node_err_status(label, resp.status()));
        }
        let bytes = read_capped(resp, MAX_GRIN_LWS_BODY_BYTES).await?;
        serde_json::from_slice::<R>(&bytes).map_err(|_| self.node_err(label, "invalid response"))
    }

    /// A node error tagged with the static endpoint `label`. `label`/`detail` are
    /// static; the untrusted response body is never included.
    fn node_err(&self, label: &str, detail: &str) -> AppError {
        AppError::NodeError(format!("grin-lws {label}: {detail}"))
    }

    fn node_err_status(&self, label: &str, status: reqwest::StatusCode) -> AppError {
        AppError::NodeError(format!("grin-lws {label} failed (HTTP {})", status.as_u16()))
    }
}

/// Read a response body into memory, enforcing `cap` as bytes arrive (the
/// content-length header is attacker-asserted, so it is not trusted).
async fn read_capped(resp: reqwest::Response, cap: usize) -> Result<Vec<u8>, AppError> {
    use futures::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| AppError::NodeError("grin-lws read failed".into()))?;
        if buf.len().saturating_add(chunk.len()) > cap {
            return Err(AppError::NodeError(
                "grin-lws response exceeded size limit".into(),
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> GrinLwsConfig {
        GrinLwsConfig {
            url: "http://127.0.0.1:8453".into(),
            admin_url: Some("http://127.0.0.1:8454".into()),
            admin_key: "test-admin-key".into(),
        }
    }

    #[test]
    fn new_builds_a_client() {
        assert!(GrinLwsClient::new(&cfg()).is_ok());
    }

    #[test]
    fn admin_key_is_redacted_in_debug() {
        let client = GrinLwsClient::new(&cfg()).unwrap();
        // The Secret wrapper must hide the key even if the field is formatted.
        assert_eq!(format!("{:?}", client.admin_key), "Secret(***)");
        assert!(!format!("{:?}", client.admin_key).contains("test-admin-key"));
    }
}
