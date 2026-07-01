//! BTCPay-compatible payment adapter.
//!
//! Speaks the BTCPay Greenfield invoice API (`POST/GET
//! /api/v1/stores/{store}/invoices`), which this project's own non-custodial
//! checkout apps (xmrcheckout / wowcheckout) implement, alongside BTCPay Server
//! and its Monero plugin — so one adapter serves every coin those processors
//! support.
//!
//! Response hygiene mirrors the LWS client (the processor may be remote):
//!   * one shared `reqwest::Client` with request + connect timeouts;
//!   * bodies read through a streaming size cap, then `serde_json::from_slice`
//!     (the content-length header is attacker-asserted);
//!   * non-success maps to a generic [`AppError::NodeError`] with a static label
//!     + status — the response body is never interpolated into a log or error;
//!   * the API key rides in a redacting [`Secret`], `skip`-ped from every span.

use std::time::Duration;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::instrument;

use super::{Invoice, InvoiceRequest, InvoiceStatus, PaymentProvider};
use crate::config::PaymentConfig;
use crate::core::secret::Secret;
use crate::error::AppError;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Hard cap on any processor response body (enforced while streaming).
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// A BTCPay-compatible invoice processor (one store).
#[derive(Clone)]
pub struct BtcPayProvider {
    /// Base URL, no trailing slash (e.g. `https://pay.example.org`).
    base_url: String,
    store_id: String,
    api_key: Secret,
    http: reqwest::Client,
}

impl BtcPayProvider {
    /// Build from the pay-to-register config. Assumes the config was validated
    /// (non-empty URL/store/key); a malformed HTTP client build fails closed.
    pub fn new(cfg: &PaymentConfig) -> Result<Self, AppError> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|_| AppError::ConfigError("failed to build payment HTTP client".into()))?;
        Ok(Self {
            base_url: cfg.provider_url.trim_end_matches('/').to_string(),
            store_id: cfg.store_id.clone(),
            api_key: Secret::new(cfg.api_key.clone()),
            http,
        })
    }

    /// Map the operator's numeric confirmations-to-finalize onto BTCPay's
    /// coarser `speedPolicy` buckets. BTCPay expresses finality as a policy, not
    /// an arbitrary N, so this rounds UP to the nearest bucket (an operator
    /// needing an exact/deeper count sets it on the processor merchant default).
    fn speed_policy(confirmations: u32) -> &'static str {
        match confirmations {
            0 => "HighSpeed",          // 0-conf
            1 => "MediumSpeed",        // 1 conf
            2..=5 => "LowMediumSpeed", // 2 conf
            _ => "LowSpeed",           // 6 conf
        }
    }

    /// Map a BTCPay invoice status string onto the neutral status. Unknown /
    /// unrecognized values fall to [`InvoiceStatus::Pending`] — fail-safe, since
    /// only `Settled` grants a registration.
    fn map_status(s: &str) -> InvoiceStatus {
        match s {
            // Greenfield v1 terminal-paid state, plus legacy synonyms for
            // cross-version robustness.
            "Settled" | "Complete" | "Confirmed" => InvoiceStatus::Settled,
            "Processing" | "Paid" => InvoiceStatus::Detected,
            "Expired" => InvoiceStatus::Expired,
            "Invalid" => InvoiceStatus::Invalid,
            _ => InvoiceStatus::Pending, // "New" and anything unrecognized
        }
    }

    fn to_invoice(resp: BtcPayInvoiceResp) -> Invoice {
        let bind = resp
            .metadata
            .as_ref()
            .and_then(|m| m.get("smirkBind"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        Invoice {
            id: resp.id,
            // Prefer the hosted checkout link; fall back to any address field.
            pay_to: resp.checkout_link.or(resp.address).unwrap_or_default(),
            status: Self::map_status(&resp.status),
            bind,
        }
    }

    fn node_err(&self, label: &str, detail: &str) -> AppError {
        AppError::NodeError(format!("payment processor {label}: {detail}"))
    }

    /// POST a JSON body and deserialize a size-capped success response.
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
        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("token {}", self.api_key.expose()))
            .json(body)
            .send()
            .await
            .map_err(|_| self.node_err(label, "request failed"))?;
        self.parse(resp, label).await
    }

    /// GET and deserialize a size-capped success response.
    async fn get_json<R: DeserializeOwned>(
        &self,
        url: String,
        label: &'static str,
    ) -> Result<R, AppError> {
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("token {}", self.api_key.expose()))
            .send()
            .await
            .map_err(|_| self.node_err(label, "request failed"))?;
        self.parse(resp, label).await
    }

    async fn parse<R: DeserializeOwned>(
        &self,
        resp: reqwest::Response,
        label: &'static str,
    ) -> Result<R, AppError> {
        if !resp.status().is_success() {
            return Err(AppError::NodeError(format!(
                "payment processor {label} failed (HTTP {})",
                resp.status().as_u16()
            )));
        }
        let bytes = read_capped(resp, MAX_BODY_BYTES).await?;
        serde_json::from_slice::<R>(&bytes).map_err(|_| self.node_err(label, "invalid response"))
    }
}

#[async_trait::async_trait]
impl PaymentProvider for BtcPayProvider {
    fn kind(&self) -> &'static str {
        "btcpay"
    }

    #[instrument(skip(self, req), fields(store = %self.store_id))]
    async fn create_invoice(&self, req: &InvoiceRequest) -> Result<Invoice, AppError> {
        let url = format!("{}/api/v1/stores/{}/invoices", self.base_url, self.store_id);
        let body = BtcPayCreateReq {
            amount: &req.amount,
            currency: &req.currency,
            metadata: serde_json::json!({ "smirkBind": req.bind }),
            checkout: BtcPayCheckout {
                speed_policy: Self::speed_policy(req.confirmations),
                expiration_minutes: req.expires_minutes,
            },
        };
        let resp: BtcPayInvoiceResp = self.post_json(url, "create_invoice", &body).await?;
        Ok(Self::to_invoice(resp))
    }

    #[instrument(skip(self), fields(store = %self.store_id))]
    async fn get_invoice(&self, id: &str) -> Result<Invoice, AppError> {
        // `id` is always one we minted and stored, but percent-encode the path
        // segment anyway so a stray value can never traverse the processor URL.
        let enc = urlencoding::encode(id);
        let url = format!(
            "{}/api/v1/stores/{}/invoices/{}",
            self.base_url, self.store_id, enc
        );
        let resp: BtcPayInvoiceResp = self.get_json(url, "get_invoice").await?;
        Ok(Self::to_invoice(resp))
    }
}

// ── wire types ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct BtcPayCreateReq<'a> {
    amount: &'a str,
    currency: &'a str,
    metadata: serde_json::Value,
    checkout: BtcPayCheckout,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BtcPayCheckout {
    speed_policy: &'static str,
    expiration_minutes: u32,
}

/// The subset of a BTCPay invoice we consume. Extra fields are ignored.
#[derive(Deserialize)]
struct BtcPayInvoiceResp {
    id: String,
    #[serde(default)]
    status: String,
    /// Hosted checkout page URL (`checkoutLink`).
    #[serde(default, rename = "checkoutLink")]
    checkout_link: Option<String>,
    /// A direct address, if the processor returns one (xmrcheckout native shape).
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
}

/// Read a response body into memory, enforcing `cap` as bytes arrive (the
/// content-length header is attacker-asserted, so it is not trusted).
async fn read_capped(resp: reqwest::Response, cap: usize) -> Result<Vec<u8>, AppError> {
    use futures::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|_| AppError::NodeError("payment processor read failed".into()))?;
        if buf.len().saturating_add(chunk.len()) > cap {
            return Err(AppError::NodeError(
                "payment processor response exceeded size limit".into(),
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PaymentConfig {
        PaymentConfig {
            require_payment: true,
            provider: "btcpay".into(),
            provider_url: "https://pay.example.org/".into(),
            store_id: "store-123".into(),
            api_key: "xmrcheckout_secretkey".into(),
            amount: "0.01".into(),
            currency: "XMR".into(),
            confirmations: 1,
            expires_minutes: 60,
        }
    }

    #[test]
    fn base_url_trailing_slash_trimmed() {
        let p = BtcPayProvider::new(&cfg()).unwrap();
        assert_eq!(p.base_url, "https://pay.example.org");
    }

    #[test]
    fn api_key_is_redacted_in_debug() {
        let p = BtcPayProvider::new(&cfg()).unwrap();
        assert_eq!(format!("{:?}", p.api_key), "Secret(***)");
        assert!(!format!("{:?}", p.api_key).contains("secretkey"));
    }

    #[test]
    fn speed_policy_buckets() {
        assert_eq!(BtcPayProvider::speed_policy(0), "HighSpeed");
        assert_eq!(BtcPayProvider::speed_policy(1), "MediumSpeed");
        assert_eq!(BtcPayProvider::speed_policy(2), "LowMediumSpeed");
        assert_eq!(BtcPayProvider::speed_policy(5), "LowMediumSpeed");
        assert_eq!(BtcPayProvider::speed_policy(6), "LowSpeed");
        assert_eq!(BtcPayProvider::speed_policy(100), "LowSpeed");
    }

    #[test]
    fn status_map_only_settled_grants() {
        assert_eq!(
            BtcPayProvider::map_status("Settled"),
            InvoiceStatus::Settled
        );
        assert_eq!(
            BtcPayProvider::map_status("Complete"),
            InvoiceStatus::Settled
        );
        assert_eq!(
            BtcPayProvider::map_status("Confirmed"),
            InvoiceStatus::Settled
        );
        assert_eq!(
            BtcPayProvider::map_status("Processing"),
            InvoiceStatus::Detected
        );
        assert_eq!(
            BtcPayProvider::map_status("Expired"),
            InvoiceStatus::Expired
        );
        assert_eq!(
            BtcPayProvider::map_status("Invalid"),
            InvoiceStatus::Invalid
        );
        // "New" and anything unrecognized are Pending — never grant.
        assert_eq!(BtcPayProvider::map_status("New"), InvoiceStatus::Pending);
        assert_eq!(BtcPayProvider::map_status("weird"), InvoiceStatus::Pending);
        assert_eq!(BtcPayProvider::map_status(""), InvoiceStatus::Pending);
    }

    #[test]
    fn to_invoice_extracts_bind_and_pay_to() {
        let resp: BtcPayInvoiceResp = serde_json::from_value(serde_json::json!({
            "id": "inv-1",
            "status": "Settled",
            "checkoutLink": "https://pay.example.org/i/inv-1",
            "metadata": { "smirkBind": "abc123", "orderId": "x" }
        }))
        .unwrap();
        let inv = BtcPayProvider::to_invoice(resp);
        assert_eq!(inv.id, "inv-1");
        assert_eq!(inv.pay_to, "https://pay.example.org/i/inv-1");
        assert_eq!(inv.status, InvoiceStatus::Settled);
        assert_eq!(inv.bind.as_deref(), Some("abc123"));
    }

    #[test]
    fn to_invoice_tolerates_missing_optional_fields() {
        // No checkoutLink / metadata: address fallback, no bind, safe status.
        let resp: BtcPayInvoiceResp = serde_json::from_value(serde_json::json!({
            "id": "inv-2",
            "status": "New",
            "address": "4ADDR"
        }))
        .unwrap();
        let inv = BtcPayProvider::to_invoice(resp);
        assert_eq!(inv.pay_to, "4ADDR");
        assert_eq!(inv.status, InvoiceStatus::Pending);
        assert!(inv.bind.is_none());
    }

    #[test]
    fn create_request_serializes_camelcase_checkout() {
        let body = BtcPayCreateReq {
            amount: "0.01",
            currency: "XMR",
            metadata: serde_json::json!({ "smirkBind": "abc" }),
            checkout: BtcPayCheckout {
                speed_policy: "MediumSpeed",
                expiration_minutes: 60,
            },
        };
        let v = serde_json::to_value(&body).unwrap();
        assert_eq!(v["amount"], "0.01");
        assert_eq!(v["currency"], "XMR");
        assert_eq!(v["metadata"]["smirkBind"], "abc");
        assert_eq!(v["checkout"]["speedPolicy"], "MediumSpeed");
        assert_eq!(v["checkout"]["expirationMinutes"], 60);
    }
}
