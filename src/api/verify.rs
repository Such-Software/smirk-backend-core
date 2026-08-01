//! Delegated settlement verification for peer instances (moon.vote).
//!
//! `POST /api/v1/verify` — the server side of moon.vote's delegated settlement
//! check. A peer instance asks this backend to confirm that a SPECIFIC on-chain
//! transaction (`tx_ref`) paid at least `amount` base units to `dest_address` on
//! the named coin, confirmed to this backend's per-asset depth. It verifies the
//! named tx (mirroring the wallet's own `UtxoEsplora`/LWS semantics), not the
//! aggregate funding of an address.
//!
//! UNAUTHENTICATED: the moon.vote client sends no bearer token, so this handler
//! deliberately does NOT call `extract_user_id_from_token`. Exposure is contained
//! at deploy time by an nginx allow-list to moon.vote's mesh IP; there is no code
//! auth here on purpose (adding one would reject the fixed peer client).
//!
//! Response discipline: EVERY business outcome — including a failed check — is a
//! `200 OK` carrying `{verified, sender, amount, reason}`, where `reason` is drawn
//! from the fixed vocabulary in [`reason`] that the moon.vote client maps to typed
//! errors. Only an INFRASTRUCTURE failure (chain disabled, node/LWS unreachable)
//! returns a non-2xx [`AppError`]; moon.vote treats non-2xx as a retryable backend
//! error, so a node being down must never surface as a false `{verified:false}`.

use std::sync::Arc;

use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use tracing::{instrument, warn};

use crate::api::wallet::{validate_cn_address, validate_hex, validate_hex64, validate_view_key};
use crate::error::AppError;
use crate::infra::electrum::ElectrumClient;
use crate::infra::grin::GrinClient;
use crate::infra::lws::LwsClient;
use crate::models::tip_status::confirmations_for_asset;
use crate::AppState;

/// The fixed `reason` vocabulary shared with the moon.vote client, which maps
/// each string to a typed error; ANY other string degrades to a generic error
/// there, so these MUST stay exact. `WRONG_SENDER` / `REF_MISMATCH` are part of
/// the shared contract but are not produced by the UTXO / CryptoNote paths here
/// (both report `sender: null` and do not gate on `ref_id`); kept for fidelity.
mod reason {
    pub const NOT_FOUND: &str = "not_found";
    pub const NOT_CONFIRMED: &str = "not_confirmed";
    pub const AMOUNT_TOO_LOW: &str = "amount_too_low";
    pub const DESTINATION_MISMATCH: &str = "destination_mismatch";
    #[allow(dead_code)]
    pub const WRONG_SENDER: &str = "wrong_sender";
    #[allow(dead_code)]
    pub const REF_MISMATCH: &str = "ref_mismatch";
}

// ── DTOs ──────────────────────────────────────────────────────────────────────

/// A delegated verification request. This is moon.vote's FIXED wire shape — do
/// not rename or reshape these fields.
//
// Deliberately omits `Debug`: it carries the optional private `view_key`
// (CryptoNote scan credential), matching the secret-bearing-request convention
// in [`crate::api::wallet::xmr_wow`] so it can't be dumped via a stray `{:?}`.
//
// `#[allow(dead_code)]`: several fields (`network`, `destination`,
// `expected_sender`, `ref_id`) are part of the fixed contract but are not
// consumed by the families implemented here — the payment target is fully
// specified by `dest_address` — so they are accepted for fidelity, not read.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct VerifyRequest {
    /// Coin slug (`btc`/`ltc`/`xmr`/`wow`); selects the chain client.
    pub coin: String,
    /// Settlement family: `utxo` | `cryptonote` | `grin` (lowercase).
    pub family: String,
    /// Network label (e.g. `btc-mainnet`); informational.
    pub network: String,
    /// Transaction id to verify (hex).
    pub tx_ref: String,
    /// Expected amount in BASE UNITS as a decimal string (satoshis for BTC/LTC,
    /// piconero/wownoshi for XMR/WOW).
    pub amount: String,
    /// `burn` | `pay_operator` | `pay_recipient`; the concrete target is
    /// `dest_address`.
    pub destination: String,
    /// Address the payment must have gone to. May be null.
    pub dest_address: Option<String>,
    /// Expected sender address, or empty string when unconstrained.
    pub expected_sender: String,
    /// Optional 64-hex settlement reference id.
    pub ref_id: Option<String>,
    /// Private view key (CryptoNote scan credential). REQUIRED to verify
    /// `xmr`/`wow`; absent for UTXO. Forwarded to the LWS; never stored or logged.
    #[serde(default)]
    pub view_key: Option<String>,
}

/// The verification outcome. On success `amount` is the observed base units and
/// `reason` is omitted; on a business failure only `reason` is set (from
/// [`reason`]). Absent optionals are omitted from the JSON.
#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl VerifyResponse {
    /// A verified payment: observed base units + optional sender (UTXO/CryptoNote
    /// carry no single sender, so they pass `None`).
    fn verified(amount: u64, sender: Option<String>) -> Self {
        Self {
            verified: true,
            sender,
            amount: Some(amount.to_string()),
            reason: None,
        }
    }

    /// A business failure carrying one of the fixed [`reason`] strings.
    fn failed(reason: &'static str) -> Self {
        Self {
            verified: false,
            sender: None,
            amount: None,
            reason: Some(reason.to_string()),
        }
    }
}

// ── chain-client resolution (mirrors `electrum_for` / `lws_for`) ──────────────

/// Resolve the Electrum client for a UTXO coin, or a validation error when the
/// coin is unknown or not enabled on this instance.
fn electrum_for<'a>(state: &'a AppState, coin: &str) -> Result<&'a ElectrumClient, AppError> {
    let client = match coin {
        "btc" => state.chains.btc.as_ref(),
        "ltc" => state.chains.ltc.as_ref(),
        other => {
            return Err(AppError::ValidationError(format!(
                "Invalid UTXO coin: {other} (expected btc or ltc)"
            )))
        }
    };
    client.ok_or_else(|| AppError::ValidationError(format!("{coin} not enabled")))
}

/// Resolve the LWS client for a CryptoNote coin, or a validation error when the
/// coin is unknown or not enabled on this instance.
fn lws_for<'a>(state: &'a AppState, coin: &str) -> Result<&'a LwsClient, AppError> {
    let client = match coin {
        "xmr" => state.chains.xmr.as_ref(),
        "wow" => state.chains.wow.as_ref(),
        other => {
            return Err(AppError::ValidationError(format!(
                "Invalid CryptoNote coin: {other} (expected xmr or wow)"
            )))
        }
    };
    client.ok_or_else(|| AppError::ValidationError(format!("{coin} not enabled")))
}

/// Resolve the Grin client for the `grin` coin, or a validation error when the coin
/// is unknown or Grin is not enabled on this instance. `state.chains.grin` is an
/// `Option<Arc<GrinClient>>`, so this uses `.as_deref()` (unlike the non-`Arc`
/// `electrum_for`/`lws_for`). A disabled/absent client is a non-2xx (400), never a
/// false `not_found`.
fn grin_for<'a>(state: &'a AppState, coin: &str) -> Result<&'a GrinClient, AppError> {
    if coin != "grin" {
        return Err(AppError::ValidationError(format!(
            "Invalid Grin coin: {coin} (expected grin)"
        )));
    }
    state
        .chains
        .grin
        .as_deref()
        .ok_or_else(|| AppError::ValidationError(format!("{coin} not enabled")))
}

/// Pure amount decision for a UTXO payment to the destination. `0` received means
/// the tx did not pay the destination at all (`destination_mismatch`); a positive
/// receipt below `expected` is `amount_too_low`; otherwise the observed amount is
/// returned. Split out so it is unit-testable without a live server.
fn utxo_amount_outcome(paid_to_dest: u64, expected: u64) -> Result<u64, &'static str> {
    if paid_to_dest == 0 {
        Err(reason::DESTINATION_MISMATCH)
    } else if paid_to_dest < expected {
        Err(reason::AMOUNT_TOO_LOW)
    } else {
        Ok(paid_to_dest)
    }
}

/// Pure depth-then-amount decision for a Grin output the recipient's `rewind_hash`
/// recognized. Below the coin's confirmation depth is `not_confirmed`; a recognized
/// output whose value is short is `amount_too_low`; otherwise the observed value is
/// returned. `not_found` (no recognized output at all) is decided by the caller
/// before this. Split out so it is unit-testable without a live wallet.
fn grin_amount_outcome(
    value: u64,
    confs: u64,
    needed: u64,
    expected: u64,
) -> Result<u64, &'static str> {
    if confs < needed {
        Err(reason::NOT_CONFIRMED)
    } else if value < expected {
        Err(reason::AMOUNT_TOO_LOW)
    } else {
        Ok(value)
    }
}

// ── per-family verification ───────────────────────────────────────────────────

/// Verify a BTC/LTC payment named by `tx_ref` to `dest_address`.
///
/// `get_transaction_verbose` maps an unknown tx and a node outage to the SAME
/// `NodeError`, so it cannot cleanly distinguish "the tx did not pay this
/// address" from "the node is down". We therefore consult the server's per-address
/// index first: `get_history(dest_address)` and look for `tx_ref`. Absent ⇒
/// `not_found` (a business outcome). Present but unconfirmed (`height <= 0`) ⇒
/// `not_confirmed`. Only then do we decode the tx to attribute the exact amount
/// paid to the destination. Any node/index error propagates as a non-2xx.
async fn verify_utxo(
    state: &AppState,
    coin: &str,
    req: &VerifyRequest,
    expected: u64,
) -> Result<VerifyResponse, AppError> {
    let electrum = electrum_for(state, coin)?;

    let Some(dest_address) = req.dest_address.as_deref() else {
        return Ok(VerifyResponse::failed(reason::DESTINATION_MISMATCH));
    };
    validate_hex(&req.tx_ref, "tx_ref", 64)?;

    // Per-address index first: it distinguishes "did not pay this address" from a
    // node error, which the verbose-tx fetch alone cannot.
    let history = electrum.get_history(dest_address).await?;
    let Some(entry) = history.iter().find(|e| e.tx_hash == req.tx_ref) else {
        return Ok(VerifyResponse::failed(reason::NOT_FOUND));
    };
    // Confirmed = in a block (`height > 0`); `0`/negative is mempool.
    if entry.height <= 0 {
        return Ok(VerifyResponse::failed(reason::NOT_CONFIRMED));
    }

    let tx = electrum.get_transaction_verbose(&req.tx_ref).await?;
    // Result-returning: a hostile/non-finite amount errors (non-2xx) rather than
    // silently coercing — never a false verify.
    let paid_to_dest = tx.total_received_at(dest_address)?;

    match utxo_amount_outcome(paid_to_dest, expected) {
        // UTXO has no single sender.
        Ok(observed) => Ok(VerifyResponse::verified(observed, None)),
        Err(r) => Ok(VerifyResponse::failed(r)),
    }
}

/// Verify an XMR/WOW payment named by `tx_ref` to `dest_address`.
///
/// Monero/Wownero are address + view-key SCAN (not txid lookup), so a private
/// view key is required; without it we cannot see the payment and return
/// `not_found` (never a 500). We scan the destination's txs, match `tx_ref`, and
/// require it be in a block AND confirmed to this coin's depth before comparing
/// the received amount.
async fn verify_cryptonote(
    state: &AppState,
    coin: &str,
    req: &VerifyRequest,
    expected: u64,
) -> Result<VerifyResponse, AppError> {
    let lws = lws_for(state, coin)?;

    let Some(view_key) = req.view_key.as_deref() else {
        warn!(
            %coin,
            "cryptonote verify requires a private view_key to scan the destination; none supplied — reporting not_found",
        );
        return Ok(VerifyResponse::failed(reason::NOT_FOUND));
    };
    let Some(dest_address) = req.dest_address.as_deref() else {
        return Ok(VerifyResponse::failed(reason::DESTINATION_MISMATCH));
    };
    validate_hex(&req.tx_ref, "tx_ref", 64)?;
    validate_view_key(view_key)?;
    validate_cn_address(dest_address)?;

    let txs = lws.get_address_txs(dest_address, view_key).await?;
    let Some(tx) = txs.transactions.iter().find(|t| t.hash == req.tx_ref) else {
        return Ok(VerifyResponse::failed(reason::NOT_FOUND));
    };
    if tx.mempool || tx.height == 0 {
        return Ok(VerifyResponse::failed(reason::NOT_CONFIRMED));
    }

    // Confirmation depth from the daemon (XMR 10, WOW 4). None / below threshold
    // ⇒ not yet confirmed.
    let needed = confirmations_for_asset(coin).max(0) as u64;
    match lws.get_transaction_confirmations(&req.tx_ref).await? {
        Some(n) if n >= needed => {}
        _ => return Ok(VerifyResponse::failed(reason::NOT_CONFIRMED)),
    }

    if tx.total_received < expected {
        return Ok(VerifyResponse::failed(reason::AMOUNT_TOO_LOW));
    }
    // CryptoNote receipts carry no single sender.
    Ok(VerifyResponse::verified(tx.total_received, None))
}

/// Verify a Grin (Mimblewimble) payment named by its output COMMITMENT (`tx_ref`).
///
/// Grin has NO address and NO txid: a received payment is a Pedersen output
/// commitment whose value is blinded, and only the recipient's `rewind_hash` VIEW
/// credential can recognize that output and read its value. We therefore REQUIRE
/// `view_key` (= the recipient `rewind_hash`); without it the output is invisible
/// and its amount unreadable, so we report `not_found` — never a 500 and never a
/// false verify — exactly as `verify_cryptonote` does for a missing view key.
///
/// `scan_rewind_hash` returns the outputs the credential owns (commitment, value in
/// nanogrin, inclusion height). We match `tx_ref` among them, gate on grin's 10-conf
/// depth, then compare the TRUE received value. Because only the true recipient's
/// credential recognizes the commitment, a match simultaneously proves destination
/// (recipient ownership) AND amount — the two facts a bare kernel excess cannot
/// prove, which is why we do NOT use `get_kernel` here (it adds a failure surface
/// and no soundness: Mimblewimble aggregation/cut-through leaves no on-chain join
/// binding a kernel excess to a specific output).
///
/// SOUNDNESS: Mimblewimble reveals no sender, so `sender` is always `None` and
/// `expected_sender` is unenforceable. `dest_address` is meaningless (no addresses)
/// and is ignored; recipient binding IS the rewind match. Any wallet/node outage is
/// a `NodeError` (non-2xx, retryable), never a false negative.
///
/// PAYER CONTRACT (footgun): `tx_ref` MUST be the recipient's received output
/// commitment (0x08/0x09-prefixed, 33 bytes). A grin KERNEL excess is ALSO a 66-hex
/// Pedersen point, so `validate_hex(66)` cannot tell them apart — but a kernel excess
/// never appears in a rewind scan, so submitting the `kernel_excess_hex` a wallet
/// conveniently surfaces yields a silent `not_found`. Likewise a send slate carries
/// both the recipient output AND the sender's CHANGE output; only the recipient's
/// commitment is recognized by the recipient's rewind_hash. The payer/frontend must
/// select the non-change received output, not the kernel excess or the change.
async fn verify_grin(
    state: &AppState,
    coin: &str,
    req: &VerifyRequest,
    expected: u64,
) -> Result<VerifyResponse, AppError> {
    let grin = grin_for(state, coin)?;

    let Some(rewind_hash) = req.view_key.as_deref() else {
        warn!(
            %coin,
            "grin verify requires the recipient rewind_hash (view_key) to recognize the output; none supplied — reporting not_found",
        );
        return Ok(VerifyResponse::failed(reason::NOT_FOUND));
    };
    // tx_ref = the received output's Pedersen commitment (33 bytes = 66 hex), one
    // byte longer than a 32-byte txid, so bound at 66 (a 64 cap would reject it).
    validate_hex(&req.tx_ref, "tx_ref", 66)?;
    validate_hex64(rewind_hash, "view_key")?;

    // Authoritative view-only scan (grin-wallet Owner API v3). A wallet/node error
    // propagates as NodeError (non-2xx) so moon.vote retries — never verified:false.
    let view = grin.scan_rewind_hash(rewind_hash, None).await?;
    // Commitments are lowercase hex on-chain; compare case-insensitively so a mere
    // casing difference is not a false not_found.
    let Some(output) = view
        .output_result
        .iter()
        .find(|o| o.commit.eq_ignore_ascii_case(&req.tx_ref))
    else {
        // This credential recognizes no output with this commitment: either the
        // payment never landed, or it did not go to this recipient.
        return Ok(VerifyResponse::failed(reason::NOT_FOUND));
    };

    let tip = grin.get_height().await?;
    let needed = confirmations_for_asset(coin).max(0) as u64;

    match grin_amount_outcome(output.value, output.confirmations(tip), needed, expected) {
        // Mimblewimble carries no sender.
        Ok(observed) => Ok(VerifyResponse::verified(observed, None)),
        Err(r) => Ok(VerifyResponse::failed(r)),
    }
}

// ── handler ───────────────────────────────────────────────────────────────────

/// Delegated settlement verification. UNAUTHENTICATED (see module docs); network-
/// restricted at deploy time.
#[instrument(
    skip_all,
    fields(coin = %req.coin, family = %req.family, network = %req.network)
)]
pub async fn verify_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, AppError> {
    let coin = req.coin.to_lowercase();
    let family = req.family.to_lowercase();

    // Base units are integers; a malformed amount is a client error, not a
    // business outcome.
    let expected: u64 = req
        .amount
        .parse()
        .map_err(|_| AppError::ValidationError("amount must be a base-unit integer".into()))?;

    let resp = match family.as_str() {
        "utxo" => verify_utxo(&state, &coin, &req, expected).await?,
        "cryptonote" => verify_cryptonote(&state, &coin, &req, expected).await?,
        "grin" => verify_grin(&state, &coin, &req, expected).await?,
        other => {
            return Err(AppError::ValidationError(format!(
                "unknown settlement family: {other}"
            )))
        }
    };
    Ok(Json(resp))
}

// ── router ────────────────────────────────────────────────────────────────────

/// The verify route, RELATIVE to the `/api/v1` mount point.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/verify", post(verify_handler))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utxo_amount_outcome_maps_to_reasons() {
        // Zero received = the tx did not pay the destination.
        assert_eq!(
            utxo_amount_outcome(0, 100),
            Err(reason::DESTINATION_MISMATCH)
        );
        // Positive but short.
        assert_eq!(utxo_amount_outcome(99, 100), Err(reason::AMOUNT_TOO_LOW));
        // Exact and over both verify, echoing the observed amount.
        assert_eq!(utxo_amount_outcome(100, 100), Ok(100));
        assert_eq!(utxo_amount_outcome(250, 100), Ok(250));
        // A zero expectation still requires a non-zero receipt to the address.
        assert_eq!(utxo_amount_outcome(0, 0), Err(reason::DESTINATION_MISMATCH));
        assert_eq!(utxo_amount_outcome(1, 0), Ok(1));
    }

    #[test]
    fn success_response_shape() {
        // Verified with no sender: only verified + amount are present.
        let v = serde_json::to_value(VerifyResponse::verified(12345, None)).unwrap();
        assert_eq!(v["verified"], serde_json::json!(true));
        assert_eq!(v["amount"], serde_json::json!("12345"));
        assert!(v.get("sender").is_none(), "sender omitted when None");
        assert!(v.get("reason").is_none(), "no reason on success");

        // Verified with a sender includes it.
        let v = serde_json::to_value(VerifyResponse::verified(1, Some("addr".into()))).unwrap();
        assert_eq!(v["sender"], serde_json::json!("addr"));
    }

    #[test]
    fn failure_response_shape() {
        let v = serde_json::to_value(VerifyResponse::failed(reason::NOT_FOUND)).unwrap();
        assert_eq!(v["verified"], serde_json::json!(false));
        assert_eq!(v["reason"], serde_json::json!("not_found"));
        assert!(v.get("amount").is_none(), "no amount on failure");
        assert!(v.get("sender").is_none(), "no sender on failure");
    }

    #[test]
    fn reason_vocabulary_is_exact() {
        // The moon.vote client maps these exact strings to typed errors.
        assert_eq!(reason::NOT_FOUND, "not_found");
        assert_eq!(reason::NOT_CONFIRMED, "not_confirmed");
        assert_eq!(reason::AMOUNT_TOO_LOW, "amount_too_low");
        assert_eq!(reason::DESTINATION_MISMATCH, "destination_mismatch");
        assert_eq!(reason::WRONG_SENDER, "wrong_sender");
        assert_eq!(reason::REF_MISMATCH, "ref_mismatch");
    }

    #[test]
    fn request_deserializes_moonvote_wire_shape() {
        // The exact UTXO request the fixed client sends (no view_key).
        let req: VerifyRequest = serde_json::from_str(
            r#"{
                "coin":"btc","family":"utxo","network":"btc-mainnet",
                "tx_ref":"deadbeef","amount":"1000","destination":"pay_operator",
                "dest_address":"bc1qexample","expected_sender":"","ref_id":null
            }"#,
        )
        .unwrap();
        assert_eq!(req.coin, "btc");
        assert_eq!(req.family, "utxo");
        assert_eq!(req.amount, "1000");
        assert_eq!(req.dest_address.as_deref(), Some("bc1qexample"));
        assert!(
            req.view_key.is_none(),
            "view_key defaults to None when absent"
        );

        // The later CryptoNote shape carries an optional view_key.
        let req: VerifyRequest = serde_json::from_str(
            r#"{
                "coin":"xmr","family":"cryptonote","network":"xmr-mainnet",
                "tx_ref":"abcd","amount":"42","destination":"pay_recipient",
                "dest_address":"4Aexample","expected_sender":"","ref_id":null,
                "view_key":"0f"
            }"#,
        )
        .unwrap();
        assert_eq!(req.view_key.as_deref(), Some("0f"));
    }

    #[test]
    fn grin_amount_outcome_maps_to_reasons() {
        // Below depth (needed=10) is not_confirmed, checked before amount.
        assert_eq!(
            grin_amount_outcome(1000, 9, 10, 500),
            Err(reason::NOT_CONFIRMED)
        );
        // Confirmed but short.
        assert_eq!(
            grin_amount_outcome(499, 10, 10, 500),
            Err(reason::AMOUNT_TOO_LOW)
        );
        // Exact and over both verify, echoing the observed nanogrin value.
        assert_eq!(grin_amount_outcome(500, 10, 10, 500), Ok(500));
        assert_eq!(
            grin_amount_outcome(1_000_000_000, 11, 10, 500),
            Ok(1_000_000_000)
        );
        // Depth is gated before amount even when the amount is fine.
        assert_eq!(
            grin_amount_outcome(500, 0, 10, 500),
            Err(reason::NOT_CONFIRMED)
        );
    }

    #[test]
    fn grin_output_confirmations_feed_the_outcome() {
        // The real depth path: build the output type and derive confs against a tip.
        use crate::infra::grin::ViewWalletOutputResult;
        let out = ViewWalletOutputResult {
            commit: "09abcd".into(),
            value: 750,
            height: 100,
            mmr_index: 0,
            is_coinbase: false,
            lock_height: 0,
        };
        // tip 100 -> 1 conf -> below 10 -> not_confirmed.
        assert_eq!(
            grin_amount_outcome(out.value, out.confirmations(100), 10, 500),
            Err(reason::NOT_CONFIRMED)
        );
        // tip 120 -> 21 confs -> verified, echoing the observed value.
        assert_eq!(
            grin_amount_outcome(out.value, out.confirmations(120), 10, 500),
            Ok(750)
        );
    }

    #[test]
    fn grin_request_deserializes_moonvote_wire_shape() {
        // The grin request: tx_ref = output commitment (66 hex), view_key =
        // recipient rewind_hash (64 hex), dest_address null (grin has no addresses).
        let req: VerifyRequest = serde_json::from_str(
            r#"{
                "coin":"grin","family":"grin","network":"grin-mainnet",
                "tx_ref":"090000000000000000000000000000000000000000000000000000000000000000",
                "amount":"1000000000","destination":"pay_operator",
                "dest_address":null,"expected_sender":"","ref_id":null,
                "view_key":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            }"#,
        )
        .unwrap();
        assert_eq!(req.coin, "grin");
        assert_eq!(req.family, "grin");
        assert_eq!(req.amount, "1000000000"); // 1 GRIN in nanogrin
        assert!(req.dest_address.is_none(), "grin has no address");
        assert_eq!(
            req.tx_ref.len(),
            66,
            "output commitment is 33 bytes = 66 hex"
        );
        assert_eq!(
            req.view_key.as_deref().map(str::len),
            Some(64),
            "rewind_hash is 32 bytes = 64 hex"
        );
    }
}
