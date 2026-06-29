//! Monero/Wownero wallet handlers — authenticated, stateless-forward proxies
//! over the [`LwsClient`](crate::infra::lws::LwsClient).
//!
//! The backend is non-custodial and holds no view secret: the wallet sends its
//! private view key per request, the backend forwards it to the LWS (which holds
//! it only for scanning), and the wallet constructs + signs spends locally. The
//! one-time `register` call forwards the view key to the LWS `add_account` so it
//! begins scanning.
//!
//! Conventions (matching [`crate::api::users`] / [`super::btc_ltc`]):
//! * JWT-gated; the view key is `skip`-ped from every span so it is never logged.
//! * `asset` is a lowercase string (`"xmr"`/`"wow"`); disabled/unknown is a 400.
//! * Amounts are atomic units (piconero / wownoshi) as `u64`.
//! * snake_case wire fields; every DTO derives `utoipa::ToSchema`.
//! * Routes are RELATIVE to the `/api/v1` mount point; see [`routes`].

use std::sync::Arc;

use axum::{
    extract::{DefaultBodyLimit, State},
    http::HeaderMap,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use super::{validate_cn_address, validate_hex, validate_view_key};
use crate::api::middleware::extract_user_id_from_token;
use crate::error::AppError;
use crate::infra::lws::{
    sum_mempool_received, AddressTx, LwsClient, RandomOutput, SpentOutput, UnspentOutput,
};
use crate::AppState;

/// Cap on a submitted Monero/Wownero tx hex. CryptoNote txs (rings, bulletproofs)
/// are larger than UTXO txs; 2 MiB of hex is well above any real single tx.
const MAX_CN_TX_HEX_LEN: usize = 2 * 1024 * 1024;

/// Resolve the LWS client for a CryptoNote asset, or a 400 (unknown / disabled).
fn lws_for<'a>(state: &'a AppState, asset: &str) -> Result<&'a LwsClient, AppError> {
    let client = match asset {
        "xmr" => state.chains.xmr.as_ref(),
        "wow" => state.chains.wow.as_ref(),
        other => {
            return Err(AppError::ValidationError(format!(
                "Invalid CryptoNote asset: {other} (expected xmr or wow)"
            )))
        }
    };
    client.ok_or_else(|| {
        AppError::ValidationError(format!("{asset} support is not enabled on this server"))
    })
}

// ── request DTOs ──────────────────────────────────────────────────────────────

/// Address + private view key for a per-account query.
// Deliberately omits `Debug`: it carries the private `view_key`, matching the
// crate convention for secret-bearing request structs — so it can't be dumped in
// cleartext via a stray `{:?}`, panic message, or added log line.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct ViewRequest {
    /// `xmr` or `wow`.
    pub asset: String,
    pub address: String,
    /// Private view key (64 hex). Forwarded to the LWS; never stored or logged.
    pub view_key: String,
}

/// Register (or import-with-height) an account for LWS scanning.
// Omits `Debug` (carries the private `view_key`) — see `ViewRequest`.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct RegisterRequest {
    pub asset: String,
    pub address: String,
    /// Private view key (64 hex). Forwarded to the LWS; never stored or logged.
    pub view_key: String,
    /// Scan from this block height (wallet birthday). Omit to scan from now.
    pub start_height: Option<u64>,
}

/// Request decoy outputs for ring construction.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RandomOutsRequest {
    pub asset: String,
    /// Decoys per real output (protocol ring size; clamped server-side).
    pub count: u32,
    /// Amounts to request decoys for (`["0"]` for RingCT).
    pub amounts: Vec<String>,
}

/// Submit a finalized, signed transaction.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SubmitRequest {
    pub asset: String,
    /// Hex-encoded signed transaction blob.
    pub tx_hex: String,
}

/// Asset-only query.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct LwsAssetRequest {
    /// `xmr` or `wow`.
    pub asset: String,
}

/// Confirmation-count query for a tx.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ConfirmationsRequest {
    pub asset: String,
    /// Transaction id (64 hex).
    pub txid: String,
}

// ── response DTOs ─────────────────────────────────────────────────────────────

/// Balance + scan state, as a **verification passthrough**. The backend holds no
/// spend key, so it cannot net out spends; the wallet computes the true spendable
/// balance client-side: `total_received − sum(spent_outputs it verifies with the
/// spend key) − locked_balance`. `spent_outputs` are therefore CANDIDATES (some
/// are ring decoys of the user's own outputs); `pending_balance` is the 0-conf
/// (mempool) received.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LwsBalanceResponse {
    pub asset: String,
    pub total_received: u64,
    pub locked_balance: u64,
    /// Unconfirmed (mempool) received — 0-conf. `0` until the LWS reports mempool
    /// rows (the monero-lws mempool feature); never negative.
    pub pending_balance: u64,
    pub start_height: u64,
    pub scanned_height: u64,
    pub blockchain_height: u64,
    pub transaction_count: u64,
    /// Candidate spent outputs (confirmed + mempool) for client-side key-image
    /// verification with the spend key. Never authoritative server-side.
    pub spent_outputs: Vec<SpentOutputDto>,
}

/// A candidate spent output (verify with the spend key before trusting).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SpentOutputDto {
    pub amount: u64,
    pub key_image: String,
    pub tx_pub_key: String,
    pub out_index: u64,
    pub mixin: u64,
}

/// A transaction in the account's history.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TxDto {
    pub hash: String,
    pub height: u64,
    pub timestamp: String,
    pub total_received: u64,
    /// "Possible" sent — candidate spends, not authoritative.
    pub total_sent: u64,
    pub mempool: bool,
    pub unlock_time: u64,
    pub payment_id: Option<String>,
    pub spent_outputs: Vec<SpentOutputDto>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LwsHistoryResponse {
    pub asset: String,
    pub transactions: Vec<TxDto>,
}

/// An unspent output for spend construction.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UnspentOutputDto {
    pub amount: u64,
    pub public_key: String,
    pub tx_pub_key: String,
    pub index: u32,
    pub global_index: u64,
    pub height: u64,
    pub timestamp: String,
    pub tx_hash: String,
    pub rct: String,
    /// Key images seen on-chain that may correspond to this output being spent.
    pub spend_key_images: Vec<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UnspentOutsResponse {
    pub asset: String,
    pub outputs: Vec<UnspentOutputDto>,
    pub per_byte_fee: u64,
    pub fee_mask: u64,
    pub fork_version: u8,
}

/// A decoy output.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RandomOutputDto {
    pub global_index: u64,
    pub public_key: String,
    pub rct: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AmountOutsDto {
    pub amount: String,
    pub outputs: Vec<RandomOutputDto>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RandomOutsResponse {
    pub asset: String,
    pub amount_outs: Vec<AmountOutsDto>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct HeightResponse {
    pub asset: String,
    pub height: u64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ConfirmationsResponse {
    pub asset: String,
    /// Confirmations, or `null` if the tx is unknown / not yet in a block.
    pub confirmations: Option<u64>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OkResponse {
    pub ok: bool,
}

// ── mappers (infra type -> wire DTO) ──────────────────────────────────────────

fn spent_dto(s: SpentOutput) -> SpentOutputDto {
    SpentOutputDto {
        amount: s.amount,
        key_image: s.key_image,
        tx_pub_key: s.tx_pub_key,
        out_index: s.out_index,
        mixin: s.mixin,
    }
}

fn tx_dto(t: AddressTx) -> TxDto {
    TxDto {
        hash: t.hash,
        height: t.height,
        timestamp: t.timestamp,
        total_received: t.total_received,
        total_sent: t.total_sent,
        mempool: t.mempool,
        unlock_time: t.unlock_time,
        payment_id: t.payment_id,
        spent_outputs: t.spent_outputs.into_iter().map(spent_dto).collect(),
    }
}

fn unspent_dto(u: UnspentOutput) -> UnspentOutputDto {
    UnspentOutputDto {
        amount: u.amount,
        public_key: u.public_key,
        tx_pub_key: u.tx_pub_key,
        index: u.index,
        global_index: u.global_index,
        height: u.height,
        timestamp: u.timestamp,
        tx_hash: u.tx_hash,
        rct: u.rct,
        spend_key_images: u.spend_key_images,
    }
}

fn random_dto(r: RandomOutput) -> RandomOutputDto {
    RandomOutputDto {
        global_index: r.global_index,
        public_key: r.public_key,
        rct: r.rct,
    }
}

// ── handlers ──────────────────────────────────────────────────────────────────

/// Register an account (its view key) with the LWS so it begins scanning.
/// Idempotent at the LWS; pass `start_height` to scan from a wallet birthday.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/lws/register",
    request_body = RegisterRequest,
    responses(
        (status = 200, description = "Account registered for scanning", body = OkResponse),
        (status = 400, description = "Invalid/disabled asset, address, or view key"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable")
    ),
    tag = "xmr_wow"
)]
#[instrument(skip(state, headers, req), fields(asset = %req.asset))]
pub async fn register(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<OkResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    let client = lws_for(&state, &asset)?;
    validate_cn_address(&req.address)?;
    validate_view_key(&req.view_key)?;

    match req.start_height {
        Some(h) => {
            // Restore: gate the scan depth against this instance's policy (the
            // backfill cost lands on our LWS). `None` (create) needs no check.
            let tip = client.get_blockchain_height().await?;
            state.config.restore.enforce(&asset, h, tip)?;
            client
                .import_account(&req.address, &req.view_key, h)
                .await?
        }
        None => client.register_account(&req.address, &req.view_key).await?,
    }
    Ok(Json(OkResponse { ok: true }))
}

/// Balance + scan state for an account.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/lws/balance",
    request_body = ViewRequest,
    responses(
        (status = 200, description = "Account balance and scan state", body = LwsBalanceResponse),
        (status = 400, description = "Invalid/disabled asset, address, or view key"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable")
    ),
    tag = "xmr_wow"
)]
#[instrument(skip(state, headers, req), fields(asset = %req.asset))]
pub async fn balance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ViewRequest>,
) -> Result<Json<LwsBalanceResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    let client = lws_for(&state, &asset)?;
    validate_cn_address(&req.address)?;
    validate_view_key(&req.view_key)?;

    // Verification passthrough: address-info gives received/locked/heights;
    // address-txs gives the candidate spent_outputs (the wallet verifies them
    // with its spend key) and the mempool rows (0-conf pending). Fetched
    // together so a balance read is one round-trip of latency, not two.
    let (info, txs) = tokio::join!(
        client.get_address_info(&req.address, &req.view_key),
        client.get_address_txs(&req.address, &req.view_key),
    );
    let info = info?;
    let txs = txs?;

    let pending_balance = sum_mempool_received(&txs.transactions);
    let spent_outputs: Vec<SpentOutputDto> = txs
        .transactions
        .into_iter()
        .flat_map(|t| t.spent_outputs)
        .map(spent_dto)
        .collect();

    Ok(Json(LwsBalanceResponse {
        asset,
        total_received: info.total_received,
        locked_balance: info.locked_funds,
        pending_balance,
        start_height: info.start_height,
        scanned_height: info.scanned_height,
        blockchain_height: info.blockchain_height,
        transaction_count: info.transaction_count,
        spent_outputs,
    }))
}

/// Transaction history (confirmed + mempool) for an account.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/lws/history",
    request_body = ViewRequest,
    responses(
        (status = 200, description = "Account transaction history", body = LwsHistoryResponse),
        (status = 400, description = "Invalid/disabled asset, address, or view key"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable")
    ),
    tag = "xmr_wow"
)]
#[instrument(skip(state, headers, req), fields(asset = %req.asset))]
pub async fn history(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ViewRequest>,
) -> Result<Json<LwsHistoryResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    let client = lws_for(&state, &asset)?;
    validate_cn_address(&req.address)?;
    validate_view_key(&req.view_key)?;

    let txs = client.get_address_txs(&req.address, &req.view_key).await?;
    Ok(Json(LwsHistoryResponse {
        asset,
        transactions: txs.transactions.into_iter().map(tx_dto).collect(),
    }))
}

/// Unspent outputs for an account (for client-side spend construction).
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/lws/unspent_outs",
    request_body = ViewRequest,
    responses(
        (status = 200, description = "Unspent outputs + fee parameters", body = UnspentOutsResponse),
        (status = 400, description = "Invalid/disabled asset, address, or view key"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable")
    ),
    tag = "xmr_wow"
)]
#[instrument(skip(state, headers, req), fields(asset = %req.asset))]
pub async fn unspent_outs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ViewRequest>,
) -> Result<Json<UnspentOutsResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    let client = lws_for(&state, &asset)?;
    validate_cn_address(&req.address)?;
    validate_view_key(&req.view_key)?;

    let outs = client.get_unspent_outs(&req.address, &req.view_key).await?;
    Ok(Json(UnspentOutsResponse {
        asset,
        outputs: outs.outputs.into_iter().map(unspent_dto).collect(),
        per_byte_fee: outs.per_byte_fee,
        fee_mask: outs.fee_mask,
        fork_version: outs.fork_version,
    }))
}

/// Random decoy outputs for ring construction.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/lws/random_outs",
    request_body = RandomOutsRequest,
    responses(
        (status = 200, description = "Decoy outputs", body = RandomOutsResponse),
        (status = 400, description = "Invalid/disabled asset or request"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable")
    ),
    tag = "xmr_wow"
)]
#[instrument(skip(state, headers, req), fields(asset = %req.asset))]
pub async fn random_outs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RandomOutsRequest>,
) -> Result<Json<RandomOutsResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    let client = lws_for(&state, &asset)?;

    // The client clamps `count` and caps `amounts`/fan-out defensively.
    let outs = client.get_random_outs(req.count, req.amounts).await?;
    Ok(Json(RandomOutsResponse {
        asset,
        amount_outs: outs
            .amount_outs
            .into_iter()
            .map(|a| AmountOutsDto {
                amount: a.amount,
                outputs: a.outputs.into_iter().map(random_dto).collect(),
            })
            .collect(),
    }))
}

/// Broadcast a finalized, signed Monero/Wownero transaction.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/lws/submit_tx",
    request_body = SubmitRequest,
    responses(
        (status = 200, description = "Transaction submitted", body = OkResponse),
        (status = 400, description = "Invalid/disabled asset or malformed tx hex"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable")
    ),
    tag = "xmr_wow"
)]
#[instrument(skip(state, headers, req), fields(asset = %req.asset))]
pub async fn submit_tx(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SubmitRequest>,
) -> Result<Json<OkResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    let client = lws_for(&state, &asset)?;
    validate_hex(&req.tx_hex, "tx_hex", MAX_CN_TX_HEX_LEN)?;

    client.submit_raw_tx(&req.tx_hex).await?;
    Ok(Json(OkResponse { ok: true }))
}

/// Current chain height (daemon) for confirmation counting.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/lws/height",
    request_body = LwsAssetRequest,
    responses(
        (status = 200, description = "Chain height", body = HeightResponse),
        (status = 400, description = "Invalid/disabled asset"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable")
    ),
    tag = "xmr_wow"
)]
#[instrument(skip(state, headers, req), fields(asset = %req.asset))]
pub async fn height(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LwsAssetRequest>,
) -> Result<Json<HeightResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    let height = lws_for(&state, &asset)?.get_blockchain_height().await?;
    Ok(Json(HeightResponse { asset, height }))
}

/// Confirmation count for a transaction (daemon).
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/lws/confirmations",
    request_body = ConfirmationsRequest,
    responses(
        (status = 200, description = "Confirmation count", body = ConfirmationsResponse),
        (status = 400, description = "Invalid/disabled asset or txid"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable")
    ),
    tag = "xmr_wow"
)]
#[instrument(skip(state, headers, req), fields(asset = %req.asset))]
pub async fn confirmations(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ConfirmationsRequest>,
) -> Result<Json<ConfirmationsResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    let client = lws_for(&state, &asset)?;
    validate_hex(&req.txid, "txid", 64)?;

    let confirmations = client.get_transaction_confirmations(&req.txid).await?;
    Ok(Json(ConfirmationsResponse {
        asset,
        confirmations,
    }))
}

// ── router ────────────────────────────────────────────────────────────────────

/// Monero/Wownero routes, RELATIVE to the `/api/v1` mount point.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/wallet/lws/register", post(register))
        .route("/wallet/lws/balance", post(balance))
        .route("/wallet/lws/history", post(history))
        .route("/wallet/lws/unspent_outs", post(unspent_outs))
        .route("/wallet/lws/random_outs", post(random_outs))
        // submit_tx carries a raw tx hex (up to MAX_CN_TX_HEX_LEN); raise its
        // body cap above the global limit, with headroom for the JSON envelope.
        .route(
            "/wallet/lws/submit_tx",
            post(submit_tx).layer(DefaultBodyLimit::max(MAX_CN_TX_HEX_LEN + 64 * 1024)),
        )
        .route("/wallet/lws/height", post(height))
        .route("/wallet/lws/confirmations", post(confirmations))
}
