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

/// Hard cap on the batch of minor subaddress indices provisioned for account 0
/// at register time. Bounds one registration's ask on the LWS; the LWS's own
/// `--max-subaddresses` is the ultimate bound (and must be `>=` this to enable
/// the feature at all).
const MAX_PROVISION_MINORS: u32 = 200;

/// Dark feature flag (default OFF): whether this instance provisions account-0
/// subaddress ranges at the LWS. Also advertised on `/capabilities` so a client
/// can negotiate instead of calling a route that is not mounted.
///
/// Kept as an environment read (rather than a new `Config` field) to stay within
/// this change's file lane. ENABLING IT ALSO REQUIRES the LWS to run with
/// `--max-subaddresses >= MAX_PROVISION_MINORS` (it defaults to `0` =
/// subaddresses disabled); the client probes that ceiling and fails closed with
/// an operator-legible error rather than half-provisioning.
pub(crate) fn subaddr_provisioning_enabled() -> bool {
    crate::api::capabilities::env_flag_enabled("FEATURE_XMR_SUBADDR_PROVISIONING")
}

/// The number of account-0 minor subaddress indices to provision at the LWS.
/// `0` (no provisioning; behavior identical to before) unless the flag is on.
fn subaddr_provisioning_minors() -> u32 {
    if subaddr_provisioning_enabled() {
        MAX_PROVISION_MINORS
    } else {
        0
    }
}

/// The batch width to provision for one register call.
///
/// A client-supplied `subaddr_count` may RAISE the instance default (clamped to
/// [`MAX_PROVISION_MINORS`]) but can never enable provisioning: with the flag
/// off this returns `0` for every input, so the dark path stays byte-identical.
/// A money-gating field is never silently dropped, which is what an absent
/// `deny_unknown_fields` used to do to it.
fn effective_provision_minors(requested: Option<u32>) -> u32 {
    let base = subaddr_provisioning_minors();
    if base == 0 {
        return 0;
    }
    base.max(requested.unwrap_or(0).min(MAX_PROVISION_MINORS))
}

/// The LWS batch width for an on-demand `max_minor` ask.
///
/// `max_minor` is the highest minor INDEX the caller wants, so the width is
/// `max_minor + 1`, clamped so one call never provisions more than
/// [`MAX_PROVISION_MINORS`] indices (i.e. an ask above `MAX_PROVISION_MINORS - 1`
/// is clamped down, never rejected). An absent ask uses the instance default.
/// `0` whenever provisioning is off, so this can never turn the feature on.
fn provision_width_for(max_minor: Option<u32>) -> u32 {
    if !subaddr_provisioning_enabled() {
        return 0;
    }
    match max_minor {
        Some(m) => m.saturating_add(1).min(MAX_PROVISION_MINORS),
        None => subaddr_provisioning_minors(),
    }
}

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
    /// Restore proof-of-work nonce. Required when the instance prices the
    /// requested restore depth (see `/capabilities` → `restore.pow_*`); ignored
    /// otherwise. Bound to `(asset, address, start_height)` (see `restore_pow`).
    #[serde(default)]
    pub restore_pow_nonce: Option<u64>,
    /// How many account-0 minor subaddress indices to provision at the LWS.
    /// Clamped to the server ceiling, and may only RAISE this instance's
    /// default; it can never enable provisioning on an instance that has it off.
    /// Omit to use the instance default.
    #[serde(default)]
    pub subaddr_count: Option<u32>,
}

/// Provision a batch of account-0 subaddress indices for an account. Additive to
/// `register`; the identity comes from the bearer token, so any `user_id` on the
/// wire is ignored.
// Omits `Debug` (carries the private `view_key`) - see `ViewRequest`.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct ProvisionRequest {
    /// `xmr` or `wow`.
    pub asset: String,
    pub address: String,
    /// Private view key (64 hex). Forwarded to the LWS; never stored or logged.
    pub view_key: String,
    /// Highest minor index wanted for account 0. Clamped to the server ceiling.
    /// Omit for the instance default.
    #[serde(default)]
    pub max_minor: Option<u32>,
}

/// The subaddress ceiling the LWS CONFIRMED for account 0.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ProvisionResponse {
    pub asset: String,
    /// Highest minor index the LWS confirmed it is scanning for account 0, read
    /// back from its response - never an echo of the request. Every index in
    /// `0..=provisioned_minor_max` is provisioned; the wallet must not hand out
    /// an index above it.
    pub provisioned_minor_max: u32,
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

/// Serialize a `u64` atomic amount as a decimal STRING. XMR/WOW amounts can exceed
/// 2^53, which a JavaScript `number` cannot hold exactly, so every atomic amount
/// crosses the wire as a string; the wallet BigInt-parses it. Heights, indices,
/// counts, and fee params stay numbers (always well under 2^53).
fn ser_u64_str<S: serde::Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&v.to_string())
}

/// Balance + scan state, as a **verification passthrough**. The backend holds no
/// spend key, so it cannot net out spends; the wallet computes the true spendable
/// balance client-side: `total_received − sum(spent_outputs it verifies with the
/// spend key) − locked_balance`. `spent_outputs` are therefore CANDIDATES (some
/// are ring decoys of the user's own outputs); `pending_balance` is the 0-conf
/// (mempool) received.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LwsBalanceResponse {
    pub asset: String,
    #[serde(serialize_with = "ser_u64_str")]
    #[schema(value_type = String, example = "12345000000000")]
    pub total_received: u64,
    #[serde(serialize_with = "ser_u64_str")]
    #[schema(value_type = String)]
    pub locked_balance: u64,
    /// Unconfirmed (mempool) received — 0-conf. `0` until the LWS reports mempool
    /// rows (the monero-lws mempool feature); never negative.
    #[serde(serialize_with = "ser_u64_str")]
    #[schema(value_type = String)]
    pub pending_balance: u64,
    pub start_height: u64,
    pub scanned_height: u64,
    pub blockchain_height: u64,
    pub transaction_count: u64,
    /// Candidate spent outputs (confirmed + mempool) for client-side key-image
    /// verification with the spend key. Never authoritative server-side.
    pub spent_outputs: Vec<SpentOutputDto>,
}

/// A subaddress index `(major, minor)` an output/tx was received at. Nested to
/// match the wallet's wasm `LwsOutput` shape (`subaddr_index: {major, minor}`);
/// mapped from the LWS `recipient` field. `(0, 0)` is the primary address.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SubaddrIndexDto {
    pub major: u32,
    pub minor: u32,
}

/// A candidate spent output (verify with the spend key before trusting).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SpentOutputDto {
    #[serde(serialize_with = "ser_u64_str")]
    #[schema(value_type = String)]
    pub amount: u64,
    pub key_image: String,
    pub tx_pub_key: String,
    pub out_index: u64,
    pub mixin: u64,
    /// Subaddress index of the output BEING SPENT (`(0, 0)` = primary address),
    /// taken from the spend record itself.
    ///
    /// Load-bearing for the balance: the wallet recomputes this output's key
    /// image to tell a real spend from a ring decoy, and the key image depends
    /// on the subaddress index. Without it a subaddress spend is recomputed
    /// against the primary index, the key images never match, the spend is
    /// dismissed as a decoy, and the amount is never subtracted - the balance
    /// over-reports forever. It is deliberately NOT the enclosing transaction's
    /// `subaddr_index`, which is the change index and would be just as wrong.
    pub subaddr_index: SubaddrIndexDto,
}

/// A transaction in the account's history.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TxDto {
    pub hash: String,
    pub height: u64,
    pub timestamp: String,
    #[serde(serialize_with = "ser_u64_str")]
    #[schema(value_type = String)]
    pub total_received: u64,
    /// "Possible" sent — candidate spends, not authoritative.
    #[serde(serialize_with = "ser_u64_str")]
    #[schema(value_type = String)]
    pub total_sent: u64,
    pub mempool: bool,
    pub unlock_time: u64,
    pub payment_id: Option<String>,
    pub spent_outputs: Vec<SpentOutputDto>,
    /// Subaddress index this tx was received at (`(0, 0)` = primary address).
    pub subaddr_index: SubaddrIndexDto,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LwsHistoryResponse {
    pub asset: String,
    pub transactions: Vec<TxDto>,
}

/// An unspent output for spend construction.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UnspentOutputDto {
    #[serde(serialize_with = "ser_u64_str")]
    #[schema(value_type = String)]
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
    /// Subaddress index this output was received at (`(0, 0)` = primary address).
    pub subaddr_index: SubaddrIndexDto,
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
        // From the SPEND RECORD (monero-lws `sender`), never from the enclosing
        // tx's `recipient` - that is the change index.
        subaddr_index: SubaddrIndexDto {
            major: s.sender.maj_i,
            minor: s.sender.min_i,
        },
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
        subaddr_index: SubaddrIndexDto {
            major: t.recipient.maj_i,
            minor: t.recipient.min_i,
        },
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
        subaddr_index: SubaddrIndexDto {
            major: u.recipient.maj_i,
            minor: u.recipient.min_i,
        },
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

    // Dark by default: 0 ⇒ no subaddress provisioning (register behaves exactly
    // as before). When the flag is on, both paths provision a bounded batch of
    // account-0 minor indices and HARD-error on provision failure (the `?`
    // propagates) — never silently skipping so a wallet is not told scanning is
    // ready when the subaddresses were not registered. A client-supplied
    // `subaddr_count` may raise the batch within the server ceiling.
    let provision_minors = effective_provision_minors(req.subaddr_count);

    match req.start_height {
        Some(h) => {
            // Restore: gate the scan depth against this instance's policy (the
            // backfill cost lands on our LWS). `None` (create) needs no check.
            let tip = client.get_blockchain_height().await?;
            state.cfg().restore.enforce(&asset, h, tip)?;
            state.cfg().restore.enforce_restore_pow(
                &asset,
                &req.address,
                h,
                tip,
                req.restore_pow_nonce,
            )?;
            client
                .import_account(&req.address, &req.view_key, h, provision_minors)
                .await?
        }
        None => {
            client
                .register_account(&req.address, &req.view_key, provision_minors)
                .await?
        }
    }
    Ok(Json(OkResponse { ok: true }))
}

/// Provision account-0 subaddress indices at the LWS for an already-registered
/// account, and report the ceiling the LWS confirmed.
///
/// Mounted only when `FEATURE_XMR_SUBADDR_PROVISIONING` is on (see
/// `/capabilities` → `features.xmr_subaddr_provisioning`); otherwise the route
/// does not exist and the request 404s.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/lws/provision_subaddrs",
    request_body = ProvisionRequest,
    responses(
        (status = 200, description = "LWS-confirmed subaddress ceiling for account 0", body = ProvisionResponse),
        (status = 400, description = "Invalid/disabled asset, address, or view key"),
        (status = 401, description = "Missing or invalid token"),
        (status = 404, description = "Subaddress provisioning is not enabled on this instance"),
        (status = 503, description = "Upstream node unavailable, or it cannot provision subaddresses")
    ),
    tag = "xmr_wow"
)]
#[instrument(skip(state, headers, req), fields(asset = %req.asset))]
pub async fn provision_subaddrs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ProvisionRequest>,
) -> Result<Json<ProvisionResponse>, AppError> {
    // Identity comes from the bearer token alone. Any `user_id` on the wire is
    // ignored (unknown fields are dropped), so it can never select an account.
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    let client = lws_for(&state, &asset)?;
    validate_cn_address(&req.address)?;
    validate_view_key(&req.view_key)?;

    // Clamped to the hard server ceiling; an absent ask uses the instance
    // default. The route is only mounted with the flag on, so the width is
    // never 0 here, but `provision_account0` rejects a 0 ask regardless.
    let n_min = provision_width_for(req.max_minor);
    let provisioned_minor_max = client
        .provision_account0(&req.address, &req.view_key, n_min)
        .await?;
    Ok(Json(ProvisionResponse {
        asset,
        provisioned_minor_max,
    }))
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
    let mut router = Router::new()
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
        .route("/wallet/lws/confirmations", post(confirmations));

    // Dark by default: the provisioning endpoint exists only when enabled, so a
    // client that has not negotiated the capability gets a clean 404.
    if subaddr_provisioning_enabled() {
        router = router.route("/wallet/lws/provision_subaddrs", post(provision_subaddrs));
    }
    router
}

#[cfg(test)]
mod amount_wire_tests {
    use super::*;

    // XMR/WOW atomic amounts can exceed 2^53, so they must cross the wire as decimal
    // STRINGS (a JS number would round them). This locks that contract.
    const BIG: u64 = 9_007_199_254_740_993; // 2^53 + 1

    #[test]
    fn unspent_output_amount_serializes_as_string() {
        let dto = UnspentOutputDto {
            amount: BIG,
            public_key: "aa".into(),
            tx_pub_key: "bb".into(),
            index: 0,
            global_index: 1,
            height: 2,
            timestamp: "t".into(),
            tx_hash: "h".into(),
            rct: String::new(),
            spend_key_images: vec![],
            subaddr_index: SubaddrIndexDto { major: 0, minor: 7 },
        };
        let v = serde_json::to_value(&dto).unwrap();
        assert_eq!(v["amount"], serde_json::json!("9007199254740993"));
        assert!(v["amount"].is_string(), "amount must be a JSON string");
        // A non-amount field stays a number.
        assert!(v["global_index"].is_number());
        // The subaddress index is nested `{major, minor}` (wasm LwsOutput shape).
        assert_eq!(v["subaddr_index"]["major"], serde_json::json!(0));
        assert_eq!(v["subaddr_index"]["minor"], serde_json::json!(7));
    }

    // The LWS `recipient` field maps straight into the nested `subaddr_index`
    // DTO — including the fail-open `(0, 0)` for a primary-address receive.
    #[test]
    fn unspent_recipient_maps_to_nested_subaddr_index() {
        use crate::infra::lws::{SubaddrIndex, UnspentOutput};
        let infra = UnspentOutput {
            amount: 1,
            public_key: "aa".into(),
            tx_pub_key: "bb".into(),
            index: 0,
            global_index: 1,
            height: 2,
            timestamp: String::new(),
            tx_hash: "h".into(),
            rct: String::new(),
            spend_key_images: vec![],
            recipient: SubaddrIndex { maj_i: 1, min_i: 9 },
        };
        let dto = unspent_dto(infra);
        assert_eq!(dto.subaddr_index.major, 1);
        assert_eq!(dto.subaddr_index.minor, 9);
    }

    #[test]
    fn balance_amounts_serialize_as_strings() {
        let bal = LwsBalanceResponse {
            asset: "xmr".into(),
            total_received: BIG,
            locked_balance: 0,
            pending_balance: 0,
            start_height: 100,
            scanned_height: 100,
            blockchain_height: 100,
            transaction_count: 1,
            spent_outputs: vec![],
        };
        let v = serde_json::to_value(&bal).unwrap();
        assert_eq!(v["total_received"], serde_json::json!("9007199254740993"));
        assert!(v["locked_balance"].is_string() && v["pending_balance"].is_string());
        assert!(v["blockchain_height"].is_number(), "heights stay numbers");
    }

    // A spend's subaddress index comes from the SPEND RECORD, so a subaddress
    // spend's key image can be recomputed. Taking it from the enclosing tx (the
    // change index) would mislabel it, the key image would never match, and the
    // spend would be dismissed as a decoy - the balance would over-report.
    #[test]
    fn spent_output_index_comes_from_the_spend_record_not_the_tx() {
        use crate::infra::lws::{SpentOutput as InfraSpent, SubaddrIndex};
        let tx = AddressTx {
            hash: "h".into(),
            height: 5,
            timestamp: String::new(),
            total_received: 1,
            total_sent: 9,
            mempool: false,
            unlock_time: 0,
            payment_id: None,
            spent_outputs: vec![InfraSpent {
                amount: 9,
                key_image: "ki".into(),
                tx_pub_key: "tp".into(),
                out_index: 2,
                mixin: 15,
                sender: SubaddrIndex { maj_i: 0, min_i: 7 },
            }],
            // The tx-level index is the CHANGE index and must not leak into the
            // spend's index.
            recipient: SubaddrIndex { maj_i: 0, min_i: 1 },
        };
        let dto = tx_dto(tx);
        assert_eq!(dto.subaddr_index.minor, 1, "tx keeps its own index");
        assert_eq!(dto.spent_outputs[0].subaddr_index.major, 0);
        assert_eq!(
            dto.spent_outputs[0].subaddr_index.minor, 7,
            "the spend's index must be the spent output's own"
        );
        // It also crosses the wire under the nested `{major, minor}` shape.
        let v = serde_json::to_value(&dto.spent_outputs[0]).unwrap();
        assert_eq!(v["subaddr_index"]["minor"], serde_json::json!(7));
    }
}

#[cfg(test)]
mod provision_gate_tests {
    use super::*;

    // These read a process-wide env var, so they run under one lock and always
    // restore the previous value.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_flag<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("FEATURE_XMR_SUBADDR_PROVISIONING").ok();
        match value {
            Some(v) => std::env::set_var("FEATURE_XMR_SUBADDR_PROVISIONING", v),
            None => std::env::remove_var("FEATURE_XMR_SUBADDR_PROVISIONING"),
        }
        let out = f();
        match prev {
            Some(v) => std::env::set_var("FEATURE_XMR_SUBADDR_PROVISIONING", v),
            None => std::env::remove_var("FEATURE_XMR_SUBADDR_PROVISIONING"),
        }
        out
    }

    #[test]
    fn flag_parsing_is_case_insensitive_and_trimmed() {
        for on in ["1", "true", "TRUE", "True", "on", "ON", "Yes", " yes "] {
            assert!(with_flag(Some(on), subaddr_provisioning_enabled), "{on}");
        }
        for off in ["0", "false", "no", "off", "", "maybe"] {
            assert!(!with_flag(Some(off), subaddr_provisioning_enabled), "{off}");
        }
        assert!(!with_flag(None, subaddr_provisioning_enabled));
    }

    #[test]
    fn subaddr_count_is_ignored_while_the_flag_is_off() {
        // Flag OFF must stay byte-identical: no client-supplied count can turn
        // provisioning on.
        with_flag(None, || {
            assert_eq!(effective_provision_minors(None), 0);
            assert_eq!(effective_provision_minors(Some(200)), 0);
            assert_eq!(effective_provision_minors(Some(u32::MAX)), 0);
            assert_eq!(provision_width_for(Some(50)), 0);
        });
    }

    #[test]
    fn subaddr_count_is_accepted_and_clamped_when_enabled() {
        with_flag(Some("1"), || {
            // Absent => the instance default.
            assert_eq!(effective_provision_minors(None), MAX_PROVISION_MINORS);
            // Never below the instance default (a client cannot narrow it).
            assert_eq!(effective_provision_minors(Some(1)), MAX_PROVISION_MINORS);
            // Never above the hard server ceiling.
            assert_eq!(
                effective_provision_minors(Some(u32::MAX)),
                MAX_PROVISION_MINORS
            );
        });
    }

    #[test]
    fn provision_width_treats_max_minor_as_an_index() {
        with_flag(Some("yes"), || {
            // `max_minor` is the highest wanted INDEX, so the width is +1.
            assert_eq!(provision_width_for(Some(0)), 1);
            assert_eq!(provision_width_for(Some(49)), 50);
            // Clamped to the ceiling, never rejected, and never overflowing.
            assert_eq!(provision_width_for(Some(10_000)), MAX_PROVISION_MINORS);
            assert_eq!(provision_width_for(Some(u32::MAX)), MAX_PROVISION_MINORS);
            // Absent => the instance default.
            assert_eq!(provision_width_for(None), MAX_PROVISION_MINORS);
        });
    }

    #[test]
    fn register_request_accepts_and_ignores_extra_wire_fields() {
        // `subaddr_count` is read (never silently dropped) and an unknown
        // `user_id` on the provision request is ignored - identity comes from
        // the bearer token.
        let r: RegisterRequest = serde_json::from_str(
            r#"{"asset":"xmr","address":"9a","view_key":"vk","subaddr_count":64}"#,
        )
        .unwrap();
        assert_eq!(r.subaddr_count, Some(64));
        let r2: RegisterRequest =
            serde_json::from_str(r#"{"asset":"xmr","address":"9a","view_key":"vk"}"#).unwrap();
        assert_eq!(r2.subaddr_count, None);
        let p: ProvisionRequest = serde_json::from_str(
            r#"{"asset":"xmr","address":"9a","view_key":"vk","max_minor":31,"user_id":"attacker"}"#,
        )
        .unwrap();
        assert_eq!(p.max_minor, Some(31));
    }
}
