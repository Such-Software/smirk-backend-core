//! Public social-tips endpoints.
//!
//! A sender funds a per-tip address and shares a claim URL whose fragment
//! carries the claim key; anyone with the URL claims by sweeping the address to
//! their own wallet. Non-custodial: the backend stores only the encrypted claim
//! blob and a hash of the claim key — never the key or the funds.
//!
//! PUBLIC tips only. Targeted (@username) tips and the socials/bot surface are
//! out of scope for this port: an `is_public = false` request is rejected.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

use crate::api::middleware::extract_user_id_from_token;
use crate::api::wallet::validate_cn_address;
use crate::error::AppError;
use crate::infra::db::{NewSocialTip, SocialTipRow};
use crate::models::tip_status::{confirmations_for_asset, TipStatus};
use crate::AppState;

/// Max `encrypted_key` size on the wire: 4096 hex chars = 2048 bytes.
const MAX_ENCRYPTED_KEY_HEX: usize = 4096;

// ── DTOs (match packages/core/src/api/social.ts verbatim) ────────────────────

/// Create a public tip. Targeted-only fields (`platform`, `username`,
/// `grin_commitment`, `sender_anonymous`) are accepted for wire-compat but
/// ignored in this port.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateSocialTipRequest {
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    pub asset: String,
    pub amount: i64,
    /// Hex-encoded AES-GCM ciphertext of the claim secret; the backend cannot
    /// decrypt it.
    #[serde(default)]
    pub encrypted_key: Option<String>,
    pub is_public: bool,
    /// SHA256 of the claim key (hex); the key itself never touches the server.
    #[serde(default)]
    pub claim_key_hash: Option<String>,
    #[serde(default)]
    pub tip_address: Option<String>,
    #[serde(default)]
    pub funding_txid: Option<String>,
    /// Private view key for the tip address (XMR/WOW), so the backend can scan
    /// it for funding + sweep.
    #[serde(default)]
    pub tip_view_key: Option<String>,
    #[serde(default)]
    pub grin_commitment: Option<String>,
    #[serde(default)]
    pub sender_anonymous: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CreateSocialTipResponse {
    pub tip_id: String,
    pub status: String,
    /// `{TIP_SHARE_BASE_URL}/{tip_id}` for a public tip, else null.
    pub share_url: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SentTip {
    pub id: String,
    pub sender_user_id: String,
    /// Always null in the public-only port (no targeted recipients).
    pub recipient_platform: Option<String>,
    pub recipient_username: Option<String>,
    pub asset: String,
    pub amount: i64,
    pub is_public: bool,
    pub status: String,
    pub created_at: String,
    pub claimed_at: Option<String>,
    pub clawed_back_at: Option<String>,
    pub funding_confirmations: i32,
    pub confirmations_required: i32,
    pub is_claimable: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SocialTipsResponse {
    pub tips: Vec<SentTip>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PublicTipInfo {
    pub id: String,
    pub asset: String,
    pub amount: i64,
    pub status: String,
    pub created_at: String,
    pub is_public: bool,
    /// Hex-encoded AES-GCM ciphertext; useless without the URL-fragment key.
    pub encrypted_key: Option<String>,
    pub tip_address: Option<String>,
    pub funding_confirmations: i32,
    pub confirmations_required: i32,
    pub is_claimable: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CancelTipResponse {
    pub ok: bool,
}

/// Attach a broadcast funding transaction to a draft tip.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AttachFundingRequest {
    /// The on-chain funding transaction id (XMR/WOW txid, BTC/LTC txid).
    pub funding_txid: String,
}

/// Claim a tip: lock it into `claiming` and receive the encrypted claim key +
/// tip address to sweep. Load-bearing INCONSISTENT key: `success` (not `ok`).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ClaimTipResponse {
    pub success: bool,
    /// Hex-encoded AES-GCM ciphertext of the claim secret; `null` if the tip
    /// stored none. Useless without the URL-fragment key.
    pub encrypted_key: Option<String>,
    pub tip_address: Option<String>,
}

/// Record the claimer's broadcast sweep transaction (first-recorder-wins).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ConfirmSweepRequest {
    /// The broadcast sweep transaction id.
    pub sweep_txid: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ConfirmSweepResponse {
    /// The WINNING (first-recorded) sweep txid, or `null` if none is recorded.
    pub sweep_txid: Option<String>,
    pub status: String,
}

/// Sender clawback of a tip. Load-bearing INCONSISTENT key: `success` (not `ok`).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ClawbackTipResponse {
    pub success: bool,
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Reject when tips are not enabled on this instance.
fn ensure_tips_enabled(state: &AppState) -> Result<(), AppError> {
    if state.cfg().features.tips {
        Ok(())
    } else {
        Err(AppError::ValidationError(
            "Tips are not available on this instance.".into(),
        ))
    }
}

/// Whether `asset` is a tip-capable chain enabled on this instance.
fn supported_tip_asset(state: &AppState, asset: &str) -> bool {
    let c = &state.cfg().features.chains;
    match asset {
        "btc" => c.btc,
        "ltc" => c.ltc,
        "xmr" => c.xmr,
        "wow" => c.wow,
        "grin" => c.grin,
        _ => false,
    }
}

/// Basic tip-address validation. XMR/WOW reuse the CryptoNote validator; BTC/LTC
/// get a light sanity check; grin's "address" is the voucher's 66-hex Pedersen
/// commitment (the sender funds and later sweeps THEIR OWN output, so a malformed
/// one merely fails funding verification — it can't misdirect funds to a third
/// party).
fn validate_tip_address(asset: &str, address: &str) -> Result<(), AppError> {
    if address.is_empty() || address.len() > 255 {
        return Err(AppError::ValidationError("tip_address is invalid.".into()));
    }
    match asset {
        "xmr" | "wow" => validate_cn_address(address),
        "btc" | "ltc" => {
            if address.len() >= 14 && address.chars().all(|c| c.is_ascii_alphanumeric()) {
                Ok(())
            } else {
                Err(AppError::ValidationError("tip_address is invalid.".into()))
            }
        }
        // Grin: a Pedersen commitment is a compressed point, 33 bytes = 66 hex
        // chars. Reject anything else so a malformed value is a clean 400 (and
        // never overflows the VARCHAR(66) grin_commitment column).
        "grin" => {
            if address.len() == 66 && address.chars().all(|c| c.is_ascii_hexdigit()) {
                Ok(())
            } else {
                Err(AppError::ValidationError("tip_address is invalid.".into()))
            }
        }
        _ => Err(AppError::ValidationError("unsupported tip asset.".into())),
    }
}

/// A tip is claimable iff funding is confirmed AND amount-verified AND it hasn't
/// left the claimable window.
fn is_claimable(row: &SocialTipRow) -> bool {
    matches!(
        TipStatus::from_db(&row.status),
        Some(TipStatus::Pending | TipStatus::Claiming)
    ) && row.funding_confirmations >= row.confirmations_required
        && row.funding_amount_verified
}

fn to_sent_tip(row: SocialTipRow) -> SentTip {
    let claimable = is_claimable(&row);
    SentTip {
        id: row.id.to_string(),
        sender_user_id: row.sender_user_id.to_string(),
        recipient_platform: None,
        recipient_username: None,
        asset: row.asset,
        amount: row.amount,
        is_public: row.is_public,
        status: row.status,
        created_at: row.created_at.to_rfc3339(),
        claimed_at: row.claimed_at.map(|t| t.to_rfc3339()),
        clawed_back_at: row.clawed_back_at.map(|t| t.to_rfc3339()),
        funding_confirmations: row.funding_confirmations,
        confirmations_required: row.confirmations_required,
        is_claimable: claimable,
    }
}

fn to_public_info(row: SocialTipRow) -> PublicTipInfo {
    let claimable = is_claimable(&row);
    PublicTipInfo {
        id: row.id.to_string(),
        asset: row.asset,
        amount: row.amount,
        status: row.status,
        created_at: row.created_at.to_rfc3339(),
        is_public: row.is_public,
        encrypted_key: row.encrypted_key.map(hex::encode),
        tip_address: row.tip_address,
        funding_confirmations: row.funding_confirmations,
        confirmations_required: row.confirmations_required,
        is_claimable: claimable,
    }
}

// ── handlers ─────────────────────────────────────────────────────────────────

/// Create a public tip (optionally as a two-phase draft).
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/tips/social",
    request_body = CreateSocialTipRequest,
    responses(
        (status = 200, description = "Tip created", body = CreateSocialTipResponse),
        (status = 400, description = "Tips off, targeted tip, or invalid input"),
        (status = 401, description = "Missing or invalid token")
    ),
    tag = "tips"
)]
#[instrument(skip(state, headers, req))]
pub async fn create_social_tip(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateSocialTipRequest>,
) -> Result<Json<CreateSocialTipResponse>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    ensure_tips_enabled(&state)?;

    // Public-only port: targeted tips are rejected outright.
    if !req.is_public {
        return Err(AppError::ValidationError(
            "Targeted tips are not supported on this instance; set is_public = true.".into(),
        ));
    }
    if req.amount <= 0 {
        return Err(AppError::ValidationError("amount must be positive.".into()));
    }
    let asset = req.asset.to_lowercase();
    if !supported_tip_asset(&state, &asset) {
        return Err(AppError::ValidationError(format!(
            "asset '{asset}' is not enabled for tips on this instance."
        )));
    }

    // Public tips require the claim-key hash (mirrors the public_tip_has_hash CHECK).
    let claim_key_hash = req
        .claim_key_hash
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::ValidationError("claim_key_hash is required for a public tip.".into())
        })?;
    // A claim-key hash is SHA256(claim key) = exactly 64 hex chars. Validate the
    // shape so malformed input is a clean 400, not a DB length-overflow 500.
    if claim_key_hash.len() != 64 || hex::decode(claim_key_hash).is_err() {
        return Err(AppError::ValidationError(
            "claim_key_hash must be a 64-character hex SHA256.".into(),
        ));
    }

    // encrypted_key: hex, capped at 4096 hex chars.
    let encrypted_key: Option<Vec<u8>> = match req.encrypted_key.as_deref() {
        Some(h) if !h.is_empty() => {
            if h.len() > MAX_ENCRYPTED_KEY_HEX {
                return Err(AppError::ValidationError(
                    "encrypted_key is too large.".into(),
                ));
            }
            Some(
                hex::decode(h)
                    .map_err(|_| AppError::ValidationError("encrypted_key must be hex.".into()))?,
            )
        }
        _ => None,
    };

    let tip_address = req.tip_address.as_deref().filter(|s| !s.is_empty());
    let funding_txid = req.funding_txid.as_deref().filter(|s| !s.is_empty());
    let is_draft = funding_txid.is_none();
    // A draft (no funding yet) must carry the address the sender will fund.
    if is_draft && tip_address.is_none() {
        return Err(AppError::ValidationError(
            "tip_address is required to create a tip draft.".into(),
        ));
    }
    if let Some(addr) = tip_address {
        validate_tip_address(&asset, addr)?;
    }

    // Grin tips use a voucher: the on-chain handle is the output's Pedersen
    // commitment, which the client sends as BOTH tip_address and grin_commitment.
    // Prefer the explicit field, fall back to tip_address, and validate it as a
    // 66-hex commitment so a malformed value is a clean 400 (not a DB overflow).
    let grin_commitment = if asset == "grin" {
        let commit = req
            .grin_commitment
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(tip_address);
        if let Some(commit) = commit {
            validate_tip_address("grin", commit)?;
        }
        commit
    } else {
        None
    };

    let new = NewSocialTip {
        sender_user_id: user_id,
        asset: &asset,
        amount: req.amount,
        claim_key_hash: Some(claim_key_hash),
        encrypted_key: encrypted_key.as_deref(),
        tip_address,
        funding_txid,
        tip_view_key: req.tip_view_key.as_deref().filter(|s| !s.is_empty()),
        confirmations_required: confirmations_for_asset(&asset),
        grin_commitment,
    };

    let tip = if is_draft {
        state.db.create_draft_social_tip(new).await?
    } else {
        state.db.create_social_tip(new).await?
    };

    let share_url = state
        .cfg()
        .tip_share_base
        .as_ref()
        .map(|base| format!("{}/{}", base.trim_end_matches('/'), tip.id));

    Ok(Json(CreateSocialTipResponse {
        tip_id: tip.id.to_string(),
        status: tip.status,
        share_url,
    }))
}

/// All tips the caller has sent, newest first.
#[utoipa::path(
    security(("bearer_auth" = [])),
    get,
    path = "/tips/social/sent",
    responses(
        (status = 200, description = "Sent tips", body = SocialTipsResponse),
        (status = 400, description = "Tips off"),
        (status = 401, description = "Missing or invalid token")
    ),
    tag = "tips"
)]
#[instrument(skip(state, headers))]
pub async fn get_sent_social_tips(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<SocialTipsResponse>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    ensure_tips_enabled(&state)?;
    let rows = state.db.get_sent_social_tips(user_id).await?;
    Ok(Json(SocialTipsResponse {
        tips: rows.into_iter().map(to_sent_tip).collect(),
    }))
}

/// Tips RECEIVED by the caller. Public-only instances have no targeted-recipient
/// inbox (public tips are claimed via share URL, never delivered to a user), so
/// this is always empty — served (200) rather than 404 so the client's inbox
/// poll doesn't error on a targeted-only endpoint this instance doesn't serve.
#[utoipa::path(
    security(("bearer_auth" = [])),
    get,
    path = "/tips/social/received",
    responses(
        (status = 200, description = "Received tips (empty on a public-only instance)", body = SocialTipsResponse),
        (status = 400, description = "Tips off"),
        (status = 401, description = "Missing or invalid token")
    ),
    tag = "tips"
)]
#[instrument(skip(state, headers))]
pub async fn get_received_social_tips(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<SocialTipsResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    ensure_tips_enabled(&state)?;
    Ok(Json(SocialTipsResponse { tips: Vec::new() }))
}

/// Tips CLAIMABLE by the caller. As with `received`, a public-only instance has
/// no targeted-claimable inbox, so this is always empty (served 200, not 404).
#[utoipa::path(
    security(("bearer_auth" = [])),
    get,
    path = "/tips/social/claimable",
    responses(
        (status = 200, description = "Claimable tips (empty on a public-only instance)", body = SocialTipsResponse),
        (status = 400, description = "Tips off"),
        (status = 401, description = "Missing or invalid token")
    ),
    tag = "tips"
)]
#[instrument(skip(state, headers))]
pub async fn get_claimable_social_tips(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<SocialTipsResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    ensure_tips_enabled(&state)?;
    Ok(Json(SocialTipsResponse { tips: Vec::new() }))
}

/// Public tip metadata for a share-URL holder. UNAUTHENTICATED: the tip id (a
/// UUID) is the bearer token. 404s for an unknown or non-public tip.
#[utoipa::path(
    get,
    path = "/tips/social/{tip_id}/public",
    params(("tip_id" = String, Path, description = "Tip id")),
    responses(
        (status = 200, description = "Public tip info", body = PublicTipInfo),
        (status = 400, description = "Tips off"),
        (status = 404, description = "No such public tip")
    ),
    tag = "tips"
)]
#[instrument(skip(state))]
pub async fn get_public_social_tip(
    State(state): State<Arc<AppState>>,
    Path(tip_id): Path<Uuid>,
) -> Result<Json<PublicTipInfo>, AppError> {
    ensure_tips_enabled(&state)?;
    let row = state
        .db
        .get_social_tip(tip_id)
        .await?
        .filter(|r| r.is_public)
        .ok_or_else(|| AppError::NotFound("tip not found".into()))?;
    Ok(Json(to_public_info(row)))
}

/// Cancel a still-unfunded draft (owner-only, draft-only). A funded/claimed tip
/// is recovered via clawback, not cancel.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/tips/social/{tip_id}/cancel",
    params(("tip_id" = String, Path, description = "Tip id")),
    responses(
        (status = 200, description = "Draft cancelled", body = CancelTipResponse),
        (status = 400, description = "Tips off"),
        (status = 401, description = "Missing or invalid token"),
        (status = 404, description = "No cancellable draft")
    ),
    tag = "tips"
)]
#[instrument(skip(state, headers))]
pub async fn cancel_social_tip(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tip_id): Path<Uuid>,
) -> Result<Json<CancelTipResponse>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    ensure_tips_enabled(&state)?;
    match state.db.cancel_draft_social_tip(tip_id, user_id).await? {
        Some(_) => Ok(Json(CancelTipResponse { ok: true })),
        None => Err(AppError::NotFound("no cancellable draft tip".into())),
    }
}

/// Attach a broadcast funding tx to a draft tip, advancing it into the funding
/// lifecycle (`pending_confirmation`; the funding worker later flips it to
/// `pending` once the on-chain receipt is confirmed AND covers `amount`).
///
/// Idempotent: re-attaching the SAME txid is a no-op that returns the row; a
/// DIFFERENT txid on a tip that already has one (or a non-draft tip) is a 400;
/// an unknown / not-owned tip is a 404. Response mirrors create: the same
/// `CreateSocialTipResponse { tip_id, status, share_url }`.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/tips/social/{tip_id}/attach-funding",
    params(("tip_id" = String, Path, description = "Tip id")),
    request_body = AttachFundingRequest,
    responses(
        (status = 200, description = "Funding attached", body = CreateSocialTipResponse),
        (status = 400, description = "Tips off, empty/oversized txid, or a conflicting funding tx"),
        (status = 401, description = "Missing or invalid token"),
        (status = 404, description = "No such tip owned by the caller")
    ),
    tag = "tips"
)]
#[instrument(skip(state, headers, req))]
pub async fn attach_funding(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tip_id): Path<Uuid>,
    Json(req): Json<AttachFundingRequest>,
) -> Result<Json<CreateSocialTipResponse>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    ensure_tips_enabled(&state)?;

    // Validate the txid shape so a malformed value is a clean 400 rather than a
    // DB length-overflow 500 (funding_txid is VARCHAR(128)).
    let funding_txid = req.funding_txid.trim();
    if funding_txid.is_empty() {
        return Err(AppError::ValidationError(
            "funding_txid is required.".into(),
        ));
    }
    if funding_txid.len() > 128 {
        return Err(AppError::ValidationError(
            "funding_txid is too long.".into(),
        ));
    }

    // The DB fn returns Ok(row) / NotFound / ValidationError; just surface it.
    let tip = state
        .db
        .attach_funding_to_tip(tip_id, user_id, funding_txid)
        .await?;

    let share_url = state
        .cfg()
        .tip_share_base
        .as_ref()
        .map(|base| format!("{}/{}", base.trim_end_matches('/'), tip.id));

    Ok(Json(CreateSocialTipResponse {
        tip_id: tip.id.to_string(),
        status: tip.status,
        share_url,
    }))
}

/// Claim a public tip: lock it into `claiming` and return the encrypted claim
/// key + tip address so the caller can sweep the funds to their own wallet.
///
/// AUTHED, no body. The `claiming` state is a UX signal, not a cryptographic
/// lock — any URL holder may claim while the sweep hasn't confirmed (whoever
/// wins the on-chain sweep race wins the tip; the reconciler resolves the
/// winner). A non-claimable tip (missing, underfunded, clawed back, already
/// swept) is a 400.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/tips/social/{tip_id}/claim",
    params(("tip_id" = String, Path, description = "Tip id")),
    responses(
        (status = 200, description = "Tip locked into claiming", body = ClaimTipResponse),
        (status = 400, description = "Tips off or tip not claimable"),
        (status = 401, description = "Missing or invalid token")
    ),
    tag = "tips"
)]
#[instrument(skip(state, headers))]
pub async fn claim_social_tip(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tip_id): Path<Uuid>,
) -> Result<Json<ClaimTipResponse>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    ensure_tips_enabled(&state)?;

    let row = state
        .db
        .mark_tip_claiming(tip_id, user_id)
        .await?
        .ok_or_else(|| AppError::ValidationError("tip not claimable".into()))?;

    Ok(Json(ClaimTipResponse {
        success: true,
        encrypted_key: row.encrypted_key.map(hex::encode),
        tip_address: row.tip_address,
    }))
}

/// Record the claimer's broadcast sweep txid (first-recorder-wins). RECORD not
/// settle: the tip stays `claiming` and the reconciler owns the settle to
/// `claimed` once the sweep confirms on-chain. Idempotent; a second, different
/// txid does NOT overwrite the recorded winner. A tip that was never claimed is
/// a 400.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/tips/social/{tip_id}/confirm-sweep",
    params(("tip_id" = String, Path, description = "Tip id")),
    request_body = ConfirmSweepRequest,
    responses(
        (status = 200, description = "Sweep txid recorded", body = ConfirmSweepResponse),
        (status = 400, description = "Tips off, empty/oversized txid, or tip not claiming"),
        (status = 401, description = "Missing or invalid token")
    ),
    tag = "tips"
)]
#[instrument(skip(state, headers, req))]
pub async fn confirm_sweep(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tip_id): Path<Uuid>,
    Json(req): Json<ConfirmSweepRequest>,
) -> Result<Json<ConfirmSweepResponse>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    ensure_tips_enabled(&state)?;

    let sweep_txid = req.sweep_txid.trim();
    if sweep_txid.is_empty() {
        return Err(AppError::ValidationError("sweep_txid is required.".into()));
    }
    if sweep_txid.len() > 128 {
        return Err(AppError::ValidationError("sweep_txid is too long.".into()));
    }

    let row = state
        .db
        .confirm_tip_sweep(tip_id, user_id, sweep_txid)
        .await?
        .ok_or_else(|| AppError::ValidationError("tip not claiming".into()))?;

    Ok(Json(ConfirmSweepResponse {
        sweep_txid: row.sweep_txid,
        status: row.status,
    }))
}

/// Sender reclaims a tip's funds. AUTHED, no body. Succeeds for the sender on a
/// pending / pending_confirmation / claiming / funding_mismatch / cancelled tip
/// while its sweep hasn't confirmed; a settled or non-clawable tip is a 400.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/tips/social/{tip_id}/clawback",
    params(("tip_id" = String, Path, description = "Tip id")),
    responses(
        (status = 200, description = "Tip clawed back", body = ClawbackTipResponse),
        (status = 400, description = "Tips off or tip not clawable"),
        (status = 401, description = "Missing or invalid token")
    ),
    tag = "tips"
)]
#[instrument(skip(state, headers))]
pub async fn clawback_social_tip(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tip_id): Path<Uuid>,
) -> Result<Json<ClawbackTipResponse>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    ensure_tips_enabled(&state)?;

    state
        .db
        .clawback_social_tip(tip_id, user_id)
        .await?
        .ok_or_else(|| AppError::ValidationError("tip not clawable".into()))?;

    Ok(Json(ClawbackTipResponse { success: true }))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/tips/social", post(create_social_tip))
        .route("/tips/social/sent", get(get_sent_social_tips))
        .route("/tips/social/received", get(get_received_social_tips))
        .route("/tips/social/claimable", get(get_claimable_social_tips))
        .route("/tips/social/:tip_id/public", get(get_public_social_tip))
        .route("/tips/social/:tip_id/cancel", post(cancel_social_tip))
        .route("/tips/social/:tip_id/attach-funding", post(attach_funding))
        .route("/tips/social/:tip_id/claim", post(claim_social_tip))
        .route("/tips/social/:tip_id/confirm-sweep", post(confirm_sweep))
        .route("/tips/social/:tip_id/clawback", post(clawback_social_tip))
}
