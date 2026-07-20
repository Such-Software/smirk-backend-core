//! Premium subscription endpoints — recurring, tiered access to the operator's
//! Nostr relay for general posting (the `premium-post` write policy). Reuses the
//! registration PaymentProvider: `POST /premium/invoice` mints a tier invoice,
//! `POST /premium/activate` verifies settlement (PULL model) and extends the
//! caller's premium window, `GET /premium/status` reports it. Non-custodial — the
//! backend only READS invoice status, never holds funds.

use std::sync::Arc;

use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing::{info, instrument};

use crate::api::middleware::extract_user_id_from_token;
use crate::error::AppError;
use crate::infra::payment::{InvoiceRequest, InvoiceStatus};
use crate::AppState;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct InvoiceReq {
    /// Plan id (see `/capabilities` → `premium.plans`), e.g. `quarter`.
    pub plan: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct InvoiceResp {
    pub invoice_id: String,
    /// Where to pay (a checkout URL or address).
    pub pay_to: String,
    pub plan: String,
    pub amount: String,
    pub currency: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ActivateReq {
    pub invoice_id: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct StatusResp {
    /// Whether the caller currently holds active premium.
    pub active: bool,
    /// Premium expiry (RFC3339), or null if never premium / lapsed.
    pub premium_until: Option<String>,
}

/// Reject when the premium tier is not enabled on this instance.
fn ensure_enabled(state: &AppState) -> Result<(), AppError> {
    if state.cfg().premium.enabled {
        Ok(())
    } else {
        Err(AppError::ValidationError(
            "Premium is not available on this instance.".into(),
        ))
    }
}

/// Mint a premium invoice for a chosen plan, bound to the caller.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/premium/invoice",
    request_body = InvoiceReq,
    responses(
        (status = 200, description = "Invoice minted", body = InvoiceResp),
        (status = 400, description = "Premium off or unknown plan"),
        (status = 401, description = "Missing or invalid token")
    ),
    tag = "premium"
)]
#[instrument(skip(state, headers))]
pub async fn invoice(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<InvoiceReq>,
) -> Result<Json<InvoiceResp>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    ensure_enabled(&state)?;

    let cfg = state.cfg();
    let plan = cfg
        .premium
        .plans
        .iter()
        .find(|p| p.id == req.plan)
        .ok_or_else(|| AppError::ValidationError("Unknown premium plan.".into()))?;

    // Cap outstanding unconsumed invoices per user — each mints a real processor
    // invoice, so bound the self-authenticated amplification into the processor.
    const MAX_PENDING: i64 = 8;
    if state.db.count_unconsumed_premium_invoices(user_id).await? >= MAX_PENDING {
        return Err(AppError::ValidationError(
            "Too many pending premium invoices; pay or let them expire before minting another."
                .into(),
        ));
    }

    let provider = state
        .payment
        .as_ref()
        .ok_or_else(|| AppError::Internal("payment provider not configured".into()))?;

    let pay = &state.cfg().registration.payment;
    let currency = state.cfg().premium.currency.clone();
    let invoice = provider
        .create_invoice(&InvoiceRequest {
            amount: plan.amount.clone(),
            currency: currency.clone(),
            confirmations: pay.confirmations,
            bind: user_id.to_string(),
            expires_minutes: pay.expires_minutes,
        })
        .await?;

    state
        .db
        .insert_premium_invoice(
            &invoice.id,
            user_id,
            provider.kind(),
            &plan.id,
            plan.days,
            &plan.amount,
            &currency,
        )
        .await?;

    Ok(Json(InvoiceResp {
        invoice_id: invoice.id,
        pay_to: invoice.pay_to,
        plan: plan.id.clone(),
        amount: plan.amount.clone(),
        currency,
    }))
}

/// Verify a settled premium invoice and extend the caller's premium window.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/premium/activate",
    request_body = ActivateReq,
    responses(
        (status = 200, description = "Premium extended", body = StatusResp),
        (status = 400, description = "Unknown, unpaid, or already-used invoice"),
        (status = 401, description = "Missing or invalid token")
    ),
    tag = "premium"
)]
#[instrument(skip(state, headers))]
pub async fn activate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ActivateReq>,
) -> Result<Json<StatusResp>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    ensure_enabled(&state)?;

    let provider = state
        .payment
        .as_ref()
        .ok_or_else(|| AppError::Internal("payment provider not configured".into()))?;

    let id = req.invoice_id.trim();
    let uid = user_id.to_string();

    // Binding precheck (local DB): must exist, be bound to THIS user, and unspent.
    // A missing row and a row bound to a different user collapse to one error.
    let row = match state.db.get_premium_invoice(id).await? {
        Some(r) if r.user_id == user_id => r,
        _ => {
            return Err(AppError::ValidationError(
                "Unknown or invalid premium invoice.".into(),
            ))
        }
    };
    if row.consumed_at.is_some() {
        return Err(AppError::ValidationError(
            "This premium invoice has already been used.".into(),
        ));
    }

    // Source of truth: the processor. Only Settled grants (paid in full per policy).
    let inv = provider.get_invoice(id).await?;
    if inv.status != InvoiceStatus::Settled {
        return Err(AppError::ValidationError(
            "Payment not yet confirmed. Complete the payment and retry.".into(),
        ));
    }
    // Defence-in-depth: the settled invoice's metadata bind must match this user.
    if let Some(ref bound) = inv.bind {
        if bound != &uid {
            return Err(AppError::ValidationError(
                "Unknown or invalid premium invoice.".into(),
            ));
        }
    }

    // Atomic single-use consume + extend (one transaction — a mid-flight failure
    // rolls back so the paid invoice stays redeemable). None = already used/raced.
    let until = match state
        .db
        .activate_premium(id, user_id, row.period_days)
        .await?
    {
        Some(u) => u,
        None => {
            return Err(AppError::ValidationError(
                "This premium invoice has already been used.".into(),
            ))
        }
    };
    info!(
        days = row.period_days,
        "premium invoice settled + activated; window extended"
    );

    Ok(Json(StatusResp {
        active: true,
        premium_until: Some(until.to_rfc3339()),
    }))
}

/// The caller's current premium status.
#[utoipa::path(
    security(("bearer_auth" = [])),
    get,
    path = "/premium/status",
    responses(
        (status = 200, description = "Premium status", body = StatusResp),
        (status = 401, description = "Missing or invalid token")
    ),
    tag = "premium"
)]
#[instrument(skip(state, headers))]
pub async fn status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<StatusResp>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    let until = state.db.get_premium_until(user_id).await?;
    let active = until.map(|u| u > chrono::Utc::now()).unwrap_or(false);
    Ok(Json(StatusResp {
        active,
        premium_until: until.map(|u| u.to_rfc3339()),
    }))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/premium/invoice", post(invoice))
        .route("/premium/activate", post(activate))
        .route("/premium/status", get(status))
}
