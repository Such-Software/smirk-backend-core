//! Unified blockchain-tip heights across all enabled chains.
//!
//! The wallet's ChainProvider seam fetches every chain's tip in a single call
//! and selects per asset, so one `GET /wallet/heights` returns them together.
//! Best-effort: a disabled chain (or a momentarily-unreachable source) is
//! reported `null` rather than failing the whole response.
//!
//! JWT-gated like the rest of the wallet surface (abuse-gating only; tip height
//! is public chain data and is not user-specific).

use std::sync::Arc;

use axum::{extract::State, http::HeaderMap, routing::get, Json, Router};
use serde::Serialize;
use tracing::instrument;
use utoipa::ToSchema;

use crate::api::middleware::extract_user_id_from_token;
use crate::error::AppError;
use crate::AppState;

/// Current tip height per chain. `null` = the chain is disabled on this instance
/// or its source was unreachable for this request.
#[derive(Debug, Serialize, ToSchema)]
pub struct HeightsResponse {
    #[schema(example = 955860)]
    pub btc: Option<i64>,
    pub ltc: Option<i64>,
    pub xmr: Option<i64>,
    pub wow: Option<i64>,
    pub grin: Option<i64>,
}

/// Current tip height for every enabled chain (one round-trip).
#[utoipa::path(
    security(("bearer_auth" = [])),
    get,
    path = "/wallet/heights",
    responses(
        (status = 200, description = "Tip height per chain (null if disabled/unreachable)", body = HeightsResponse),
        (status = 401, description = "Missing or invalid token")
    ),
    tag = "system"
)]
#[instrument(skip(state, headers))]
pub async fn heights(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<HeightsResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    let c = &state.chains;
    // Concurrent best-effort: each chain's failure collapses to `None`, never
    // failing the others. Disabled chains short-circuit without a network call.
    let (btc, ltc, xmr, wow, grin) = tokio::join!(
        async {
            match &c.btc {
                Some(e) => e.get_tip_height().await.ok(),
                None => None,
            }
        },
        async {
            match &c.ltc {
                Some(e) => e.get_tip_height().await.ok(),
                None => None,
            }
        },
        async {
            match &c.xmr {
                Some(l) => l.get_blockchain_height().await.ok().map(|h| h as i64),
                None => None,
            }
        },
        async {
            match &c.wow {
                Some(l) => l.get_blockchain_height().await.ok().map(|h| h as i64),
                None => None,
            }
        },
        async {
            match &c.grin {
                Some(g) => g.get_height().await.ok().map(|h| h as i64),
                None => None,
            }
        },
    );
    Ok(Json(HeightsResponse {
        btc,
        ltc,
        xmr,
        wow,
        grin,
    }))
}

/// `GET /wallet/heights`, RELATIVE to the `/api/v1` mount point.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/wallet/heights", get(heights))
}
