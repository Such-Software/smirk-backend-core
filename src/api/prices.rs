//! Fiat price feed endpoint.
//!
//! Serves the in-memory snapshot maintained by the background refresh task (see
//! [`crate::infra::prices`]). Public and cached — no upstream call happens on the
//! request path. When the feed is disabled this route returns `404`, so a client
//! reading [`crate::api::capabilities`] never has to special-case it.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;
use tracing::instrument;

use crate::error::AppError;
use crate::AppState;

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PricesResponse {
    /// Fiat currency the quotes are in (e.g. `"usd"`).
    pub currency: String,
    /// Asset symbol → price in `currency`. Only enabled feeds appear.
    pub prices: HashMap<String, f64>,
    /// RFC 3339 timestamp of the last successful refresh; `null` until the first.
    pub updated_at: Option<String>,
}

/// Current fiat prices for the enabled feeds.
#[utoipa::path(
    get,
    path = "/prices",
    responses(
        (status = 200, description = "Latest cached prices", body = PricesResponse),
        (status = 404, description = "Price feed disabled on this server")
    ),
    tag = "prices"
)]
#[instrument(skip(state))]
pub async fn prices(State(state): State<Arc<AppState>>) -> Result<Json<PricesResponse>, AppError> {
    if !state.config.features.prices {
        return Err(AppError::NotFound(
            "price feed is not enabled on this server".into(),
        ));
    }
    let snap = state.prices.read().await;
    Ok(Json(PricesResponse {
        currency: snap.currency.clone(),
        prices: snap.prices.clone(),
        updated_at: snap.updated_at.map(|t| t.to_rfc3339()),
    }))
}

/// Price route, RELATIVE to the `/api/v1` mount point. Public (no auth).
pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/prices", get(prices))
}
