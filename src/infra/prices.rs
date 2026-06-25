//! Fiat price feed.
//!
//! Fetches current crypto→fiat prices from a configurable provider (CoinGecko by
//! default), into an in-memory snapshot refreshed on a background interval. The
//! handler serves the cached snapshot; a fetch failure logs and keeps the last
//! good values rather than blanking them. Prices are display-only quotes — `f64`
//! is appropriate here (this is not on-chain money math).

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::error::AppError;

/// Per-request timeout for the upstream price API.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// CoinGecko simple-price endpoint (fixed, trusted host).
const COINGECKO_URL: &str = "https://api.coingecko.com/api/v3/simple/price";
/// Lower bound on the refresh interval, to stay within free-tier rate limits.
const MIN_INTERVAL_SECS: u64 = 60;

/// Our asset symbols mapped to their CoinGecko coin ids.
const COIN_IDS: &[(&str, &str)] = &[
    ("btc", "bitcoin"),
    ("ltc", "litecoin"),
    ("xmr", "monero"),
    ("wow", "wownero"),
    ("grin", "grin"),
];

/// The latest fetched prices. `updated_at` is `None` until the first successful
/// refresh, so clients can tell "not yet available" from a real zero.
#[derive(Debug, Clone)]
pub struct PriceSnapshot {
    pub currency: String,
    pub prices: HashMap<String, f64>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl PriceSnapshot {
    /// Empty snapshot for the given fiat currency (no prices yet).
    pub fn empty(currency: &str) -> Self {
        Self {
            currency: currency.to_string(),
            prices: HashMap::new(),
            updated_at: None,
        }
    }
}

/// Fetches prices from the configured provider, for a fixed set of feeds.
pub struct PriceClient {
    http: reqwest::Client,
    provider: String,
    currency: String,
    /// (asset symbol, provider coin id) for exactly the enabled feeds.
    feeds: Vec<(String, &'static str)>,
}

impl PriceClient {
    /// Build a client for `provider` (e.g. `"coingecko"`), quoting `assets` in
    /// `currency` (e.g. `"usd"`). Assets not in [`COIN_IDS`] are dropped here
    /// (config validation rejects them earlier). The provider is validated
    /// lazily on first fetch.
    pub fn new(provider: &str, currency: &str, assets: &[String]) -> Result<Self, AppError> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| AppError::ConfigError("failed to build price HTTP client".into()))?;
        let feeds = assets
            .iter()
            .filter_map(|a| {
                COIN_IDS
                    .iter()
                    .find(|(sym, _)| *sym == a)
                    .map(|(sym, id)| (sym.to_string(), *id))
            })
            .collect();
        Ok(Self {
            http,
            provider: provider.to_string(),
            currency: currency.to_string(),
            feeds,
        })
    }

    pub fn currency(&self) -> &str {
        &self.currency
    }

    /// Whether any feed is enabled (an empty whitelist quotes nothing).
    pub fn is_empty(&self) -> bool {
        self.feeds.is_empty()
    }

    /// Fetch the current price for every enabled feed. Assets the provider omits
    /// (or returns non-finite/negative) are skipped, not faked.
    pub async fn fetch(&self) -> Result<HashMap<String, f64>, AppError> {
        if self.feeds.is_empty() {
            return Ok(HashMap::new());
        }
        match self.provider.as_str() {
            "coingecko" => self.fetch_coingecko().await,
            other => Err(AppError::ConfigError(format!(
                "unsupported prices provider: {other}"
            ))),
        }
    }

    async fn fetch_coingecko(&self) -> Result<HashMap<String, f64>, AppError> {
        let ids = self
            .feeds
            .iter()
            .map(|(_, id)| *id)
            .collect::<Vec<_>>()
            .join(",");
        let resp = self
            .http
            .get(COINGECKO_URL)
            .query(&[
                ("ids", ids.as_str()),
                ("vs_currencies", self.currency.as_str()),
            ])
            .send()
            .await
            .map_err(|_| AppError::NodeError("price fetch failed".into()))?;
        if !resp.status().is_success() {
            return Err(AppError::NodeError(format!(
                "price provider returned HTTP {}",
                resp.status().as_u16()
            )));
        }
        // Shape: { "bitcoin": { "usd": 12345.6 }, ... }. The host is fixed and
        // the payload is a handful of numbers, so `json()` (timeout-bounded) is
        // sufficient here without the streaming cap the chain clients need.
        let raw: HashMap<String, HashMap<String, f64>> = resp
            .json()
            .await
            .map_err(|_| AppError::NodeError("invalid price response".into()))?;

        let mut out = HashMap::new();
        for (asset, id) in &self.feeds {
            if let Some(&price) = raw.get(*id).and_then(|m| m.get(&self.currency)) {
                if price.is_finite() && price >= 0.0 {
                    out.insert(asset.clone(), price);
                }
            }
        }
        Ok(out)
    }
}

/// Clamp the configured refresh interval to a provider-friendly minimum.
pub fn refresh_interval(configured_secs: u64) -> Duration {
    Duration::from_secs(configured_secs.max(MIN_INTERVAL_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_assets() -> Vec<String> {
        crate::config::SUPPORTED_PRICE_ASSETS
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn empty_snapshot_has_no_timestamp() {
        let snap = PriceSnapshot::empty("usd");
        assert_eq!(snap.currency, "usd");
        assert!(snap.prices.is_empty());
        assert!(snap.updated_at.is_none());
    }

    #[test]
    fn refresh_interval_enforces_minimum() {
        assert_eq!(refresh_interval(5), Duration::from_secs(MIN_INTERVAL_SECS));
        assert_eq!(refresh_interval(300), Duration::from_secs(300));
    }

    #[test]
    fn coin_ids_cover_exactly_the_supported_assets() {
        // Guards against config/provider drift: every configurable asset must
        // have a provider mapping, and vice versa.
        let mapped: std::collections::HashSet<&str> =
            COIN_IDS.iter().map(|(sym, _)| *sym).collect();
        let supported: std::collections::HashSet<&str> = crate::config::SUPPORTED_PRICE_ASSETS
            .iter()
            .copied()
            .collect();
        assert_eq!(mapped, supported);
    }

    #[test]
    fn unknown_and_empty_whitelists_yield_no_feeds() {
        let client = PriceClient::new("coingecko", "usd", &["doge".to_string()]).unwrap();
        assert!(client.is_empty());
        let client = PriceClient::new("coingecko", "usd", &[]).unwrap();
        assert!(client.is_empty());
    }

    #[tokio::test]
    async fn empty_whitelist_fetches_nothing_without_contacting_provider() {
        // No feeds => Ok(empty), even though "nonesuch" is an invalid provider:
        // the short-circuit happens before provider dispatch.
        let client = PriceClient::new("nonesuch", "usd", &[]).unwrap();
        assert!(client.fetch().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn unsupported_provider_is_rejected_when_feeds_exist() {
        let client = PriceClient::new("nonesuch", "usd", &all_assets()).unwrap();
        let err = client.fetch().await.unwrap_err();
        assert!(matches!(err, AppError::ConfigError(_)));
    }
}
