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
use serde::Deserialize;

use crate::error::AppError;

/// Per-request timeout for the upstream price API.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Browser-like User-Agent. Public price APIs (CoinGecko, Kraken) 403 requests
/// that carry no UA — reqwest sends none by default. Mirrors the v0.2.x feed.
const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) smirk-backend";
/// CoinGecko simple-price endpoint (fixed, trusted host).
const COINGECKO_URL: &str = "https://api.coingecko.com/api/v3/simple/price";
/// Kraken public ticker — the majors (BTC/LTC/XMR) in USD, one multi-pair call.
const KRAKEN_URL: &str = "https://api.kraken.com/0/public/Ticker";
/// Nonlogs markets — WOW/GRIN, which Kraken doesn't list (priced via BTC/USDT).
const NONLOGS_URL: &str = "https://api.nonlogs.io/api/markets";
/// The canonical Such Software price oracle (hash-wallet-prices Worker):
/// Kraken majors; WOW from Nonlogs + volume-weighted CexSwap, averaged and
/// KV-cached each minute. One call returns every rate, USD only.
const NEROSWAP_URL: &str = "https://prices.neroswap.com/v1/prices";
/// Our majors → Kraken USD pair. WOW/GRIN come from nonlogs instead.
const KRAKEN_PAIRS: &[(&str, &str)] = &[
    ("btc", "XXBTZUSD"),
    ("ltc", "XLTCZUSD"),
    ("xmr", "XXMRZUSD"),
];
/// Lower bound on the refresh interval, to stay within free-tier rate limits.
const MIN_INTERVAL_SECS: u64 = 60;
/// Upper bound on the price response body. The real payload is a handful of
/// numbers; this caps memory if the (otherwise trusted) host misbehaves, matching
/// the bounded-read convention used by the chain clients.
const MAX_PRICE_BODY_BYTES: usize = 256 * 1024;

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
    /// (config validation rejects them earlier). The provider is enforced
    /// fail-closed at startup by `Config::validate`; the `fetch` dispatch arm is
    /// a belt-and-suspenders fallback.
    pub fn new(provider: &str, currency: &str, assets: &[String]) -> Result<Self, AppError> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(USER_AGENT)
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

    #[cfg(test)]
    fn feed_symbols(&self) -> Vec<&str> {
        self.feeds.iter().map(|(s, _)| s.as_str()).collect()
    }

    /// Fetch the current price for every enabled feed. Assets the provider omits
    /// (or returns non-finite/negative) are skipped, not faked.
    pub async fn fetch(&self) -> Result<HashMap<String, f64>, AppError> {
        if self.feeds.is_empty() {
            return Ok(HashMap::new());
        }
        match self.provider.as_str() {
            "neroswap" => self.fetch_neroswap().await,
            "coingecko" => self.fetch_coingecko().await,
            "kraken" => self.fetch_kraken_nonlogs().await,
            other => Err(AppError::ConfigError(format!(
                "unsupported prices provider: {other}"
            ))),
        }
    }

    /// The v0.2.x feed: Kraken for the majors (BTC/LTC/XMR, USD) + nonlogs.io for
    /// WOW/GRIN (which Kraken doesn't list), priced via BTC. A per-source failure
    /// drops that asset rather than blanking the whole feed. USD only — the Kraken
    /// pairs are USD (config currency is `usd`).
    async fn fetch_kraken_nonlogs(&self) -> Result<HashMap<String, f64>, AppError> {
        let mut out = HashMap::new();

        // Majors from Kraken, in one multi-pair call.
        let pairs: Vec<(&str, &str)> = self
            .feeds
            .iter()
            .filter_map(|(sym, _)| KRAKEN_PAIRS.iter().find(|(s, _)| s == sym).copied())
            .collect();
        if !pairs.is_empty() {
            let joined = pairs.iter().map(|(_, p)| *p).collect::<Vec<_>>().join(",");
            if let Ok(resp) = self
                .http
                .get(KRAKEN_URL)
                .query(&[("pair", joined.as_str())])
                .send()
                .await
            {
                if resp.status().is_success() {
                    let body = read_capped(resp, MAX_PRICE_BODY_BYTES).await?;
                    #[derive(Deserialize)]
                    struct KrakenResp {
                        #[serde(default)]
                        error: Vec<String>,
                        result: Option<HashMap<String, KrakenTicker>>,
                    }
                    #[derive(Deserialize)]
                    struct KrakenTicker {
                        c: Vec<String>, // [last-trade price, lot volume]
                    }
                    if let Ok(data) = serde_json::from_slice::<KrakenResp>(&body) {
                        if let (true, Some(result)) = (data.error.is_empty(), data.result) {
                            for (sym, pair) in &pairs {
                                if let Some(price) = result
                                    .get(*pair)
                                    .and_then(|t| t.c.first())
                                    .and_then(|s| s.parse::<f64>().ok())
                                    .filter(|p| p.is_finite() && *p > 0.0)
                                {
                                    out.insert(sym.to_string(), price);
                                }
                            }
                        }
                    }
                }
            }
        }

        // WOW/GRIN from nonlogs, converted through BTC/USD.
        if self.feeds.iter().any(|(s, _)| s == "wow" || s == "grin") {
            if let Some(np) = self.fetch_nonlogs(out.get("btc").copied()).await {
                for (sym, price) in np {
                    if self.feeds.iter().any(|(s, _)| *s == sym) {
                        out.insert(sym, price);
                    }
                }
            }
        }

        Ok(out)
    }

    /// WOW/GRIN prices from nonlogs.io, each averaged over its `-BTC` (×BTC/USD)
    /// and `-USDT` markets. Returns `None` on any transport/parse failure (the
    /// caller keeps the last good snapshot). Needs BTC/USD to convert the BTC pair.
    async fn fetch_nonlogs(&self, btc_usd: Option<f64>) -> Option<HashMap<String, f64>> {
        let btc_usd = btc_usd?;
        let resp = self.http.get(NONLOGS_URL).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body = read_capped(resp, MAX_PRICE_BODY_BYTES).await.ok()?;
        #[derive(Deserialize)]
        struct NonlogsResp {
            markets: HashMap<String, NonlogsMarket>,
        }
        let data: NonlogsResp = serde_json::from_slice(&body).ok()?;
        let mut out = HashMap::new();
        for sym in ["wow", "grin"] {
            if let Some(p) = nonlogs_usd_price(&data.markets, sym, btc_usd) {
                out.insert(sym.to_string(), p);
            }
        }
        Some(out)
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
        // trusted, but the body is still read with a streaming size cap (as the
        // chain clients do) so a misbehaving upstream can't force a large alloc.
        let body = read_capped(resp, MAX_PRICE_BODY_BYTES).await?;
        let raw: HashMap<String, HashMap<String, f64>> = serde_json::from_slice(&body)
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

    /// The prices.neroswap.com oracle: one call, uppercase-symbol rate map.
    /// Assets the oracle doesn't publish (GRIN) fall back to the direct
    /// nonlogs leg, converted via the oracle's own BTC/USD. USD only — the
    /// oracle does not serve other quote currencies.
    async fn fetch_neroswap(&self) -> Result<HashMap<String, f64>, AppError> {
        let resp = self
            .http
            .get(NEROSWAP_URL)
            .send()
            .await
            .map_err(|_| AppError::NodeError("price fetch failed".into()))?;
        if !resp.status().is_success() {
            return Err(AppError::NodeError(format!(
                "price provider returned HTTP {}",
                resp.status().as_u16()
            )));
        }
        let body = read_capped(resp, MAX_PRICE_BODY_BYTES).await?;
        #[derive(Deserialize)]
        struct NeroswapResp {
            rates: HashMap<String, f64>,
        }
        let data: NeroswapResp = serde_json::from_slice(&body)
            .map_err(|_| AppError::NodeError("invalid price response".into()))?;

        let mut out = HashMap::new();
        let mut missing = Vec::new();
        for (asset, _) in &self.feeds {
            match data.rates.get(&asset.to_uppercase()) {
                Some(&price) if price.is_finite() && price > 0.0 => {
                    out.insert(asset.clone(), price);
                }
                _ => missing.push(asset.clone()),
            }
        }
        if !missing.is_empty() {
            let btc_usd = data
                .rates
                .get("BTC")
                .copied()
                .filter(|p| p.is_finite() && *p > 0.0);
            if let Some(nonlogs) = self.fetch_nonlogs(btc_usd).await {
                for asset in missing {
                    if let Some(&price) = nonlogs.get(&asset) {
                        out.insert(asset, price);
                    }
                }
            }
        }
        Ok(out)
    }
}

/// A nonlogs.io market row (only the last trade price is used; other fields
/// ignored).
#[derive(Deserialize)]
struct NonlogsMarket {
    last_price: Option<String>,
}

/// USD price for `sym` (lowercase) from nonlogs markets: average of its `-BTC`
/// quote (×`btc_usd`) and its `-USDT` quote, whichever are present. `None` if
/// neither is. Mirrors the v0.2.x conversion.
fn nonlogs_usd_price(
    markets: &HashMap<String, NonlogsMarket>,
    sym: &str,
    btc_usd: f64,
) -> Option<f64> {
    let up = sym.to_uppercase();
    let parse = |pair: &str| -> Option<f64> {
        markets
            .get(pair)?
            .last_price
            .as_deref()?
            .parse::<f64>()
            .ok()
            .filter(|p| *p > 0.0)
    };
    let mut sources = Vec::new();
    if let Some(btc) = parse(&format!("{up}-BTC")) {
        sources.push(btc * btc_usd);
    }
    if let Some(usdt) = parse(&format!("{up}-USDT")) {
        sources.push(usdt);
    }
    if sources.is_empty() {
        return None;
    }
    Some(sources.iter().sum::<f64>() / sources.len() as f64)
}

/// Clamp the configured refresh interval to a provider-friendly minimum.
pub fn refresh_interval(configured_secs: u64) -> Duration {
    Duration::from_secs(configured_secs.max(MIN_INTERVAL_SECS))
}

/// Read a response body, failing if it exceeds `cap` bytes (content-length is
/// attacker-assertable, so the limit is enforced as bytes actually arrive).
async fn read_capped(resp: reqwest::Response, cap: usize) -> Result<Vec<u8>, AppError> {
    use futures::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| AppError::NodeError("price read failed".into()))?;
        if buf.len().saturating_add(chunk.len()) > cap {
            return Err(AppError::NodeError(
                "price response exceeded size limit".into(),
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
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
    fn subset_whitelist_selects_exactly_those_feeds() {
        let client = PriceClient::new("coingecko", "usd", &["btc".into(), "grin".into()]).unwrap();
        let mut syms = client.feed_symbols();
        syms.sort();
        assert_eq!(syms, vec!["btc", "grin"]);
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
