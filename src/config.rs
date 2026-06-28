//! Configuration: the single source of environment-driven settings.
//!
//! [`Config::from_env`] is the ONLY place that reads `std::env`; every other
//! module receives typed config. `from_env` calls [`Config::validate`], which
//! **fails closed**: the server refuses to start on a weak or placeholder
//! secret, or an inconsistent feature configuration, rather than booting and
//! logging success while a security control is silently defeated.
//!
//! Secrets are never logged, never placed in defaults, and never emitted in the
//! OpenAPI spec. Structs that hold secrets deliberately do not derive `Debug`.

use std::env;
use std::net::IpAddr;
use std::str::FromStr;

use ipnetwork::IpNetwork;

use crate::error::AppError;

fn cfg_err(msg: impl Into<String>) -> AppError {
    AppError::ConfigError(msg.into())
}

/// Substrings we refuse to accept as real secrets in production.
const PLACEHOLDERS: &[&str] = &[
    "change_me",
    "changeme",
    "your-",
    "example",
    "placeholder",
    "dev-",
    "xxxx",
    "0000000000",
];

fn looks_placeholder(s: &str) -> bool {
    let l = s.to_lowercase();
    PLACEHOLDERS.iter().any(|p| l.contains(p))
}

// ── env helpers ─────────────────────────────────────────────────────────────

/// Non-empty env value, or `None`.
fn env_opt(key: &str) -> Option<String> {
    env::var(key).ok().filter(|s| !s.is_empty())
}

fn env_or(key: &str, default: &str) -> String {
    env_opt(key).unwrap_or_else(|| default.to_string())
}

fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(v) => matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}

/// Parse a typed value. Errors if the var is *present but unparseable* (so a
/// `doctor` preflight can distinguish "set but invalid" from "unset"); falls
/// back to `default` only when truly absent/empty.
fn env_parse<T: FromStr>(key: &str, default: T) -> Result<T, AppError> {
    match env_opt(key) {
        Some(v) => v
            .parse()
            .map_err(|_| cfg_err(format!("{key} is set but not a valid value"))),
        None => Ok(default),
    }
}

fn env_list(key: &str) -> Vec<String> {
    env_opt(key)
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Parse a comma-separated list of CIDRs or bare IPs into networks.
fn parse_networks(key: &str) -> Result<Vec<IpNetwork>, AppError> {
    let mut out = Vec::new();
    for tok in env_list(key) {
        let net = IpNetwork::from_str(&tok)
            .or_else(|_| IpAddr::from_str(&tok).map(IpNetwork::from))
            .map_err(|_| cfg_err(format!("{key} contains an invalid CIDR/IP: {tok}")))?;
        out.push(net);
    }
    Ok(out)
}

// ── config tree ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeploymentMode {
    /// Single instance (default). In-memory challenge state is permitted.
    Single,
    /// Load-balanced fleet. Requires shared/stateless challenge state.
    Fleet,
}

/// Top-level application configuration. Does not derive `Debug` (holds secrets).
#[derive(Clone)]
pub struct Config {
    pub server_host: String,
    pub server_port: u16,
    pub deployment_mode: DeploymentMode,
    pub environment: String,

    pub database_url: String,

    pub auth: AuthConfig,
    pub identity: IdentityConfig,
    pub secrets: SecretConfig,
    /// Networks whose `X-Forwarded-For` is trusted. Empty (default) means the
    /// real TCP peer is always used for rate-limiting and audit IPs.
    pub trusted_proxies: Vec<IpNetwork>,
    /// Browser origins allowed by CORS (e.g. the web wallet). Empty (default)
    /// allows any origin — safe here because auth is a Bearer token, not cookies,
    /// so no ambient credentials ride a cross-origin request.
    pub cors_allowed_origins: Vec<String>,

    pub features: FeatureFlags,
    pub chains: ChainConfig,
    pub pow: PowConfig,
    pub admin: AdminConfig,
    pub landing: LandingConfig,
    pub retention: RetentionConfig,
}

#[derive(Clone)]
pub struct AuthConfig {
    /// HS256 signing key. Length-checked (>= 32 bytes) and placeholder-checked.
    pub jwt_secret: String,
    pub jwt_expiry_hours: u64,
}

#[derive(Clone)]
pub struct IdentityConfig {
    /// Public absolute API base URL (e.g. `https://backend.example.org/api/v1`).
    /// Required when Nostr identity is enabled: it is the canonical value the
    /// NIP-98 `u` tag is verified against — never the request `Host` header.
    pub public_api_url: Option<String>,
}

/// HMAC peppers and salts. Fail-closed: required and length-checked. These make
/// stored fingerprints non-reproducible from a candidate seed and unlink IPs.
#[derive(Clone)]
pub struct SecretConfig {
    pub seed_fingerprint_pepper: String,
    pub refresh_token_pepper: String,
    pub ip_salt: String,
}

/// Assets the price feed can quote. Source of truth for which `PRICES_ASSETS`
/// values are accepted; the provider mapping (symbol→coin id) lives in
/// `infra::prices` and a test there asserts it covers exactly this set.
pub const SUPPORTED_PRICE_ASSETS: &[&str] = &["btc", "ltc", "xmr", "wow", "grin"];

/// Fiat (and crypto-denominated) currencies the price feed may quote in. A
/// curated allowlist so a `PRICES_CURRENCY` typo fails closed at startup rather
/// than booting a feed that advertises `prices:true` but serves nothing (the
/// provider returns empty quotes for an unknown currency).
pub const SUPPORTED_PRICE_CURRENCIES: &[&str] = &[
    "usd", "eur", "gbp", "jpy", "cny", "aud", "cad", "chf", "btc",
];

#[derive(Clone)]
pub struct FeatureFlags {
    pub chains: ChainFlags,
    /// Master switch for the price feed. When off, `/prices` is `404` and no
    /// upstream is ever contacted.
    pub prices: bool,
    pub prices_provider: String,
    pub prices_interval_secs: u64,
    /// Per-feed control: exactly which assets this instance quotes. Unset =
    /// all supported; an explicit (possibly empty) `PRICES_ASSETS` list narrows
    /// it — so an operator can serve a subset or none at all.
    pub prices_assets: Vec<String>,
    /// Fiat currency the feed quotes in (e.g. `"usd"`).
    pub prices_currency: String,
    /// Parked feature; off by default.
    pub tips: bool,
    /// Nostr-native identity (NIP-98 login/link, NIP-05 directory).
    pub nostr_identity: bool,
    /// Grin slatepack relay (async store-and-forward mailbox for interactive
    /// Grin transfers). A non-custodial encrypted mailbox; operators can disable
    /// it independently of Grin chain access.
    pub grin_relay: bool,
}

#[derive(Clone, Copy)]
pub struct ChainFlags {
    pub btc: bool,
    pub ltc: bool,
    pub xmr: bool,
    pub wow: bool,
    pub grin: bool,
}

#[derive(Clone)]
pub struct ChainConfig {
    pub btc: UtxoConfig,
    pub ltc: UtxoConfig,
    pub xmr: LwsConfig,
    pub wow: LwsConfig,
    pub grin: GrinConfig,
}

/// Bitcoin/Litecoin chain access via Electrum/Fulcrum. The backend runs no
/// BTC/LTC node — reads, fee estimation, and broadcast all go through Electrum.
/// (A self-hosted Fulcrum relays broadcasts to its own backing node, so no
/// separate Core-RPC path is needed; a future MWEB/node provider would slot in
/// at the provider seam rather than extending this config.)
#[derive(Clone)]
pub struct UtxoConfig {
    pub network: String,
    pub electrum_primary: Option<String>,
    pub electrum_fallbacks: Vec<String>,
}

/// Monero/Wownero daemon + light-wallet-server configuration.
#[derive(Clone)]
pub struct LwsConfig {
    pub lws_url: String,
    pub lws_admin_url: String,
    pub lws_admin_key: String,
    pub daemon_url: String,
}

#[derive(Clone)]
pub struct GrinConfig {
    pub owner_api_url: String,
    pub owner_api_secret: String,
    pub wallet_password: String,
    pub foreign_api_url: String,
    pub node_api_url: String,
    pub node_api_user: String,
    pub node_api_pass: String,
    pub node_foreign_api_url: String,
    pub node_foreign_api_secret: String,
}

/// Proof-of-work signup gate (ALTCHA). Feature-gated; when enabled the HMAC key
/// is required (no source-visible fallback).
#[derive(Clone)]
pub struct PowConfig {
    pub enabled: bool,
    pub hmac_key: String,
    pub required: bool,
    pub cost: u64,
    /// Lowercase hex pubkey hashes that always require PoW (opt-in testing).
    pub required_for_pubkeys: Vec<String>,
}

/// Admin surface. Default posture is loopback/Tor; allowlist mutation is
/// CLI/loopback-only in v1. Only public keys are stored — never a seed.
#[derive(Clone)]
pub struct AdminConfig {
    pub enabled: bool,
    pub bind: String,
    /// Absolute base URL the operator's wallet reaches the admin plane at (the
    /// value the signed-action `u` tag is verified against — never the Host
    /// header). Loopback by default; a Tor onion / SSH-tunnel URL in production.
    pub public_url: String,
    pub jwt_secret: String,
    /// MAC secret protecting admin/setup trust anchors against DB tampering.
    pub key_integrity_secret: String,
    pub pubkeys: Vec<String>,
    pub max_keys: u32,
    pub pending_key_ttl_days: u32,
    /// Allow the admin plane to bind a non-loopback address (default false →
    /// startup refuses a public bind; confidentiality is by socket).
    pub allow_public_bind: bool,
    /// Tor onion host the admin plane is reached at (added to the Host allowlist;
    /// never logged or surfaced publicly).
    pub onion: Option<String>,
}

/// Public landing page. Off by default; full + per-field tunable when enabled.
#[derive(Clone)]
pub struct LandingConfig {
    pub enabled: bool,
    /// Operator free text (HTML-escaped on render). `None` = omitted.
    pub title: Option<String>,
    /// Emit a coarse (major.minor) version. Default off (version is recon).
    pub expose_version: bool,
    /// Emit the enabled chain symbols. Default off.
    pub expose_chains: bool,
    /// Emit `price_feed.enabled`. Default off.
    pub expose_price_feed: bool,
    pub expose_uptime: bool,
    pub stats_enabled: bool,
    pub stats_cache_hours: u64,
}

#[derive(Clone)]
pub struct RetentionConfig {
    pub login_events_days: u64,
    pub audit_days: u64,
    pub erasure_enabled: bool,
    pub purge_login_events: bool,
    pub export_per_day: u32,
    /// Grace window between a confirmed erasure and its execution.
    pub grace_period_hours: u64,
}

impl Config {
    /// Load configuration from the environment and validate it (fail-closed).
    pub fn from_env() -> Result<Self, AppError> {
        let cfg = Self {
            server_host: env_or("SERVER_HOST", "0.0.0.0"),
            server_port: env_parse("SERVER_PORT", 8080u16)?,
            deployment_mode: match env_or("DEPLOYMENT_MODE", "single").to_lowercase().as_str() {
                "fleet" => DeploymentMode::Fleet,
                "single" => DeploymentMode::Single,
                other => {
                    return Err(cfg_err(format!(
                        "DEPLOYMENT_MODE must be single|fleet, got {other}"
                    )))
                }
            },
            environment: env_or("ENVIRONMENT", "development"),

            database_url: env_opt("DATABASE_URL")
                .ok_or_else(|| cfg_err("DATABASE_URL is required"))?,

            auth: AuthConfig {
                jwt_secret: env_or("JWT_SECRET", ""),
                jwt_expiry_hours: env_parse("JWT_EXPIRY_HOURS", 24u64)?,
            },
            identity: IdentityConfig {
                public_api_url: env_opt("PUBLIC_API_URL"),
            },
            secrets: SecretConfig {
                seed_fingerprint_pepper: env_or("SEED_FINGERPRINT_PEPPER", ""),
                refresh_token_pepper: env_or("REFRESH_TOKEN_PEPPER", ""),
                ip_salt: env_or("IP_SALT", ""),
            },
            trusted_proxies: parse_networks("TRUSTED_PROXIES")?,
            cors_allowed_origins: env_list("CORS_ALLOWED_ORIGINS"),

            features: FeatureFlags {
                chains: ChainFlags {
                    btc: env_bool("FEATURE_BTC", true),
                    ltc: env_bool("FEATURE_LTC", true),
                    xmr: env_bool("FEATURE_XMR", true),
                    wow: env_bool("FEATURE_WOW", true),
                    grin: env_bool("FEATURE_GRIN", true),
                },
                prices: env_bool("FEATURE_PRICES", true),
                prices_provider: env_or("PRICES_PROVIDER", "coingecko").to_lowercase(),
                prices_interval_secs: env_parse("PRICES_FETCH_INTERVAL_SECS", 300u64)?,
                // Per-feed control. Distinguish UNSET from PRESENT-BUT-EMPTY:
                // `env::var` (not `env_opt`, which collapses empty into None) so
                // `PRICES_ASSETS=` means "none", not "all".
                //   unset            => all supported feeds
                //   "btc,xmr"        => that subset
                //   "" (or blanks)   => none
                prices_assets: match env::var("PRICES_ASSETS") {
                    Err(_) => SUPPORTED_PRICE_ASSETS
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                    Ok(s) => s
                        .split(',')
                        .map(|x| x.trim().to_lowercase())
                        .filter(|x| !x.is_empty())
                        .collect(),
                },
                prices_currency: env_or("PRICES_CURRENCY", "usd").to_lowercase(),
                tips: env_bool("FEATURE_TIPS", false),
                nostr_identity: env_bool("FEATURE_NOSTR_IDENTITY", true),
                grin_relay: env_bool("FEATURE_GRIN_RELAY", true),
            },
            chains: ChainConfig {
                btc: UtxoConfig {
                    network: env_or("BTC_NETWORK", "mainnet"),
                    electrum_primary: env_opt("BTC_ELECTRUM_URL"),
                    electrum_fallbacks: env_list("BTC_ELECTRUM_FALLBACKS"),
                },
                ltc: UtxoConfig {
                    network: env_or("LTC_NETWORK", "mainnet"),
                    electrum_primary: env_opt("LTC_ELECTRUM_URL"),
                    electrum_fallbacks: env_list("LTC_ELECTRUM_FALLBACKS"),
                },
                xmr: LwsConfig {
                    lws_url: env_or("XMR_LWS_URL", "http://127.0.0.1:8443"),
                    lws_admin_url: env_or("XMR_LWS_ADMIN_URL", "http://127.0.0.1:9443"),
                    lws_admin_key: env_or("XMR_LWS_ADMIN_KEY", ""),
                    daemon_url: env_or("XMR_DAEMON_URL", "http://127.0.0.1:18081"),
                },
                wow: LwsConfig {
                    lws_url: env_or("WOW_LWS_URL", "http://127.0.0.1:18443"),
                    lws_admin_url: env_or("WOW_LWS_ADMIN_URL", "http://127.0.0.1:19443"),
                    lws_admin_key: env_or("WOW_LWS_ADMIN_KEY", ""),
                    daemon_url: env_or("WOW_DAEMON_URL", "http://127.0.0.1:34568"),
                },
                grin: GrinConfig {
                    owner_api_url: env_or("GRIN_OWNER_API_URL", "http://127.0.0.1:3420/v3/owner"),
                    owner_api_secret: env_or("GRIN_OWNER_API_SECRET", ""),
                    wallet_password: env_or("GRIN_WALLET_PASSWORD", ""),
                    foreign_api_url: env_or(
                        "GRIN_FOREIGN_API_URL",
                        "http://127.0.0.1:3415/v2/foreign",
                    ),
                    node_api_url: env_or("GRIN_NODE_API_URL", "http://127.0.0.1:3413/v2/owner"),
                    node_api_user: env_or("GRIN_NODE_API_USER", "grin"),
                    node_api_pass: env_or("GRIN_NODE_API_PASS", ""),
                    node_foreign_api_url: env_or(
                        "GRIN_NODE_FOREIGN_API_URL",
                        "http://127.0.0.1:3413/v2/foreign",
                    ),
                    node_foreign_api_secret: env_or("GRIN_NODE_FOREIGN_API_SECRET", ""),
                },
            },
            pow: PowConfig {
                enabled: env_bool("FEATURE_POW", false),
                hmac_key: env_or("ALTCHA_HMAC_KEY", ""),
                required: env_bool("POW_REQUIRED", false),
                cost: env_parse("ALTCHA_COST", 100_000u64)?,
                required_for_pubkeys: env_list("TEST_POW_REQUIRED_FOR_PUBKEYS")
                    .into_iter()
                    .map(|s| s.to_lowercase())
                    .collect(),
            },
            admin: AdminConfig {
                enabled: env_bool("ADMIN_ENABLED", false),
                bind: env_or("ADMIN_BIND", "127.0.0.1:8081"),
                public_url: env_or("ADMIN_PUBLIC_URL", "http://127.0.0.1:8081"),
                jwt_secret: env_or("ADMIN_JWT_SECRET", ""),
                key_integrity_secret: env_or("ADMIN_KEY_INTEGRITY_SECRET", ""),
                pubkeys: env_list("ADMIN_PUBKEYS"),
                max_keys: env_parse("ADMIN_MAX_KEYS", 8u32)?,
                pending_key_ttl_days: env_parse("ADMIN_PENDING_KEY_TTL_DAYS", 7u32)?,
                allow_public_bind: env_bool("ADMIN_ALLOW_PUBLIC_BIND", false),
                onion: env_opt("TOR_ADMIN_ONION"),
            },
            landing: LandingConfig {
                enabled: env_bool("PUBLIC_LANDING_ENABLED", false),
                title: env_opt("PUBLIC_LANDING_TITLE"),
                expose_version: env_bool("PUBLIC_EXPOSE_VERSION", false),
                expose_chains: env_bool("PUBLIC_EXPOSE_CHAINS", false),
                expose_price_feed: env_bool("PUBLIC_EXPOSE_PRICE_FEED", false),
                expose_uptime: env_bool("PUBLIC_EXPOSE_UPTIME", false),
                stats_enabled: env_bool("PUBLIC_STATS_ENABLED", false),
                stats_cache_hours: env_parse("PUBLIC_STATS_CACHE_HOURS", 24u64)?,
            },
            retention: RetentionConfig {
                login_events_days: env_parse("RETENTION_LOGIN_EVENTS_DAYS", 90u64)?,
                audit_days: env_parse("RETENTION_AUDIT_DAYS", 365u64)?,
                erasure_enabled: env_bool("ERASURE_ENABLED", false),
                purge_login_events: env_bool("ERASURE_PURGE_LOGIN_EVENTS", true),
                export_per_day: env_parse("ERASURE_EXPORT_PER_DAY", 3u32)?,
                grace_period_hours: env_parse("ERASURE_GRACE_PERIOD_HOURS", 72u64)?,
            },
        };

        cfg.validate()?;
        Ok(cfg)
    }

    pub fn is_production(&self) -> bool {
        self.environment == "production"
    }

    /// Fail-closed validation. Returns `Err` (aborting startup) on any weak,
    /// missing, or inconsistent security-relevant setting.
    pub fn validate(&self) -> Result<(), AppError> {
        let prod = self.is_production();

        // A secret that must be present, long enough, and (in prod) not a placeholder.
        let require_secret = |name: &str, val: &str, min: usize| -> Result<(), AppError> {
            if val.len() < min {
                return Err(cfg_err(format!(
                    "{name} must be set and at least {min} bytes"
                )));
            }
            if prod && looks_placeholder(val) {
                return Err(cfg_err(format!(
                    "{name} looks like a placeholder; set a real value"
                )));
            }
            Ok(())
        };

        // Core auth + identity secrets are always required.
        require_secret("JWT_SECRET", &self.auth.jwt_secret, 32)?;
        require_secret(
            "SEED_FINGERPRINT_PEPPER",
            &self.secrets.seed_fingerprint_pepper,
            32,
        )?;
        require_secret(
            "REFRESH_TOKEN_PEPPER",
            &self.secrets.refresh_token_pepper,
            32,
        )?;
        require_secret("IP_SALT", &self.secrets.ip_salt, 16)?;

        // Nostr identity: PUBLIC_API_URL must be a real absolute URL.
        if self.features.nostr_identity {
            let url = self.identity.public_api_url.as_deref().ok_or_else(|| {
                cfg_err("PUBLIC_API_URL is required when FEATURE_NOSTR_IDENTITY is on")
            })?;
            let parsed = url::Url::parse(url)
                .map_err(|_| cfg_err("PUBLIC_API_URL must be an absolute URL"))?;
            if prod && parsed.scheme() != "https" {
                return Err(cfg_err("PUBLIC_API_URL must be https in production"));
            }
            if prod && looks_placeholder(url) {
                return Err(cfg_err(
                    "PUBLIC_API_URL looks like a placeholder; set your own domain",
                ));
            }
        }

        // PoW gate: a real HMAC key when enabled (no source-visible fallback).
        if self.pow.enabled {
            require_secret("ALTCHA_HMAC_KEY", &self.pow.hmac_key, 32)?;
        }

        // Admin surface: dedicated secrets + a real public URL when enabled.
        if self.admin.enabled {
            require_secret("ADMIN_JWT_SECRET", &self.admin.jwt_secret, 32)?;
            require_secret(
                "ADMIN_KEY_INTEGRITY_SECRET",
                &self.admin.key_integrity_secret,
                32,
            )?;
            url::Url::parse(&self.admin.public_url)
                .map_err(|_| cfg_err("ADMIN_PUBLIC_URL must be an absolute URL"))?;
        }

        // Fleet mode cannot rely on in-process challenge state.
        if self.deployment_mode == DeploymentMode::Fleet {
            tracing::info!(
                "deployment_mode=fleet: challenge/nonce state must be shared-store backed"
            );
        }

        // Price feed: provider must be one we implement, and every configured
        // asset must be one we can quote. Fail closed on a typo rather than
        // booting a feed that can never populate (which would still advertise
        // prices:true and silently serve nothing).
        if self.features.prices {
            if !matches!(self.features.prices_provider.as_str(), "coingecko") {
                return Err(cfg_err(format!(
                    "PRICES_PROVIDER {:?} is not supported; supported: coingecko",
                    self.features.prices_provider
                )));
            }
            for asset in &self.features.prices_assets {
                if !SUPPORTED_PRICE_ASSETS.contains(&asset.as_str()) {
                    return Err(cfg_err(format!(
                        "PRICES_ASSETS contains unsupported asset {asset:?}; supported: {}",
                        SUPPORTED_PRICE_ASSETS.join(", ")
                    )));
                }
            }
            if !SUPPORTED_PRICE_CURRENCIES.contains(&self.features.prices_currency.as_str()) {
                return Err(cfg_err(format!(
                    "PRICES_CURRENCY {:?} is not supported; supported: {}",
                    self.features.prices_currency,
                    SUPPORTED_PRICE_CURRENCIES.join(", ")
                )));
            }
        }

        // Self-service erasure: its audit trail is the integrity-MAC'd hash chain,
        // and its proofs bind PUBLIC_API_URL — both are required when it's on.
        if self.retention.erasure_enabled {
            require_secret(
                "ADMIN_KEY_INTEGRITY_SECRET",
                &self.admin.key_integrity_secret,
                32,
            )?;
            if self.identity.public_api_url.is_none() {
                return Err(cfg_err(
                    "PUBLIC_API_URL is required when ERASURE_ENABLED is on (it binds the signed-action proof)",
                ));
            }
            // Bound the grace window: a huge value panics Duration::hours and an
            // overflow on the i64 cast could wrap negative (defeating grace).
            if self.retention.grace_period_hours > 24 * 365 * 10 {
                return Err(cfg_err(
                    "ERASURE_GRACE_PERIOD_HOURS must be <= 87600 (10 years)",
                ));
            }
        }

        // Per-enabled-chain infra config: hard error in production, warn in dev.
        // This keeps /capabilities honest — an enabled chain that can't be served
        // (no node/secret) must not boot in prod advertising itself as available.
        let mut chain_warnings: Vec<&str> = Vec::new();
        if self.features.chains.btc
            && self.chains.btc.electrum_primary.is_none()
            && self.chains.btc.electrum_fallbacks.is_empty()
        {
            chain_warnings.push("BTC_ELECTRUM_URL");
        }
        if self.features.chains.ltc
            && self.chains.ltc.electrum_primary.is_none()
            && self.chains.ltc.electrum_fallbacks.is_empty()
        {
            chain_warnings.push("LTC_ELECTRUM_URL");
        }
        if self.features.chains.xmr && self.chains.xmr.lws_admin_key.is_empty() {
            chain_warnings.push("XMR_LWS_ADMIN_KEY");
        }
        if self.features.chains.wow && self.chains.wow.lws_admin_key.is_empty() {
            chain_warnings.push("WOW_LWS_ADMIN_KEY");
        }
        if self.features.chains.grin && self.chains.grin.owner_api_secret.is_empty() {
            chain_warnings.push("GRIN_OWNER_API_SECRET");
        }
        if !chain_warnings.is_empty() {
            if prod {
                return Err(cfg_err(format!(
                    "missing required config for enabled chains: {}",
                    chain_warnings.join(", ")
                )));
            }
            for w in &chain_warnings {
                tracing::warn!("{w} is unset — set this before enabling that chain in production");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Fail-closed validation regression tests. `validate()` must reject weak
    //! or inconsistent security settings rather than booting.
    use super::*;

    fn valid() -> Config {
        let utxo = || UtxoConfig {
            network: "mainnet".into(),
            electrum_primary: None,
            electrum_fallbacks: vec![],
        };
        let lws = || LwsConfig {
            lws_url: String::new(),
            lws_admin_url: String::new(),
            lws_admin_key: String::new(),
            daemon_url: String::new(),
        };
        Config {
            server_host: "0.0.0.0".into(),
            server_port: 8080,
            deployment_mode: DeploymentMode::Single,
            environment: "development".into(),
            database_url: "postgres://localhost/smirk".into(),
            auth: AuthConfig {
                jwt_secret: "a".repeat(32),
                jwt_expiry_hours: 24,
            },
            identity: IdentityConfig {
                public_api_url: Some("https://backend.example.org/api/v1".into()),
            },
            secrets: SecretConfig {
                seed_fingerprint_pepper: "p".repeat(32),
                refresh_token_pepper: "r".repeat(32),
                ip_salt: "s".repeat(16),
            },
            trusted_proxies: vec![],
            cors_allowed_origins: vec![],
            features: FeatureFlags {
                chains: ChainFlags {
                    btc: false,
                    ltc: false,
                    xmr: false,
                    wow: false,
                    grin: false,
                },
                prices: false,
                prices_provider: "coingecko".into(),
                prices_interval_secs: 300,
                prices_assets: vec!["btc".into(), "xmr".into()],
                prices_currency: "usd".into(),
                tips: false,
                nostr_identity: true,
                grin_relay: true,
            },
            chains: ChainConfig {
                btc: utxo(),
                ltc: utxo(),
                xmr: lws(),
                wow: lws(),
                grin: GrinConfig {
                    owner_api_url: String::new(),
                    owner_api_secret: String::new(),
                    wallet_password: String::new(),
                    foreign_api_url: String::new(),
                    node_api_url: String::new(),
                    node_api_user: String::new(),
                    node_api_pass: String::new(),
                    node_foreign_api_url: String::new(),
                    node_foreign_api_secret: String::new(),
                },
            },
            pow: PowConfig {
                enabled: false,
                hmac_key: String::new(),
                required: false,
                cost: 100_000,
                required_for_pubkeys: vec![],
            },
            admin: AdminConfig {
                enabled: false,
                bind: "127.0.0.1:8081".into(),
                public_url: "http://127.0.0.1:8081".into(),
                jwt_secret: String::new(),
                key_integrity_secret: String::new(),
                pubkeys: vec![],
                max_keys: 8,
                pending_key_ttl_days: 7,
                allow_public_bind: false,
                onion: None,
            },
            landing: LandingConfig {
                enabled: false,
                title: None,
                expose_version: false,
                expose_chains: false,
                expose_price_feed: false,
                expose_uptime: false,
                stats_enabled: false,
                stats_cache_hours: 24,
            },
            retention: RetentionConfig {
                login_events_days: 90,
                audit_days: 365,
                erasure_enabled: false,
                purge_login_events: true,
                export_per_day: 3,
                grace_period_hours: 72,
            },
        }
    }

    #[test]
    fn valid_config_passes() {
        assert!(valid().validate().is_ok());
    }

    #[test]
    fn short_jwt_secret_rejected() {
        let mut c = valid();
        c.auth.jwt_secret = "tooshort".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn placeholder_jwt_rejected_in_production() {
        let mut c = valid();
        c.environment = "production".into();
        c.auth.jwt_secret = "CHANGE_ME_CHANGE_ME_CHANGE_ME_1234".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn nostr_requires_public_api_url() {
        let mut c = valid();
        c.identity.public_api_url = None;
        assert!(c.validate().is_err());
    }

    #[test]
    fn missing_pepper_rejected() {
        let mut c = valid();
        c.secrets.seed_fingerprint_pepper.clear();
        assert!(c.validate().is_err());
    }

    #[test]
    fn pow_enabled_requires_key() {
        let mut c = valid();
        c.pow.enabled = true;
        assert!(c.validate().is_err());
    }

    #[test]
    fn enabled_chain_requires_secret_in_production() {
        let mut c = valid();
        c.environment = "production".into();
        c.features.chains.xmr = true; // xmr.lws_admin_key is empty
        assert!(c.validate().is_err());
    }

    #[test]
    fn unsupported_price_provider_rejected() {
        let mut c = valid();
        c.features.prices = true;
        c.features.prices_provider = "binance".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn unsupported_price_asset_rejected() {
        let mut c = valid();
        c.features.prices = true;
        c.features.prices_assets = vec!["doge".into()];
        assert!(c.validate().is_err());
    }

    #[test]
    fn disabled_prices_skips_provider_validation() {
        let mut c = valid();
        c.features.prices = false;
        c.features.prices_provider = "binance".into();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn unsupported_price_currency_rejected() {
        let mut c = valid();
        c.features.prices = true;
        c.features.prices_currency = "usdd".into(); // typo
        assert!(c.validate().is_err());
    }

    #[test]
    fn enabled_utxo_chain_without_electrum_rejected_in_production() {
        let mut c = valid();
        c.environment = "production".into();
        c.features.chains.btc = true; // btc has no electrum_primary/fallbacks
        assert!(c.validate().is_err());
    }
}
