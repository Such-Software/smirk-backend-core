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

/// True if the URL's host is loopback (127.0.0.0/8, ::1, or `localhost`).
/// Plaintext to a loopback processor is acceptable even in production: the hop
/// never leaves the host (e.g. a payment processor reached over an SSH tunnel or
/// a local reverse proxy), so the https requirement is relaxed for it.
fn is_loopback_url(s: &str) -> bool {
    match url::Url::parse(s).ok().and_then(|u| u.host().map(|h| h.to_owned())) {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// Whether `s` is a positive decimal literal — digits with at most one dot and
/// at least one non-zero digit (`"0.01"`, `"1"`, `"10.5"` yes; `"0"`, `"0.00"`,
/// `"-1"`, `"1e5"`, `""` no). Validates a price without pulling in float math.
fn is_positive_decimal(s: &str) -> bool {
    let mut seen_dot = false;
    let mut seen_digit = false;
    let mut seen_nonzero = false;
    for c in s.chars() {
        match c {
            '0'..='9' => {
                seen_digit = true;
                seen_nonzero |= c != '0';
            }
            '.' if !seen_dot => seen_dot = true,
            _ => return false,
        }
    }
    seen_digit && seen_nonzero
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

    /// Base URL for public-tip share links: a tip's share URL is
    /// `{tip_share_base}/{tip_id}`. Required when `FEATURE_TIPS` is on (checked
    /// in `validate`); never hardcode a host (federation).
    pub tip_share_base: Option<String>,

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
    pub restore: RestoreConfig,
    pub registration: RegistrationConfig,
    pub messaging: MessagingConfig,
    pub premium: PremiumConfig,
    pub feed: FeedConfig,
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
    pub grin_lws: GrinLwsConfig,
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
    /// Require CA-verified TLS (webpki + hostname) for ssl:// electrum servers.
    /// Default false: electrum servers are self-signed by convention and their
    /// data is treated as hostile regardless (see electrum.rs), so accepting any
    /// cert keeps the public fallbacks usable. Operators who run their own
    /// CA-cert'd Fulcrum can set `ELECTRUM_STRICT_TLS=1` to harden.
    pub electrum_strict_tls: bool,
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

/// grin-lws (Grin light-wallet-server) configuration. An optional add-on to the
/// Grin chain: when `url` is set (and `FEATURE_GRIN` is on) the backend's Grin
/// scan proxies to grin-lws first, falling back to the authoritative
/// grin-wallet scan. Unset = "use grin-wallet only".
#[derive(Clone)]
pub struct GrinLwsConfig {
    pub url: String,
    pub admin_url: Option<String>,
    pub admin_key: String,
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

/// Wallet restore (import) policy — an OPERATOR decision, because the scan cost
/// of a deep restore lands on *this* instance's LWS/node. Advertised via
/// `/capabilities` (so the wallet adapts its import UX) and enforced at the scan
/// path. Self-sovereignty is preserved at the ecosystem level: a user needing a
/// deeper restore runs their own instance or picks a looser operator.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RestorePolicy {
    /// New-wallet registration only — the scan start must sit at (near) the tip.
    CreateOnly,
    /// Restore permitted up to `max_depth_days` behind the tip.
    Bounded,
    /// Any restore height accepted (the natural choice for self-hosting).
    Unlimited,
}

impl RestorePolicy {
    /// The wire token used in `/capabilities`.
    pub fn as_str(&self) -> &'static str {
        match self {
            RestorePolicy::CreateOnly => "create-only",
            RestorePolicy::Bounded => "bounded",
            RestorePolicy::Unlimited => "unlimited",
        }
    }
}

#[derive(Clone, Copy)]
pub struct RestoreConfig {
    pub policy: RestorePolicy,
    /// For `Bounded`: how many days behind the tip a restore may start.
    pub max_depth_days: u32,
    /// Restore depth (days behind tip) that is FREE of PoW pricing.
    pub pow_free_days: u32,
    /// `+1` hashcash difficulty bit per this many days of restore depth beyond
    /// the free window. `0` disables restore pricing (the depth gate above still
    /// applies). Each bit ~doubles the wallet's solve time, so the requester pays
    /// compute proportional to the scan cost they impose on the operator.
    pub pow_days_per_bit: u32,
    /// Hard cap on the priced difficulty (bounds wallet solve time on a phone).
    pub pow_max_bits: u32,
}

/// Approximate blocks per day per chain (from target block time). Used only to
/// turn the `max_depth_days` policy into a height floor — a soft operator bound,
/// never a consensus value, so an approximation is fine.
fn blocks_per_day(chain: &str) -> u64 {
    match chain {
        "xmr" | "wow" => 720, // ~120s target
        "grin" => 1440,       // ~60s target
        "btc" => 144,         // ~600s
        "ltc" => 576,         // ~150s
        _ => 720,
    }
}

impl RestoreConfig {
    /// The earliest height this instance will scan from for `chain`, given the
    /// current `tip`. `0` means "no floor" (Unlimited).
    pub fn min_start_height(&self, chain: &str, tip: u64) -> u64 {
        let depth_days = match self.policy {
            RestorePolicy::Unlimited => return 0,
            // 1-day grace so a wallet "created today" still registers under
            // create-only without a tight tip race.
            RestorePolicy::CreateOnly => 1,
            RestorePolicy::Bounded => self.max_depth_days as u64,
        };
        tip.saturating_sub(depth_days.saturating_mul(blocks_per_day(chain)))
    }

    /// Enforce the policy for a requested `start_height` against the live `tip`.
    /// A too-deep restore is a `ValidationError` naming the bound — never the
    /// caller's value. Unlimited always passes.
    pub fn enforce(&self, chain: &str, start_height: u64, tip: u64) -> Result<(), AppError> {
        if self.policy == RestorePolicy::Unlimited
            || start_height >= self.min_start_height(chain, tip)
        {
            return Ok(());
        }
        Err(match self.policy {
            RestorePolicy::CreateOnly => AppError::ValidationError(
                "this instance accepts new-wallet registration only (create-only); a restore \
                 scan from an earlier height is not permitted here"
                    .into(),
            ),
            RestorePolicy::Bounded => AppError::ValidationError(format!(
                "restore depth exceeds this instance's limit of {} days",
                self.max_depth_days
            )),
            RestorePolicy::Unlimited => unreachable!(),
        })
    }

    /// Hashcash difficulty (leading zero BITS) required to restore `chain` from
    /// `start_height` against `tip` — `0` within the free window or when pricing
    /// is off. The depth→bits curve is the operator's "pay for the scan you cost
    /// me" knob; it sits ON TOP of the [`enforce`](Self::enforce) depth gate.
    pub fn required_restore_pow_bits(&self, chain: &str, start_height: u64, tip: u64) -> u32 {
        if self.pow_days_per_bit == 0 {
            return 0;
        }
        let depth_days = tip.saturating_sub(start_height) / blocks_per_day(chain).max(1);
        let over = depth_days.saturating_sub(self.pow_free_days as u64);
        ((over / self.pow_days_per_bit as u64) as u32).min(self.pow_max_bits)
    }

    /// Enforce restore PoW pricing: when the requested depth is priced, a valid
    /// hashcash `nonce` (bound to `chain`/`address`/`start_height`) of the
    /// required difficulty must accompany the restore. A literal error names the
    /// requirement, never the caller's value.
    pub fn enforce_restore_pow(
        &self,
        chain: &str,
        address: &str,
        start_height: u64,
        tip: u64,
        nonce: Option<u64>,
    ) -> Result<(), AppError> {
        let bits = self.required_restore_pow_bits(chain, start_height, tip);
        if bits == 0 {
            return Ok(());
        }
        let nonce = nonce.ok_or_else(|| {
            AppError::ValidationError(format!(
                "this restore depth requires a {bits}-bit proof-of-work nonce; \
                 upgrade to a newer Smirk client"
            ))
        })?;
        if !crate::core::restore_pow::verify(chain, address, start_height, nonce, bits) {
            return Err(AppError::ValidationError(
                "restore proof-of-work is insufficient for the requested depth".into(),
            ));
        }
        Ok(())
    }
}

/// How the composable registration gates (invite / payment) combine. PoW is
/// orthogonal and always applies on top, regardless of mode.
///
/// - `All` (default): a new wallet must satisfy EVERY enabled gate (conjunction)
///   — the historical behavior.
/// - `Any`: the enabled gates are ALTERNATIVES; the wallet satisfies exactly ONE
///   (the client presents that one method's credential). Lets an operator offer
///   e.g. "invite code OR pay to register."
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum GateMode {
    #[default]
    All,
    Any,
}

impl GateMode {
    /// Wire string advertised via `/capabilities` and parsed from env.
    pub fn as_str(self) -> &'static str {
        match self {
            GateMode::All => "all",
            GateMode::Any => "any",
        }
    }

    /// Parse the operator's `REGISTRATION_GATE_MODE`. Anything other than a
    /// case-insensitive `any` is the safe default (`all` — conjunction).
    pub fn from_env_str(s: &str) -> Self {
        if s.eq_ignore_ascii_case("any") {
            GateMode::Any
        } else {
            GateMode::All
        }
    }
}

/// Registration gates beyond PoW — composable, operator-configured, advertised
/// via `/capabilities`. Each is a gate the wallet must satisfy to create a NEW
/// identity; returning wallets bypass them, and self-hosting bypasses all of
/// them (run your own backend). PoW lives in [`PowConfig`]; this holds the rest.
#[derive(Clone)]
pub struct RegistrationConfig {
    /// Require a valid operator-minted invite code to register a new wallet.
    pub require_invite: bool,
    /// Pay-to-register gate (settle an invoice on an external, non-custodial
    /// processor before a new wallet is granted).
    pub payment: PaymentConfig,
    /// How enabled gates combine (`All` = every gate; `Any` = one-of). PoW is
    /// orthogonal and applies regardless.
    pub gate_mode: GateMode,
}

/// Pay-to-register gate. When `require_payment` is on, a NEW wallet must present
/// a SETTLED payment invoice — minted at `/auth/payment-invoice` and paid to the
/// operator's OWN wallet via an external processor (the `btcpay` adapter also
/// serves this project's xmrcheckout/wowcheckout apps + the BTCPay Monero
/// plugin). Returning wallets bypass it; self-hosting bypasses all gates. Does
/// not derive `Debug` (holds the processor API key).
#[derive(Clone)]
pub struct PaymentConfig {
    pub require_payment: bool,
    /// Processor adapter kind (currently only `btcpay`).
    pub provider: String,
    /// Processor base URL (e.g. `https://pay.example.org`).
    pub provider_url: String,
    /// Processor store/merchant id.
    pub store_id: String,
    /// Processor API key (create/read invoices). Never logged.
    pub api_key: String,
    /// Registration price, as a decimal string (no float math end-to-end).
    pub amount: String,
    /// Price currency (e.g. `XMR`, or a fiat code the processor converts).
    pub currency: String,
    /// Operator's confirmations-to-finalize; the adapter maps it to the
    /// processor's own finality control.
    pub confirmations: u32,
    /// Invoice lifetime (minutes) before it expires unpaid.
    pub expires_minutes: u32,
}

/// A single premium purchase option (a discount tier): `days` of relay-posting
/// access for `amount` in the shared [`PremiumConfig::currency`].
#[derive(Debug, Clone)]
pub struct PremiumPlan {
    pub id: String,
    pub days: i32,
    pub amount: String,
}

/// Premium subscription tier: recurring, tiered access to the operator's Nostr
/// relay for general posting (the `premium-post` write policy). Reuses the
/// registration PaymentProvider for invoicing. Off by default.
#[derive(Clone)]
pub struct PremiumConfig {
    pub enabled: bool,
    pub currency: String,
    pub plans: Vec<PremiumPlan>,
}

/// Parse `PREMIUM_PLANS` = comma-separated `id:days:amount` entries (e.g.
/// `quarter:90:5,year:365:15`). Malformed entries are dropped; `validate()`
/// rejects an empty result when premium is enabled.
fn parse_premium_plans(s: &str) -> Vec<PremiumPlan> {
    s.split(',')
        .filter_map(|entry| {
            let mut parts = entry.trim().splitn(3, ':');
            let id = parts.next()?.trim();
            let days = parts.next()?.trim().parse::<i32>().ok()?;
            let amount = parts.next()?.trim();
            (!id.is_empty() && !amount.is_empty() && days > 0).then(|| PremiumPlan {
                id: id.to_string(),
                days,
                amount: amount.to_string(),
            })
        })
        .collect()
}

/// Messaging plane (identity + encrypted delivery). Today it holds the optional
/// first-party Nostr relay; the seam leaves room for other messaging backends.
#[derive(Clone)]
pub struct MessagingConfig {
    pub relay: RelayConfig,
}

/// Optional first-party Nostr relay. When `enabled`, the operator runs a relay
/// (the packaged `nostr-rs-relay`, or an external one) that the backend
/// ADVERTISES (NIP-05 / kind-10050) and, for a non-`open` policy, write-restricts
/// via a gRPC event-admission service. It is the user's INBOX relay, never the
/// only relay — clients also use the public interop relays. Self-hosting concern;
/// off by default. Does not derive `Debug` (URL/policy are fine, but kept
/// consistent with the other adapter configs).
#[derive(Clone)]
pub struct RelayConfig {
    /// Master switch for the relay integration.
    pub enabled: bool,
    /// `bundled` (operator runs the packaged nostr-rs-relay) or `external`
    /// (point at any relay the operator already runs). The seam handles both.
    pub mode: String,
    /// Public `wss://` URL clients connect to + we advertise.
    pub advertised_url: String,
    /// Admission policy the gRPC service enforces: `inbox-outbox` (default),
    /// `author-allowlist`, or `open`.
    pub write_policy: String,
    /// NIP-13 proof-of-work bits required on cross-ecosystem (non-registered-
    /// author) inbound events; `0` disables the PoW gate.
    pub inbound_pow_bits: u8,
    /// Loopback address the gRPC event-admission service binds (nostr-rs-relay
    /// calls it per event). Only used when `write_policy != open`. It answers
    /// "is this npub registered?", so it MUST stay loopback (a registration
    /// oracle) unless explicitly opted out.
    pub admission_bind: String,
    /// Allow a NON-loopback `admission_bind` (e.g. a relay in a container without
    /// host networking). Off by default; the operator must firewall it.
    pub admission_allow_public: bool,
    /// Reject events larger than this many bytes (the relay enforces it too).
    pub max_event_bytes: usize,
    /// Event retention (days) — advisory for operator housekeeping/advertising.
    pub retention_days: u32,
    /// Write-exempt npubs (hex or `npub1…`): may publish ANY kind regardless of
    /// the write policy or premium status. The operator's use case is an
    /// announcements / feed-owner account that seeds a `premium-post` feed without
    /// itself holding a subscription. Empty by default. Configured via
    /// `RELAY_WRITE_ALLOWLIST_NPUBS` (comma-separated).
    pub write_allowlist: Vec<String>,
}

/// Public curated feed (`feed.<domain>`) — an operator knob for what the
/// read-only web feed shows. It reads from the relay, so it requires
/// `RELAY_ENABLED`. All public display config, no secrets.
#[derive(Clone)]
pub struct FeedConfig {
    /// Master switch — advertise a curated public feed for this instance.
    pub enabled: bool,
    /// Include the operator's own posts.
    pub show_owner: bool,
    /// Include premium members' posts (all general notes on the gated relay).
    pub show_premium: bool,
    /// The operator's npub (hex or `npub1…`) for owner filtering + display;
    /// empty when unset.
    pub owner_npub: String,
    /// Specific featured npubs to surface (hex or `npub1…`).
    pub allowlist_npubs: Vec<String>,
    /// Extra relays to also pull the allowlisted authors from.
    pub extra_relays: Vec<String>,
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

            tip_share_base: env_opt("TIP_SHARE_BASE_URL"),

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
                    electrum_strict_tls: env_bool("ELECTRUM_STRICT_TLS", false),
                },
                ltc: UtxoConfig {
                    network: env_or("LTC_NETWORK", "mainnet"),
                    electrum_primary: env_opt("LTC_ELECTRUM_URL"),
                    electrum_fallbacks: env_list("LTC_ELECTRUM_FALLBACKS"),
                    electrum_strict_tls: env_bool("ELECTRUM_STRICT_TLS", false),
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
                grin_lws: GrinLwsConfig {
                    url: env_or("GRIN_LWS_URL", ""),
                    admin_url: env_opt("GRIN_LWS_ADMIN_URL"),
                    admin_key: env_or("GRIN_LWS_ADMIN_KEY", ""),
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
            restore: {
                let policy = match env_or("WALLET_RESTORE_POLICY", "create-only")
                    .to_lowercase()
                    .as_str()
                {
                    "create-only" | "create_only" | "createonly" => RestorePolicy::CreateOnly,
                    "bounded" => RestorePolicy::Bounded,
                    "unlimited" => RestorePolicy::Unlimited,
                    other => {
                        return Err(cfg_err(format!(
                        "WALLET_RESTORE_POLICY must be create-only|bounded|unlimited, got {other}"
                    )))
                    }
                };
                RestoreConfig {
                    policy,
                    max_depth_days: env_parse("WALLET_MAX_RESTORE_DEPTH_DAYS", 365u32)?,
                    pow_free_days: env_parse("WALLET_RESTORE_POW_FREE_DAYS", 90u32)?,
                    pow_days_per_bit: env_parse("WALLET_RESTORE_POW_DAYS_PER_BIT", 0u32)?,
                    pow_max_bits: env_parse("WALLET_RESTORE_POW_MAX_BITS", 24u32)?,
                }
            },
            registration: RegistrationConfig {
                require_invite: env_bool("REGISTRATION_REQUIRE_INVITE", false),
                payment: PaymentConfig {
                    require_payment: env_bool("REGISTRATION_REQUIRE_PAYMENT", false),
                    provider: env_or("PAYMENT_PROVIDER", "btcpay").to_lowercase(),
                    provider_url: env_or("PAYMENT_PROVIDER_URL", ""),
                    store_id: env_or("PAYMENT_STORE_ID", ""),
                    api_key: env_or("PAYMENT_API_KEY", ""),
                    amount: env_or("PAYMENT_AMOUNT", ""),
                    currency: env_or("PAYMENT_CURRENCY", "").to_uppercase(),
                    confirmations: env_parse("PAYMENT_CONFIRMATIONS", 1u32)?,
                    expires_minutes: env_parse("PAYMENT_EXPIRES_MINUTES", 60u32)?,
                },
                gate_mode: GateMode::from_env_str(&env_or("REGISTRATION_GATE_MODE", "all")),
            },
            messaging: MessagingConfig {
                relay: RelayConfig {
                    enabled: env_bool("RELAY_ENABLED", false),
                    mode: env_or("RELAY_MODE", "bundled").to_lowercase(),
                    advertised_url: env_or("RELAY_URL", ""),
                    write_policy: env_or("RELAY_WRITE_POLICY", "inbox-outbox").to_lowercase(),
                    inbound_pow_bits: env_parse("RELAY_INBOUND_POW_BITS", 0u8)?,
                    admission_bind: env_or("RELAY_ADMISSION_BIND", "127.0.0.1:8090"),
                    admission_allow_public: env_bool("RELAY_ADMISSION_ALLOW_PUBLIC", false),
                    max_event_bytes: env_parse("RELAY_MAX_EVENT_BYTES", 65536usize)?,
                    retention_days: env_parse("RELAY_RETENTION_DAYS", 30u32)?,
                    write_allowlist: env_list("RELAY_WRITE_ALLOWLIST_NPUBS"),
                },
            },
            premium: PremiumConfig {
                enabled: env_bool("PREMIUM_ENABLED", false),
                currency: env_or("PREMIUM_CURRENCY", "").to_uppercase(),
                plans: parse_premium_plans(&env_or("PREMIUM_PLANS", "")),
            },
            feed: FeedConfig {
                enabled: env_bool("FEED_ENABLED", false),
                show_owner: env_bool("FEED_SHOW_OWNER", true),
                show_premium: env_bool("FEED_SHOW_PREMIUM", true),
                owner_npub: env_or("FEED_OWNER_NPUB", "").trim().to_string(),
                allowlist_npubs: env_list("FEED_ALLOWLIST_NPUBS"),
                extra_relays: env_list("FEED_EXTRA_RELAYS"),
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

        // Restore policy: a Bounded policy needs a positive depth (0 would
        // silently behave as create-only and muddy the capabilities contract).
        if self.restore.policy == RestorePolicy::Bounded && self.restore.max_depth_days == 0 {
            return Err(cfg_err(
                "WALLET_MAX_RESTORE_DEPTH_DAYS must be > 0 when WALLET_RESTORE_POLICY=bounded",
            ));
        }

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
        // Fail closed on the silent-disarm footgun: asking for PoW (POW_REQUIRED or a
        // per-pubkey list) while the feature master switch is off means the gate never
        // applies and /capabilities reports pow_required:false — a signup endpoint the
        // operator believes is protected but isn't.
        if !self.pow.enabled && (self.pow.required || !self.pow.required_for_pubkeys.is_empty()) {
            return Err(cfg_err(
                "POW_REQUIRED (or TEST_POW_REQUIRED_FOR_PUBKEYS) is set but FEATURE_POW is off \
                 — the PoW gate would never apply; set FEATURE_POW=true",
            ));
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
            if !matches!(self.features.prices_provider.as_str(), "coingecko" | "kraken") {
                return Err(cfg_err(format!(
                    "PRICES_PROVIDER {:?} is not supported; supported: coingecko, kraken",
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

        // Public tips escrow on-chain and deliver by share URL, so an instance
        // with FEATURE_TIPS on but no chain to escrow on, or no TIP_SHARE_BASE_URL
        // to build share links from, would advertise a tips subsystem it cannot
        // actually serve. Fail closed rather than boot broken. Grin tips (voucher
        // model, verified against the grin node) are supported, so grin counts.
        if self.features.tips {
            let c = &self.features.chains;
            if !(c.btc || c.ltc || c.xmr || c.wow || c.grin) {
                return Err(cfg_err(
                    "FEATURE_TIPS is on but no supported tip chain is enabled: enable at least \
                     one of FEATURE_BTC / FEATURE_LTC / FEATURE_XMR / FEATURE_WOW / FEATURE_GRIN",
                ));
            }
            if self.tip_share_base.is_none() {
                return Err(cfg_err(
                    "FEATURE_TIPS is on but TIP_SHARE_BASE_URL is unset — it is required to build \
                     public tip share links",
                ));
            }
        }

        // Pay-to-register gate: when on, the processor wiring must be complete
        // and sane, or /capabilities would advertise payment_required while every
        // registration then fails. Fail closed at startup instead.
        if self.registration.payment.require_payment {
            let p = &self.registration.payment;
            if !matches!(p.provider.as_str(), "btcpay") {
                return Err(cfg_err(format!(
                    "PAYMENT_PROVIDER {:?} is not supported; supported: btcpay",
                    p.provider
                )));
            }
            if p.provider_url.is_empty() {
                return Err(cfg_err(
                    "PAYMENT_PROVIDER_URL is required when REGISTRATION_REQUIRE_PAYMENT is on",
                ));
            }
            let url = url::Url::parse(&p.provider_url)
                .map_err(|_| cfg_err("PAYMENT_PROVIDER_URL must be an absolute URL"))?;
            if prod && url.scheme() != "https" && !is_loopback_url(&p.provider_url) {
                return Err(cfg_err(
                    "PAYMENT_PROVIDER_URL must be https in production (loopback exempt)",
                ));
            }
            if p.store_id.is_empty() {
                return Err(cfg_err(
                    "PAYMENT_STORE_ID is required when REGISTRATION_REQUIRE_PAYMENT is on",
                ));
            }
            // Processor API keys are long; 8 is a floor against an empty/typo'd value.
            require_secret("PAYMENT_API_KEY", &p.api_key, 8)?;
            if !is_positive_decimal(&p.amount) {
                return Err(cfg_err(
                    "PAYMENT_AMOUNT must be a positive decimal (e.g. 0.01) when REGISTRATION_REQUIRE_PAYMENT is on",
                ));
            }
            if p.currency.is_empty() {
                return Err(cfg_err(
                    "PAYMENT_CURRENCY is required when REGISTRATION_REQUIRE_PAYMENT is on",
                ));
            }
            // 0-conf ("HighSpeed") marks an invoice settled on first mempool
            // sighting, which a payer can then double-spend away AFTER registering
            // — a settled-then-reversed free registration. An on-chain gate must
            // require at least one confirmation. (A genuinely-final 0-conf rail
            // like Lightning would be a different provider, not this one.)
            if p.confirmations == 0 {
                return Err(cfg_err(
                    "PAYMENT_CONFIRMATIONS must be >= 1 (0-conf lets a settled payment be \
                     double-spent after registration)",
                ));
            }
            // Bound the unpaid-invoice window: 0 never expires, and > BTCPay's own
            // max (10080 min = 7 days) both accumulates stale rows and would be
            // rejected by the processor at create time.
            if p.expires_minutes == 0 || p.expires_minutes > 10080 {
                return Err(cfg_err(
                    "PAYMENT_EXPIRES_MINUTES must be between 1 and 10080 (7 days)",
                ));
            }
        }

        // ── Nostr relay (optional messaging plane) ──────────────────────────
        if self.messaging.relay.enabled {
            let r = &self.messaging.relay;
            if !matches!(r.mode.as_str(), "bundled" | "external") {
                return Err(cfg_err(format!(
                    "RELAY_MODE {:?} is not supported; use bundled|external",
                    r.mode
                )));
            }
            if r.advertised_url.trim().is_empty() {
                return Err(cfg_err(
                    "RELAY_URL is required when RELAY_ENABLED (the ws(s):// URL clients connect to)",
                ));
            }
            if !(r.advertised_url.starts_with("wss://") || r.advertised_url.starts_with("ws://")) {
                return Err(cfg_err("RELAY_URL must be a ws:// or wss:// URL"));
            }
            if prod && r.advertised_url.starts_with("ws://") {
                return Err(cfg_err("RELAY_URL must be wss:// in production"));
            }
            if !matches!(
                r.write_policy.as_str(),
                "inbox-outbox" | "author-allowlist" | "open" | "premium-post"
            ) {
                return Err(cfg_err(format!(
                    "RELAY_WRITE_POLICY {:?} is not supported; use inbox-outbox|author-allowlist|open|premium-post",
                    r.write_policy
                )));
            }
            // Bound PoW difficulty: 0 = off; a value this high is unsolvable in
            // practice and would silently reject every inbound event.
            if r.inbound_pow_bits > 40 {
                return Err(cfg_err("RELAY_INBOUND_POW_BITS must be <= 40 (0 disables)"));
            }
            // A non-`open` policy is enforced by the gRPC admission service, which
            // needs a bind address the relay can reach.
            if r.write_policy != "open" && r.admission_bind.trim().is_empty() {
                return Err(cfg_err(
                    "RELAY_ADMISSION_BIND is required for a non-open RELAY_WRITE_POLICY",
                ));
            }
            // The admission service answers "is this npub registered?" per event —
            // a registration oracle. Require a loopback bind unless the operator
            // explicitly opts out (and firewalls it).
            if r.write_policy != "open" && !r.admission_allow_public {
                use std::net::ToSocketAddrs;
                let loopback = r
                    .admission_bind
                    .to_socket_addrs()
                    .map(|addrs| {
                        let addrs: Vec<_> = addrs.collect();
                        !addrs.is_empty() && addrs.iter().all(|a| a.ip().is_loopback())
                    })
                    .unwrap_or(false);
                if !loopback {
                    return Err(cfg_err(
                        "RELAY_ADMISSION_BIND must be loopback (it is a registration oracle); \
                         set RELAY_ADMISSION_ALLOW_PUBLIC=true to override + firewall it",
                    ));
                }
            }
        }

        // Premium tier reuses the registration PaymentProvider for invoicing, so
        // the processor credentials must be present, the relay must be on with the
        // premium-post policy, and there must be at least one priced plan.
        // The public feed reads from the relay, so it needs the relay enabled.
        if self.feed.enabled && !self.messaging.relay.enabled {
            return Err(cfg_err(
                "FEED_ENABLED needs RELAY_ENABLED=true (the feed reads posts from the relay)",
            ));
        }

        if self.premium.enabled {
            let p = &self.registration.payment;
            if !matches!(p.provider.as_str(), "btcpay") {
                return Err(cfg_err(format!(
                    "PREMIUM_ENABLED needs a supported PAYMENT_PROVIDER (btcpay); got {:?}",
                    p.provider
                )));
            }
            if p.provider_url.trim().is_empty() {
                return Err(cfg_err("PREMIUM_ENABLED needs PAYMENT_PROVIDER_URL"));
            }
            if prod && !p.provider_url.starts_with("https://") && !is_loopback_url(&p.provider_url) {
                return Err(cfg_err(
                    "PAYMENT_PROVIDER_URL must be https:// in production (loopback exempt)",
                ));
            }
            if p.store_id.trim().is_empty() {
                return Err(cfg_err("PREMIUM_ENABLED needs PAYMENT_STORE_ID"));
            }
            require_secret("PAYMENT_API_KEY", &p.api_key, 8)?;
            // The same processor-safety floors the pay-to-register path enforces —
            // premium's common case is require_payment=false, which skips that
            // block. A 0-conf invoice settles on first mempool sighting and can
            // then be double-spent AWAY after the premium grant; a 0/oversize
            // expiry is a malformed invoice window.
            if p.confirmations == 0 {
                return Err(cfg_err(
                    "PAYMENT_CONFIRMATIONS must be >= 1 when PREMIUM_ENABLED is on \
                     (0-conf lets a settled premium payment be double-spent after activation)",
                ));
            }
            if p.expires_minutes == 0 || p.expires_minutes > 10080 {
                return Err(cfg_err(
                    "PAYMENT_EXPIRES_MINUTES must be between 1 and 10080 (7 days)",
                ));
            }
            if self.premium.currency.trim().is_empty() {
                return Err(cfg_err("PREMIUM_ENABLED needs PREMIUM_CURRENCY"));
            }
            if !self.messaging.relay.enabled {
                return Err(cfg_err("PREMIUM_ENABLED needs RELAY_ENABLED=true"));
            }
            if self.messaging.relay.write_policy != "premium-post" {
                return Err(cfg_err(
                    "PREMIUM_ENABLED needs RELAY_WRITE_POLICY=premium-post",
                ));
            }
            if self.premium.plans.is_empty() {
                return Err(cfg_err(
                    "PREMIUM_ENABLED needs at least one PREMIUM_PLANS entry (id:days:amount)",
                ));
            }
            let mut seen = std::collections::HashSet::new();
            for plan in &self.premium.plans {
                if !seen.insert(plan.id.as_str()) {
                    return Err(cfg_err(format!("duplicate PREMIUM_PLANS id {:?}", plan.id)));
                }
                // Same positive-decimal rule as PAYMENT_AMOUNT (rejects NaN/inf/1e5).
                if !is_positive_decimal(&plan.amount) {
                    return Err(cfg_err(format!(
                        "PREMIUM_PLANS[{}] amount {:?} must be a positive decimal",
                        plan.id, plan.amount
                    )));
                }
                // Cap the period: a plan longer than ~10 years is a config error,
                // and a huge value would overflow the premium_until timestamp math
                // (make_interval) at activation — after the invoice is consumed.
                if plan.days > 3660 {
                    return Err(cfg_err(format!(
                        "PREMIUM_PLANS[{}] days {} exceeds the 3660-day (10-year) maximum",
                        plan.id, plan.days
                    )));
                }
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
            electrum_strict_tls: false,
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
            tip_share_base: None,
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
                grin_lws: GrinLwsConfig {
                    url: String::new(),
                    admin_url: None,
                    admin_key: String::new(),
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
            restore: RestoreConfig {
                policy: RestorePolicy::Bounded,
                max_depth_days: 365,
                pow_free_days: 90,
                pow_days_per_bit: 0,
                pow_max_bits: 24,
            },
            registration: RegistrationConfig {
                require_invite: false,
                payment: PaymentConfig {
                    require_payment: false,
                    provider: "btcpay".into(),
                    provider_url: String::new(),
                    store_id: String::new(),
                    api_key: String::new(),
                    amount: String::new(),
                    currency: String::new(),
                    confirmations: 1,
                    expires_minutes: 60,
                },
                gate_mode: GateMode::All,
            },
            messaging: MessagingConfig {
                relay: RelayConfig {
                    enabled: false,
                    mode: "bundled".into(),
                    advertised_url: String::new(),
                    write_policy: "inbox-outbox".into(),
                    inbound_pow_bits: 0,
                    admission_bind: "127.0.0.1:8090".into(),
                    admission_allow_public: false,
                    max_event_bytes: 65536,
                    retention_days: 30,
                    write_allowlist: Vec::new(),
                },
            },
            premium: PremiumConfig {
                enabled: false,
                currency: String::new(),
                plans: Vec::new(),
            },
            feed: FeedConfig {
                enabled: false,
                show_owner: true,
                show_premium: true,
                owner_npub: String::new(),
                allowlist_npubs: Vec::new(),
                extra_relays: Vec::new(),
            },
        }
    }

    /// A fully-wired pay-to-register config (for the require_payment tests).
    fn valid_payment() -> PaymentConfig {
        PaymentConfig {
            require_payment: true,
            provider: "btcpay".into(),
            provider_url: "https://pay.example.org".into(),
            store_id: "store-1".into(),
            api_key: "xmrcheckout_abcdefgh".into(),
            amount: "0.01".into(),
            currency: "XMR".into(),
            confirmations: 1,
            expires_minutes: 60,
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
    fn pow_required_without_feature_pow_rejected() {
        // POW_REQUIRED=true while FEATURE_POW is off silently disarms the gate.
        let mut c = valid();
        c.pow.enabled = false;
        c.pow.required = true;
        assert!(c.validate().is_err());
        // Enabling the master switch (with a key) makes it valid.
        c.pow.enabled = true;
        c.pow.hmac_key = "a".repeat(32);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn enabled_chain_requires_secret_in_production() {
        let mut c = valid();
        c.environment = "production".into();
        c.features.chains.xmr = true; // xmr.lws_admin_key is empty
        assert!(c.validate().is_err());
    }

    #[test]
    fn tips_enabled_requires_share_base() {
        // FEATURE_TIPS on + a tip chain but NO share base → fail closed.
        let mut c = valid();
        c.features.tips = true;
        c.features.chains.btc = true;
        c.tip_share_base = None;
        assert!(c.validate().is_err(), "tips on without a share base must fail");
    }

    #[test]
    fn tips_enabled_requires_a_tip_chain() {
        // FEATURE_TIPS on + a share base but NO tip chain enabled → fail closed.
        // (valid() has all chains off.)
        let mut c = valid();
        c.features.tips = true;
        c.tip_share_base = Some("https://tips.example".into());
        assert!(c.validate().is_err(), "tips on with no tip chain must fail");
    }

    #[test]
    fn tips_enabled_with_chain_and_share_base_ok() {
        let mut c = valid();
        c.features.tips = true;
        c.features.chains.btc = true;
        c.tip_share_base = Some("https://tips.example".into());
        assert!(
            c.validate().is_ok(),
            "tips on with a tip chain + share base is valid"
        );
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

    #[test]
    fn restore_bounded_zero_depth_rejected() {
        let mut c = valid();
        c.restore = RestoreConfig {
            policy: RestorePolicy::Bounded,
            max_depth_days: 0,
            pow_free_days: 90,
            pow_days_per_bit: 0,
            pow_max_bits: 24,
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn restore_unlimited_accepts_any_height() {
        let rc = RestoreConfig {
            policy: RestorePolicy::Unlimited,
            max_depth_days: 0,
            pow_free_days: 0,
            pow_days_per_bit: 0,
            pow_max_bits: 0,
        };
        assert!(rc.enforce("xmr", 1, 3_000_000).is_ok());
    }

    #[test]
    fn restore_bounded_rejects_too_deep_accepts_within() {
        let rc = RestoreConfig {
            policy: RestorePolicy::Bounded,
            max_depth_days: 30,
            pow_free_days: 0,
            pow_days_per_bit: 0,
            pow_max_bits: 0,
        };
        let tip = 3_000_000u64; // 30 days * 720 blocks/day => floor = tip - 21_600.
        assert!(rc.enforce("xmr", tip - 21_600, tip).is_ok()); // exactly at the floor
        assert!(rc.enforce("xmr", tip - 21_601, tip).is_err()); // one below the floor
        assert!(rc.enforce("xmr", tip, tip).is_ok()); // create (at the tip)
    }

    #[test]
    fn restore_create_only_rejects_old_allows_near_tip() {
        let rc = RestoreConfig {
            policy: RestorePolicy::CreateOnly,
            max_depth_days: 365, // ignored under create-only
            pow_free_days: 0,
            pow_days_per_bit: 0,
            pow_max_bits: 0,
        };
        let tip = 3_000_000u64;
        assert!(rc.enforce("xmr", tip, tip).is_ok()); // create
        assert!(rc.enforce("xmr", tip - 720, tip).is_ok()); // within the 1-day grace
        assert!(rc.enforce("xmr", tip - 100_000, tip).is_err()); // a real restore
    }

    fn priced(free: u32, per_bit: u32, max: u32) -> RestoreConfig {
        RestoreConfig {
            policy: RestorePolicy::Unlimited,
            max_depth_days: 0,
            pow_free_days: free,
            pow_days_per_bit: per_bit,
            pow_max_bits: max,
        }
    }

    #[test]
    fn restore_pow_bits_scale_with_depth_and_cap() {
        let rc = priced(30, 30, 10); // free 30d, +1 bit / 30d, cap 10
        let tip = 3_000_000u64;
        let d = |days: u64| tip.saturating_sub(days * 720); // xmr = 720 blocks/day
        assert_eq!(
            rc.required_restore_pow_bits("xmr", d(20), tip),
            0,
            "within free window"
        );
        assert_eq!(
            rc.required_restore_pow_bits("xmr", d(90), tip),
            2,
            "30 free + 60 over => 2 bits"
        );
        assert_eq!(
            rc.required_restore_pow_bits("xmr", d(100_000), tip),
            10,
            "capped"
        );
    }

    #[test]
    fn restore_pow_off_when_days_per_bit_zero() {
        let rc = priced(0, 0, 24);
        assert_eq!(rc.required_restore_pow_bits("xmr", 1, 3_000_000), 0);
        assert!(rc
            .enforce_restore_pow("xmr", "addr", 1, 3_000_000, None)
            .is_ok());
    }

    #[test]
    fn restore_pow_requires_a_valid_nonce_when_priced() {
        let rc = priced(0, 1, 8);
        let tip = 3_000_000u64;
        let start = tip - 8 * 720; // 8 days depth => 8 bits
        assert_eq!(rc.required_restore_pow_bits("xmr", start, tip), 8);
        // Missing nonce is rejected.
        assert!(rc
            .enforce_restore_pow("xmr", "addr", start, tip, None)
            .is_err());
        // A correctly-solved nonce is accepted.
        let nonce = (0u64..)
            .find(|&n| crate::core::restore_pow::verify("xmr", "addr", start, n, 8))
            .unwrap();
        assert!(rc
            .enforce_restore_pow("xmr", "addr", start, tip, Some(nonce))
            .is_ok());
        // A nonce that doesn't clear the bar is rejected.
        assert!(
            rc.enforce_restore_pow("xmr", "addr", start, tip, Some(nonce.wrapping_add(1)))
                .is_err()
                || crate::core::restore_pow::verify("xmr", "addr", start, nonce.wrapping_add(1), 8)
        );
    }

    #[test]
    fn positive_decimal_rules() {
        assert!(is_positive_decimal("0.01"));
        assert!(is_positive_decimal("1"));
        assert!(is_positive_decimal("10.5"));
        assert!(!is_positive_decimal("0")); // zero is not positive
        assert!(!is_positive_decimal("0.00")); // still zero
        assert!(!is_positive_decimal("")); // empty
        assert!(!is_positive_decimal("-1")); // sign not allowed
        assert!(!is_positive_decimal("1.2.3")); // two dots
        assert!(!is_positive_decimal("abc")); // non-numeric
        assert!(!is_positive_decimal("1e5")); // no scientific notation
    }

    #[test]
    fn payment_off_skips_provider_validation() {
        let mut c = valid();
        c.registration.payment.require_payment = false;
        c.registration.payment.provider = "nonsense".into(); // ignored when off
        assert!(c.validate().is_ok());
    }

    #[test]
    fn payment_required_with_full_config_passes() {
        let mut c = valid();
        c.registration.payment = valid_payment();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn payment_required_missing_wiring_rejected() {
        let mut c = valid();
        c.registration.payment.require_payment = true; // url/store/key/amount empty
        assert!(c.validate().is_err());
    }

    #[test]
    fn payment_rejects_unsupported_provider() {
        let mut c = valid();
        c.registration.payment = valid_payment();
        c.registration.payment.provider = "stripe".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn payment_rejects_nonpositive_amount() {
        let mut c = valid();
        c.registration.payment = valid_payment();
        c.registration.payment.amount = "0".into();
        assert!(c.validate().is_err());
    }

    fn valid_relay() -> RelayConfig {
        RelayConfig {
            enabled: true,
            mode: "bundled".into(),
            advertised_url: "wss://relay.example.org".into(),
            write_policy: "inbox-outbox".into(),
            inbound_pow_bits: 20,
            admission_bind: "127.0.0.1:8090".into(),
            admission_allow_public: false,
            max_event_bytes: 65536,
            retention_days: 30,
            write_allowlist: Vec::new(),
        }
    }

    #[test]
    fn relay_off_skips_validation() {
        let mut c = valid();
        c.messaging.relay.enabled = false;
        c.messaging.relay.write_policy = "nonsense".into(); // ignored when off
        assert!(c.validate().is_ok());
    }

    #[test]
    fn relay_enabled_full_config_passes() {
        let mut c = valid();
        c.messaging.relay = valid_relay();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn feed_requires_relay_enabled() {
        // FEED_ENABLED without the relay it reads from is a fail-closed misconfig.
        let mut c = valid();
        c.feed.enabled = true;
        assert!(c.validate().is_err());
        c.messaging.relay = valid_relay();
        assert!(c.validate().is_ok());
    }

    /// Fully-wired premium tier (free registration + paid premium) on top of the
    /// base valid() config: relay on with the premium-post policy, processor
    /// creds present, and priced plans.
    fn wire_premium(c: &mut Config) {
        c.messaging.relay = valid_relay();
        c.messaging.relay.write_policy = "premium-post".into();
        c.registration.payment = valid_payment();
        c.registration.payment.require_payment = false; // free to register; pay for premium
        c.premium.enabled = true;
        c.premium.currency = "XMR".into();
        c.premium.plans = vec![
            PremiumPlan {
                id: "quarter".into(),
                days: 90,
                amount: "5".into(),
            },
            PremiumPlan {
                id: "year".into(),
                days: 365,
                amount: "15".into(),
            },
        ];
    }

    #[test]
    fn loopback_url_detection() {
        assert!(is_loopback_url("http://127.0.0.1:8099"));
        assert!(is_loopback_url("http://localhost:8000"));
        assert!(is_loopback_url("http://[::1]:8099"));
        assert!(!is_loopback_url("http://pay.example.org"));
        assert!(!is_loopback_url("https://10.0.0.5"));
        assert!(!is_loopback_url("not a url"));
    }

    #[test]
    fn premium_off_skips_validation() {
        let c = valid(); // premium disabled by default
        assert!(c.validate().is_ok());
    }

    #[test]
    fn premium_plans_parse_drops_malformed() {
        // valid: quarter, year; dropped: "bad" (no fields), "x::5" (empty id),
        // "y:0:5" (non-positive days), "z:9:" (empty amount).
        let p = parse_premium_plans("quarter:90:5, year:365:15 ,bad, x::5, y:0:5, z:9:");
        assert_eq!(p.len(), 2);
        assert_eq!(
            (p[0].id.as_str(), p[0].days, p[0].amount.as_str()),
            ("quarter", 90, "5")
        );
        assert_eq!(p[1].id, "year");
        assert!(parse_premium_plans("").is_empty());
    }

    #[test]
    fn premium_enabled_full_config_passes() {
        let mut c = valid();
        wire_premium(&mut c);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn premium_requires_relay_and_premium_post_policy() {
        let mut c = valid();
        wire_premium(&mut c);
        c.messaging.relay.enabled = false; // premium needs the relay on
        assert!(c.validate().is_err());

        let mut c = valid();
        wire_premium(&mut c);
        c.messaging.relay.write_policy = "inbox-outbox".into(); // wrong policy
        assert!(c.validate().is_err());
    }

    #[test]
    fn premium_requires_plans_and_processor_creds() {
        let mut c = valid();
        wire_premium(&mut c);
        c.premium.plans.clear(); // no plans
        assert!(c.validate().is_err());

        let mut c = valid();
        wire_premium(&mut c);
        c.registration.payment.provider_url = String::new(); // missing processor creds
        assert!(c.validate().is_err());
    }

    #[test]
    fn premium_rejects_duplicate_plan_ids() {
        let mut c = valid();
        wire_premium(&mut c);
        c.premium.plans = vec![
            PremiumPlan {
                id: "dup".into(),
                days: 90,
                amount: "5".into(),
            },
            PremiumPlan {
                id: "dup".into(),
                days: 365,
                amount: "15".into(),
            },
        ];
        assert!(c.validate().is_err());
    }

    #[test]
    fn premium_rejects_zero_confirmations() {
        // 0-conf lets a settled premium payment be double-spent after activation;
        // the guard must hold on the premium path (require_payment is off here).
        let mut c = valid();
        wire_premium(&mut c);
        c.registration.payment.confirmations = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn premium_rejects_absurd_plan_days() {
        let mut c = valid();
        wire_premium(&mut c);
        c.premium.plans[0].days = 900_000_000; // would overflow premium_until math
        assert!(c.validate().is_err());
    }

    #[test]
    fn premium_rejects_non_decimal_plan_amount() {
        for bad in ["NaN", "inf", "1e5", "-1", "abc"] {
            let mut c = valid();
            wire_premium(&mut c);
            c.premium.plans[0].amount = bad.to_string();
            assert!(c.validate().is_err(), "amount {bad:?} must be rejected");
        }
    }

    #[test]
    fn relay_enabled_requires_url() {
        let mut c = valid();
        c.messaging.relay = valid_relay();
        c.messaging.relay.advertised_url = String::new();
        assert!(c.validate().is_err());
    }

    #[test]
    fn relay_rejects_non_ws_url() {
        let mut c = valid();
        c.messaging.relay = valid_relay();
        c.messaging.relay.advertised_url = "https://relay.example.org".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn relay_rejects_unknown_policy() {
        let mut c = valid();
        c.messaging.relay = valid_relay();
        c.messaging.relay.write_policy = "whitelist-only".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn relay_rejects_excessive_pow() {
        let mut c = valid();
        c.messaging.relay = valid_relay();
        c.messaging.relay.inbound_pow_bits = 64;
        assert!(c.validate().is_err());
    }

    #[test]
    fn relay_rejects_ws_in_production() {
        let mut c = valid();
        c.environment = "production".into();
        c.messaging.relay = valid_relay();
        c.messaging.relay.advertised_url = "ws://relay.example.org".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn relay_rejects_non_loopback_admission_bind() {
        let mut c = valid();
        c.messaging.relay = valid_relay();
        c.messaging.relay.admission_bind = "0.0.0.0:8090".into();
        assert!(
            c.validate().is_err(),
            "non-loopback admission bind rejected"
        );
        // …unless explicitly opted out.
        c.messaging.relay.admission_allow_public = true;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn payment_requires_https_provider_url_in_production() {
        let mut c = valid();
        c.environment = "production".into();
        c.registration.payment = valid_payment();
        c.registration.payment.provider_url = "http://pay.example.org".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn payment_rejects_zero_confirmations() {
        // 0-conf would let a settled payment be double-spent after registration.
        let mut c = valid();
        c.registration.payment = valid_payment();
        c.registration.payment.confirmations = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn payment_rejects_out_of_range_expiry() {
        let mut c = valid();
        c.registration.payment = valid_payment();
        c.registration.payment.expires_minutes = 0;
        assert!(c.validate().is_err(), "0 (never expires) rejected");
        c.registration.payment.expires_minutes = 100_000; // > 10080
        assert!(c.validate().is_err(), "beyond BTCPay's 7-day max rejected");
    }
}
