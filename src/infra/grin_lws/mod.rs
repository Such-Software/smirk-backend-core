//! grin-lws (Grin light-wallet-server) client.
//!
//! An optional add-on to the view-only Grin path. When configured, the backend's
//! Grin scan proxies to grin-lws — which scans the chain for registered
//! `rewind_hash` view credentials — and trusts its result only when it is
//! provably synced to the tip, otherwise falling back to the authoritative
//! grin-wallet scan. A hardened client of that service (config-pointed, timeout-
//! and size-bounded, secret-redacting), mirroring [`crate::infra::lws`].

mod client;
mod types;

pub use client::GrinLwsClient;
pub use types::{GrinLwsBalance, GrinLwsRegister, GrinLwsUnspentOut, GrinLwsUnspentOuts};
