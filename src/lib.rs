//! smirk-backend-core
//!
//! Open, self-hostable backend for the Smirk non-custodial multi-chain wallet:
//! authentication, per-chain wallet access (Bitcoin, Litecoin, Monero, Wownero,
//! Grin), the Grin slatepack relay, and Nostr-based identity.
//!
//! The HTTP contract is generated from the handlers (`utoipa`) into
//! `openapi.json`, which is the single source of truth for the API and the
//! wallet's generated TypeScript client.

pub mod api;
pub mod config;
pub mod error;
pub mod models;
