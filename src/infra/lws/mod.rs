//! Light-wallet-server (LWS) client for Monero/Wownero.
//!
//! The backend holds no spend key and runs no wallet. An LWS scans the chain
//! for registered view keys and answers balance / history / output / broadcast
//! queries; this module is a hardened client of that service (config-pointed,
//! timeout- and size-bounded, secret-redacting). Monero and Wownero share the
//! API, so one [`LwsClient`] serves both via [`CryptoNoteNetwork`].

mod client;
mod types;

pub(crate) use client::sum_mempool_received;
pub use client::LwsClient;
pub use types::{
    AccountEntry, AccountStatus, AddressInfo, AddressTx, AddressTxsResponse, AmountOuts,
    CryptoNoteNetwork, ListAccountsResponse, RandomOutput, RandomOutsResponse, SpentOutput,
    UnspentOutput, UnspentOutsResponse,
};
