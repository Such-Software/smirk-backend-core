//! Infrastructure layer: adapters for external services (database, chain nodes,
//! light-wallet servers). Chain clients are wired in as they land.

pub mod chains;
pub mod db;
pub mod electrum;
pub mod grin;
pub mod lws;
pub mod prices;
