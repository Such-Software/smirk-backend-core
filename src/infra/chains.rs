//! Per-chain client handles, constructed once at startup and shared via
//! [`crate::AppState`]. Each chain's client is config-pointed at an external node
//! service (Fulcrum/Electrum, monero/wownero-lws, grin-wallet + grin node) and is
//! present only when that chain's feature flag is enabled. A malformed endpoint
//! fails startup (fail-closed), not the first request.

use std::sync::Arc;

use crate::config::Config;
use crate::error::AppError;
use crate::infra::electrum::ElectrumClient;
use crate::infra::grin::GrinClient;
use crate::infra::lws::LwsClient;

/// The enabled chains' data-source clients. Cloneable (the heavyweight grin
/// session state is shared via `Arc`) so it can live in the cloneable `AppState`.
#[derive(Clone)]
pub struct ChainClients {
    pub btc: Option<ElectrumClient>,
    pub ltc: Option<ElectrumClient>,
    pub xmr: Option<LwsClient>,
    pub wow: Option<LwsClient>,
    pub grin: Option<Arc<GrinClient>>,
}

impl ChainClients {
    /// Build clients for the enabled chains from config.
    pub fn from_config(cfg: &Config) -> Result<Self, AppError> {
        let flags = &cfg.features.chains;
        Ok(Self {
            btc: flags
                .btc
                .then(|| ElectrumClient::bitcoin(&cfg.chains.btc))
                .transpose()?,
            ltc: flags
                .ltc
                .then(|| ElectrumClient::litecoin(&cfg.chains.ltc))
                .transpose()?,
            xmr: flags
                .xmr
                .then(|| LwsClient::monero(&cfg.chains.xmr))
                .transpose()?,
            wow: flags
                .wow
                .then(|| LwsClient::wownero(&cfg.chains.wow))
                .transpose()?,
            grin: flags
                .grin
                .then(|| GrinClient::new(&cfg.chains.grin).map(Arc::new))
                .transpose()?,
        })
    }
}
