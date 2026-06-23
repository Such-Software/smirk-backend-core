//! Grin view-only API surface: open the operator's scan-engine wallet, run a
//! `rewind_hash` scan, read node tip/status, and broadcast a finalized tx.
//!
//! No spend method exists here by design — the backend holds no spend key; the
//! wallet builds and signs transactions locally and hands the backend only the
//! finalized transaction to broadcast.

use tracing::instrument;

use super::{GrinClient, GrinStatus, ViewWallet};
use crate::error::AppError;

impl GrinClient {
    /// Open the operator's scan-engine wallet and cache its session token.
    /// TOCTOU-free: re-checks the cache under the write lock. The wallet is used
    /// only as a scan engine — its own keys are irrelevant to view-only scans.
    #[instrument(skip(self))]
    pub async fn open_wallet(&self) -> Result<String, AppError> {
        if let Some(token) = self.session_token.read().await.as_ref() {
            return Ok(token.clone());
        }
        let mut guard = self.session_token.write().await;
        if let Some(token) = guard.as_ref() {
            return Ok(token.clone());
        }
        // open_wallet params: (name: Option<String>, password).
        let token: String = self
            .owner_rpc(
                "open_wallet",
                (Option::<String>::None, self.wallet_password.expose()),
            )
            .await?;
        *guard = Some(token.clone());
        Ok(token)
    }

    /// View-only scan for the outputs a `rewind_hash` recognizes, from
    /// `start_height` (a wallet birthday or the last scanned height). Returns the
    /// outputs, total balance, and `last_pmmr_index` for the next incremental scan.
    /// Cannot spend — `rewind_hash` is derived from a public key.
    #[instrument(skip(self, rewind_hash))]
    pub async fn scan_rewind_hash(
        &self,
        rewind_hash: &str,
        start_height: Option<u64>,
    ) -> Result<ViewWallet, AppError> {
        match self.scan_attempt(rewind_hash, start_height).await {
            Ok(view) => Ok(view),
            Err(_) => {
                // The cached wallet token may be stale (e.g. grin-wallet was
                // restarted: the owner_rpc -32001 path re-handshakes the secure
                // channel but the old token no longer opens the wallet). Drop it
                // and retry once with a fresh open_wallet, so a wallet restart
                // self-heals instead of wedging scans until our own restart.
                *self.session_token.write().await = None;
                self.scan_attempt(rewind_hash, start_height).await
            }
        }
    }

    async fn scan_attempt(
        &self,
        rewind_hash: &str,
        start_height: Option<u64>,
    ) -> Result<ViewWallet, AppError> {
        let token = self.open_wallet().await?;
        // scan_rewind_hash params: (token, rewind_hash, start_height).
        self.owner_rpc("scan_rewind_hash", (token, rewind_hash, start_height))
            .await
    }

    /// Node status (chain tip height + sync status).
    #[instrument(skip(self))]
    pub async fn get_status(&self) -> Result<GrinStatus, AppError> {
        self.node_rpc(
            &self.node_api_url,
            Some((self.node_api_user.as_str(), self.node_api_pass.expose())),
            "get_status",
            Vec::<()>::new(),
        )
        .await
    }

    /// Current chain tip height.
    pub async fn get_height(&self) -> Result<u64, AppError> {
        Ok(self.get_status().await?.tip.height)
    }

    /// Broadcast a finalized transaction via the node Foreign API
    /// (`push_transaction`). The wallet builds + signs locally; the backend only
    /// relays. `tx` is the finalized transaction object.
    #[instrument(skip(self, tx))]
    pub async fn broadcast(&self, tx: &serde_json::Value) -> Result<(), AppError> {
        let auth = if self.node_foreign_api_secret.is_empty() {
            None
        } else {
            Some(("grin", self.node_foreign_api_secret.expose()))
        };
        // push_transaction params: (tx, fluff).
        let _: serde_json::Value = self
            .node_rpc(
                &self.node_foreign_api_url,
                auth,
                "push_transaction",
                (tx, false),
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GrinConfig;
    use crate::infra::grin::ViewWalletOutputResult;

    fn cfg() -> GrinConfig {
        GrinConfig {
            owner_api_url: "http://127.0.0.1:3420/v3/owner".into(),
            owner_api_secret: "owner-secret".into(),
            wallet_password: "wallet-pass".into(),
            foreign_api_url: String::new(),
            node_api_url: "http://127.0.0.1:3413/v2/owner".into(),
            node_api_user: "grin".into(),
            node_api_pass: "node-pass".into(),
            node_foreign_api_url: "http://127.0.0.1:3413/v2/foreign".into(),
            node_foreign_api_secret: String::new(),
        }
    }

    #[test]
    fn new_builds_without_io() {
        assert!(GrinClient::new(&cfg()).is_ok());
    }

    #[test]
    fn confirmations_handles_tip_zero_and_future() {
        let out = |height| ViewWalletOutputResult {
            commit: "c".into(),
            value: 1,
            height,
            mmr_index: 0,
            is_coinbase: false,
            lock_height: 0,
        };
        assert_eq!(out(100).confirmations(110), 11); // 110 - 100 + 1
        assert_eq!(out(110).confirmations(110), 1); // tip block
        assert_eq!(out(0).confirmations(110), 0); // unconfirmed / no height
        assert_eq!(out(120).confirmations(110), 0); // beyond tip -> not a bogus count
    }
}
