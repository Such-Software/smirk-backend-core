//! Fundless restore regressions against a local, stateful LWS double.
use std::sync::{Arc, Mutex};

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde_json::{json, Value};
use smirk_backend_core::{config::LwsConfig, infra::lws::LwsClient};

const ADDRESS: &str = "test-wallet-address";
const VIEW_KEY: &str = "test-view-key";

#[derive(Default)]
struct Account {
    present: bool,
    start: u64,
    scanned: u64,
    failures: usize,
    lost_ack: bool,
    omit_range: bool,
    rescans: Vec<u64>,
}

type Shared = Arc<Mutex<Account>>;

async fn accounts(State(state): State<Shared>) -> Json<Value> {
    let account = state.lock().unwrap();
    Json(json!({"active": if account.present {
        vec![json!({"address": ADDRESS, "scan_height": account.scanned})]
    } else { vec![] }}))
}

async fn add(State(state): State<Shared>) -> Json<Value> {
    let mut account = state.lock().unwrap();
    account.present = true;
    account.start = 600;
    account.scanned = 600;
    Json(json!({"updated": [ADDRESS]}))
}

async fn info(State(state): State<Shared>) -> Json<Value> {
    let account = state.lock().unwrap();
    Json(if account.omit_range {
        json!({})
    } else {
        json!({"start_height": account.start, "scanned_height": account.scanned})
    })
}

async fn rescan(State(state): State<Shared>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let mut account = state.lock().unwrap();
    let height = body["params"]["height"].as_u64().unwrap();
    assert!(
        height < account.scanned,
        "rescan must lower the current cursor"
    );
    account.rescans.push(height);
    if account.failures > 0 {
        account.failures -= 1;
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({})));
    }
    account.start = account.start.min(height);
    account.scanned = height;
    let status = if account.lost_ack {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    (status, Json(json!({"updated": [ADDRESS]})))
}

struct Harness {
    state: Shared,
    cfg: LwsConfig,
    server: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn new(account: Account) -> Self {
        let state = Arc::new(Mutex::new(account));
        let router = Router::new()
            .route("/list_accounts", post(accounts))
            .route("/add_account", post(add))
            .route("/get_address_info", post(info))
            .route("/rescan", post(rescan))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            state,
            cfg: LwsConfig {
                lws_url: url.clone(),
                lws_admin_url: url,
                lws_admin_key: "test-admin-key".into(),
                daemon_url: String::new(),
            },
            server,
        }
    }
    fn client(&self) -> LwsClient {
        LwsClient::monero(&self.cfg).unwrap()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[tokio::test]
async fn failed_initial_backfill_can_resume_after_backend_restart() {
    let h = Harness::new(Account {
        failures: 3,
        ..Account::default()
    })
    .await;
    assert!(h
        .client()
        .import_account(ADDRESS, VIEW_KEY, 100, 0)
        .await
        .is_err());
    assert!(h.state.lock().unwrap().present);
    assert_eq!(h.state.lock().unwrap().start, 600);
    // A fresh client has no process-local memory of the failed add/rescan pair.
    h.client()
        .import_account(ADDRESS, VIEW_KEY, 100, 0)
        .await
        .unwrap();
    assert_eq!(h.state.lock().unwrap().start, 100);
    let rescans = h.state.lock().unwrap().rescans.clone();
    h.state.lock().unwrap().scanned = 550;
    h.client()
        .import_account(ADDRESS, VIEW_KEY, 100, 0)
        .await
        .unwrap();
    let account = h.state.lock().unwrap();
    assert_eq!(
        account.scanned, 550,
        "routine re-registration retains progress"
    );
    assert_eq!(
        account.rescans, rescans,
        "completed backfills are not replayed"
    );
}

#[tokio::test]
async fn lost_rescan_response_is_reconciled_before_retrying() {
    let h = Harness::new(Account {
        lost_ack: true,
        ..Account::default()
    })
    .await;
    h.client()
        .import_account(ADDRESS, VIEW_KEY, 100, 0)
        .await
        .unwrap();
    let account = h.state.lock().unwrap();
    assert_eq!(account.start, 100);
    assert_eq!(
        account.rescans,
        vec![100],
        "uncertain success must not reset progress twice"
    );
}

#[tokio::test]
async fn missing_range_is_unknown_and_cannot_authorize_a_rescan() {
    let h = Harness::new(Account {
        present: true,
        start: 600,
        scanned: 600,
        omit_range: true,
        ..Account::default()
    })
    .await;
    assert!(h
        .client()
        .import_account(ADDRESS, VIEW_KEY, 100, 0)
        .await
        .is_err());
    assert!(h.state.lock().unwrap().rescans.is_empty());
}

#[tokio::test]
async fn already_covered_restore_never_moves_the_cursor_forward() {
    let h = Harness::new(Account {
        present: true,
        start: 50,
        scanned: 75,
        ..Account::default()
    })
    .await;
    h.client()
        .import_account(ADDRESS, VIEW_KEY, 100, 0)
        .await
        .unwrap();
    let account = h.state.lock().unwrap();
    assert_eq!(account.scanned, 75);
    assert!(account.rescans.is_empty());
}
