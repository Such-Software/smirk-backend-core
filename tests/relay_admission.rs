//! L1 integration: the relay event-admission (nauthz) gRPC handler.
//!
//! Drives `AdmissionService::event_admit` directly (no gRPC transport — that is
//! covered by the docker-relay E2E) to prove the handler wiring: p-tag
//! extraction, the DB registration lookup, and the policy decision, end to end
//! against live Postgres. The pure policy branches are covered in unit tests.

mod common;

use smirk_backend_core::infra::relay::nauthz::proto::authorization_server::Authorization;
use smirk_backend_core::infra::relay::nauthz::{proto, AdmissionService};
use smirk_backend_core::infra::relay::{self, RelayProvider};
use smirk_backend_core::models::db::NewUser;
use std::sync::Arc;
use tonic::Request;

/// A 64-char lowercase-hex pubkey/id (valid for hex::decode).
fn hex64(seed: &str) -> String {
    let base = format!("{seed}{}", "0".repeat(64));
    base[..64].to_string()
}

async fn register_npub(db: &smirk_backend_core::infra::db::Database, npub_hex: &str) {
    db.create_user(NewUser {
        username: None,
        pubkey_hash: Some(format!("pk-{}", uuid::Uuid::new_v4())),
        nostr_pubkey: Some(npub_hex.to_string()),
        wallet_birthday: None,
        seed_fingerprint: None,
        xmr_start_height: None,
        wow_start_height: None,
    })
    .await
    .unwrap();
}

fn inbox_outbox_relay(base: &smirk_backend_core::config::Config) -> Arc<dyn RelayProvider> {
    let mut cfg = base.clone();
    cfg.messaging.relay.enabled = true;
    cfg.messaging.relay.write_policy = "inbox-outbox".into();
    cfg.messaging.relay.advertised_url = "wss://relay.example.org".into();
    cfg.messaging.relay.inbound_pow_bits = 0;
    relay::from_config(&cfg).unwrap().unwrap()
}

fn event(author_hex: &str, kind: u64, p_tags: &[&str], id_hex: &str) -> proto::EventRequest {
    proto::EventRequest {
        event: Some(proto::Event {
            id: hex::decode(id_hex).unwrap(),
            pubkey: hex::decode(author_hex).unwrap(),
            created_at: 0,
            kind,
            content: String::new(),
            tags: p_tags
                .iter()
                .map(|p| proto::TagEntry {
                    values: vec!["p".to_string(), (*p).to_string()],
                })
                .collect(),
            sig: vec![],
        }),
        ip_addr: None,
        origin: None,
        user_agent: None,
        auth_pubkey: None,
        nip05: None,
    }
}

async fn admit(svc: &AdmissionService, req: proto::EventRequest) -> bool {
    let reply = svc
        .event_admit(Request::new(req))
        .await
        .unwrap()
        .into_inner();
    reply.decision == proto::Decision::Permit as i32
}

#[tokio::test]
async fn is_registered_npub_membership() {
    let app = require_app!();
    let npub = hex64("aaaa");
    assert!(!app.state.db.is_registered_npub(&npub).await.unwrap());
    register_npub(&app.state.db, &npub).await;
    assert!(app.state.db.is_registered_npub(&npub).await.unwrap());
}

#[tokio::test]
async fn admission_inbox_outbox_end_to_end() {
    let app = require_app!();
    let svc = AdmissionService::new(inbox_outbox_relay(&app.state.cfg()), app.state.db.clone());

    let author = hex64("b1"); // registered author (outbox)
    let recipient = hex64("b2"); // registered recipient (inbox)
    let stranger = hex64("b3"); // unregistered
    register_npub(&app.state.db, &author).await;
    register_npub(&app.state.db, &recipient).await;
    let ff = "ff".repeat(32);

    // Outbox: a registered author's own event → PERMIT.
    assert!(
        admit(&svc, event(&author, 1, &[], &ff)).await,
        "registered author outbox"
    );

    // Inbox: an unregistered author's gift-wrap (1059) to a registered recipient → PERMIT.
    assert!(
        admit(&svc, event(&stranger, 1059, &[&recipient], &ff)).await,
        "gift-wrap to registered recipient"
    );

    // External non-gift-wrap → DENY.
    assert!(
        !admit(&svc, event(&stranger, 1, &[&recipient], &ff)).await,
        "external non-gift-wrap rejected"
    );

    // Gift-wrap to an UNREGISTERED recipient → DENY.
    assert!(
        !admit(&svc, event(&stranger, 1059, &[&hex64("b9")], &ff)).await,
        "gift-wrap to unregistered recipient rejected"
    );
}
