//! gRPC event-admission service — the `nostr-rs-relay` `nauthz` hook.
//!
//! `nostr-rs-relay` (configured with `[grpc] event_admission_server`) calls
//! `Authorization.EventAdmit` once per inbound event, before storing it. We
//! resolve the author + recipient registration against the DB and run the pure
//! [`super::policy`] engine, returning PERMIT/DENY. This is the adapter-specific
//! transport for the write policy; a different relay backend could enforce the
//! same policy over a different mechanism.
//!
//! Runs on a loopback socket (like the admin plane); never exposed publicly.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::infra::db::Database;

use super::{decide, Admit, EventMeta, RelayProvider};

/// Generated from `proto/nauthz.proto` (see `build.rs`).
pub mod proto {
    tonic::include_proto!("nauthz");
}

use proto::authorization_server::{Authorization, AuthorizationServer};
use proto::{Decision, EventReply, EventRequest};

/// The admission decider: the configured relay policy + the user DB.
pub struct AdmissionService {
    relay: Arc<dyn RelayProvider>,
    db: Database,
}

impl AdmissionService {
    pub fn new(relay: Arc<dyn RelayProvider>, db: Database) -> Self {
        Self { relay, db }
    }
}

fn permit() -> EventReply {
    EventReply {
        decision: Decision::Permit as i32,
        message: None,
    }
}

fn deny(msg: &str) -> EventReply {
    EventReply {
        decision: Decision::Deny as i32,
        message: Some(msg.to_string()),
    }
}

#[tonic::async_trait]
impl Authorization for AdmissionService {
    async fn event_admit(
        &self,
        request: Request<EventRequest>,
    ) -> Result<Response<EventReply>, Status> {
        let req = request.into_inner();
        let Some(event) = req.event else {
            // Fail closed on a malformed request.
            return Ok(Response::new(deny("missing event")));
        };

        // Canonical lowercase hex (matches how we store/verify npubs).
        let author_hex = hex::encode(&event.pubkey);
        let id_hex = hex::encode(&event.id);

        // Author registration.
        let author_registered = self
            .db
            .is_registered_npub(&author_hex)
            .await
            .unwrap_or(false);

        // Recipient registration: any `p` tag that is a registered npub. Only
        // resolved when needed (skipped once the author is already registered).
        let mut recipient_registered = false;
        if !author_registered {
            for tag in &event.tags {
                if tag.values.len() >= 2 && tag.values[0] == "p" {
                    let p = tag.values[1].to_lowercase();
                    if self.db.is_registered_npub(&p).await.unwrap_or(false) {
                        recipient_registered = true;
                        break;
                    }
                }
            }
        }

        let meta = EventMeta {
            author_pubkey: &author_hex,
            kind: event.kind,
            id_hex: &id_hex,
        };
        let reply = match decide(
            &meta,
            self.relay.write_policy(),
            self.relay.inbound_pow_bits(),
            author_registered,
            recipient_registered,
        ) {
            Admit::Permit => permit(),
            Admit::Deny(msg) => deny(msg),
        };
        Ok(Response::new(reply))
    }
}

/// Serve the admission service on `addr` (a loopback socket). Returns when the
/// server stops or errors.
pub async fn serve(
    addr: std::net::SocketAddr,
    relay: Arc<dyn RelayProvider>,
    db: Database,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let svc = AdmissionService { relay, db };
    tonic::transport::Server::builder()
        .add_service(AuthorizationServer::new(svc))
        .serve(addr)
        .await?;
    Ok(())
}
