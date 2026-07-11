//! Public social-tips route tests (Stage 2: create / get-public / get-sent /
//! cancel). Self-skips when `TEST_DATABASE_URL` is unset (see `tests/common`).

mod common;

use axum::http::StatusCode;
use serde_json::json;

/// Boot the app with tips ENABLED + a share base configured (BTC is on by
/// default in the test config). Returns None (skip) when no test DB.
async fn tips_app() -> Option<common::TestApp> {
    common::try_app_with(|c| {
        c.features.tips = true;
        c.tip_share_base = Some("https://tips.example".into());
    })
    .await
}

/// A valid SHA256 hash shape: exactly 64 hex chars (4 × 16).
const CLAIM_HASH: &str = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const ENC_KEY_HEX: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const BTC_ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

fn draft_body() -> serde_json::Value {
    json!({
        "asset": "btc",
        "amount": 100_000,
        "is_public": true,
        "claim_key_hash": CLAIM_HASH,
        "encrypted_key": ENC_KEY_HEX,
        "tip_address": BTC_ADDR,
    })
}

#[tokio::test]
async fn public_tip_draft_create_get_cancel_flow() {
    let Some(app) = tips_app().await else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let (_uid, token, _refresh) = app.mint_session().await;

    // 1. Create a draft (no funding_txid) -> draft + share_url.
    let (status, body) = app
        .request("POST", "/api/v1/tips/social", Some(&token), Some(draft_body()))
        .await;
    assert_eq!(status, StatusCode::OK, "create: {body}");
    assert_eq!(body["status"], "draft");
    let tip_id = body["tip_id"].as_str().expect("tip_id").to_string();
    assert_eq!(body["share_url"], format!("https://tips.example/{tip_id}"));

    // 2. Public read (UNAUTH) surfaces it and is not yet claimable.
    let (status, pub_body) = app
        .request("GET", &format!("/api/v1/tips/social/{tip_id}/public"), None, None)
        .await;
    assert_eq!(status, StatusCode::OK, "get_public: {pub_body}");
    assert_eq!(pub_body["is_public"], true);
    assert_eq!(pub_body["is_claimable"], false);
    assert_eq!(pub_body["encrypted_key"], ENC_KEY_HEX);
    assert_eq!(pub_body["tip_address"], BTC_ADDR);

    // 3. Unknown id -> 404 (not 200-with-nulls).
    let (status, _) = app
        .request(
            "GET",
            "/api/v1/tips/social/00000000-0000-0000-0000-000000000000/public",
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // 4. Cancel the draft (owner) -> {ok:true}.
    let (status, cancel_body) = app
        .request("POST", &format!("/api/v1/tips/social/{tip_id}/cancel"), Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK, "cancel: {cancel_body}");
    assert_eq!(cancel_body["ok"], true);

    // 5. Cancelling again -> 404 (no longer a draft).
    let (status, _) = app
        .request("POST", &format!("/api/v1/tips/social/{tip_id}/cancel"), Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // 6. Sent list shows the tip as cancelled.
    let (status, sent) = app
        .request("GET", "/api/v1/tips/social/sent", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK, "sent: {sent}");
    let tips = sent["tips"].as_array().expect("tips array");
    let found = tips.iter().find(|t| t["id"] == tip_id).expect("tip in sent list");
    assert_eq!(found["status"], "cancelled");
    assert_eq!(found["is_public"], true);
}

#[tokio::test]
async fn db_create_draft_roundtrips_all_columns() {
    let Some(app) = tips_app().await else { return };
    let uid = app.create_user().await;
    use smirk_backend_core::infra::db::NewSocialTip;
    let enc = hex::decode("cdcd").unwrap();
    let new = NewSocialTip {
        sender_user_id: uid,
        asset: "btc",
        amount: 100_000,
        claim_key_hash: Some(CLAIM_HASH),
        encrypted_key: Some(&enc),
        tip_address: Some(BTC_ADDR),
        funding_txid: None,
        tip_view_key: None,
        confirmations_required: 0,
        grin_commitment: None,
    };
    // Exercises the full 32-column FromRow decode on RETURNING.
    let row = app.state.db.create_draft_social_tip(new).await.expect("create draft");
    assert_eq!(row.status, "draft");
    assert_eq!(row.amount, 100_000);
    assert!(row.is_public);
    assert_eq!(row.encrypted_key.as_deref(), Some(&[0xcd, 0xcd][..]));
    assert_eq!(row.grin_commitment, None);
}

#[tokio::test]
async fn targeted_tip_is_rejected() {
    let Some(app) = tips_app().await else { return };
    let (_uid, token, _r) = app.mint_session().await;
    let (status, body) = app
        .request(
            "POST",
            "/api/v1/tips/social",
            Some(&token),
            Some(json!({
                "asset": "btc", "amount": 100, "is_public": false,
                "platform": "telegram", "username": "bob",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "targeted must be rejected: {body}");
}

#[tokio::test]
async fn create_requires_positive_amount_and_claim_hash() {
    let Some(app) = tips_app().await else { return };
    let (_uid, token, _r) = app.mint_session().await;

    // Non-positive amount.
    let mut b = draft_body();
    b["amount"] = json!(0);
    let (status, _) = app.request("POST", "/api/v1/tips/social", Some(&token), Some(b)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Missing claim_key_hash on a public tip.
    let mut b = draft_body();
    b.as_object_mut().unwrap().remove("claim_key_hash");
    let (status, _) = app.request("POST", "/api/v1/tips/social", Some(&token), Some(b)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tips_disabled_returns_400() {
    // Default config: FEATURE_TIPS off.
    let Some(app) = common::try_app().await else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let (_uid, token, _r) = app.mint_session().await;
    let (status, _) = app
        .request("POST", "/api/v1/tips/social", Some(&token), Some(draft_body()))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "tips off must 400");
}

// ── Stage 3: money-in (attach-funding + funding verifier) DB-level tests ──────

use smirk_backend_core::error::AppError;
use smirk_backend_core::infra::db::NewSocialTip;

/// Create a draft tip for `uid` and return its id. `conf` = confirmations_required.
async fn make_draft(
    app: &common::TestApp,
    uid: uuid::Uuid,
    asset: &str,
    amount: i64,
    conf: i32,
    view_key: Option<&str>,
) -> uuid::Uuid {
    let new = NewSocialTip {
        sender_user_id: uid,
        asset,
        amount,
        claim_key_hash: Some(CLAIM_HASH),
        encrypted_key: None,
        tip_address: Some(BTC_ADDR),
        funding_txid: None,
        tip_view_key: view_key,
        confirmations_required: conf,
        grin_commitment: None,
    };
    app.state
        .db
        .create_draft_social_tip(new)
        .await
        .expect("create draft")
        .id
}

#[tokio::test]
async fn attach_funding_is_idempotent_and_advances_draft() {
    let Some(app) = tips_app().await else { return };
    let uid = app.create_user().await;
    let tip_id = make_draft(&app, uid, "btc", 100_000, 0, None).await;

    // First attach: draft -> pending_confirmation, funding_txid recorded.
    let r1 = app
        .state
        .db
        .attach_funding_to_tip(tip_id, uid, "txid-aaa")
        .await
        .expect("attach");
    assert_eq!(r1.id, tip_id);
    assert_eq!(r1.status, "pending_confirmation");
    assert_eq!(r1.funding_txid.as_deref(), Some("txid-aaa"));
    assert!(!r1.funding_amount_verified);

    // Second attach, SAME txid: idempotent no-op returning the same row.
    let r2 = app
        .state
        .db
        .attach_funding_to_tip(tip_id, uid, "txid-aaa")
        .await
        .expect("attach idempotent");
    assert_eq!(r2.id, tip_id);
    assert_eq!(r2.status, "pending_confirmation");
    assert_eq!(r2.funding_txid.as_deref(), Some("txid-aaa"));
}

#[tokio::test]
async fn attach_funding_conflicting_txid_is_validation_error() {
    let Some(app) = tips_app().await else { return };
    let uid = app.create_user().await;
    let tip_id = make_draft(&app, uid, "btc", 100_000, 0, None).await;
    app.state
        .db
        .attach_funding_to_tip(tip_id, uid, "txid-first")
        .await
        .expect("attach");

    // A DIFFERENT txid on the same tip -> ValidationError (400).
    let err = app
        .state
        .db
        .attach_funding_to_tip(tip_id, uid, "txid-DIFFERENT")
        .await
        .unwrap_err();
    assert!(matches!(err, AppError::ValidationError(_)), "expected ValidationError, got {err:?}");

    // Not-owned / unknown tip -> NotFound (404).
    let other = app.create_user().await;
    let err = app
        .state
        .db
        .attach_funding_to_tip(tip_id, other, "txid-x")
        .await
        .unwrap_err();
    assert!(matches!(err, AppError::NotFound(_)), "expected NotFound, got {err:?}");
}

#[tokio::test]
async fn mark_verified_only_from_pending_confirmation() {
    let Some(app) = tips_app().await else { return };
    let uid = app.create_user().await;

    // A draft is NOT pending_confirmation -> mark returns None (guard misses).
    let draft_id = make_draft(&app, uid, "btc", 100_000, 0, None).await;
    let none = app
        .state
        .db
        .mark_tip_funding_verified(draft_id, 100_000)
        .await
        .expect("mark on draft");
    assert!(none.is_none(), "mark_verified on a draft must return None");

    // Attach -> pending_confirmation; verify flips it to pending + records observed.
    app.state
        .db
        .attach_funding_to_tip(draft_id, uid, "txid-v")
        .await
        .expect("attach");
    let verified = app
        .state
        .db
        .mark_tip_funding_verified(draft_id, 250_000)
        .await
        .expect("verify")
        .expect("verify returns row");
    assert_eq!(verified.status, "pending");
    assert!(verified.funding_amount_verified);
    assert_eq!(verified.funding_amount_observed, Some(250_000));

    // Re-verify -> None (funding_amount_verified guard no longer matches).
    let again = app
        .state
        .db
        .mark_tip_funding_verified(draft_id, 250_000)
        .await
        .expect("verify idempotent");
    assert!(again.is_none(), "re-verify must return None");
}

#[tokio::test]
async fn mark_mismatch_transitions_to_funding_mismatch() {
    let Some(app) = tips_app().await else { return };
    let uid = app.create_user().await;
    let tip_id = make_draft(&app, uid, "btc", 1_000_000, 0, None).await;
    app.state
        .db
        .attach_funding_to_tip(tip_id, uid, "txid-m")
        .await
        .expect("attach");

    let mismatch = app
        .state
        .db
        .mark_tip_funding_mismatch(tip_id, 10)
        .await
        .expect("mismatch")
        .expect("mismatch returns row");
    assert_eq!(mismatch.status, "funding_mismatch");
    assert!(mismatch.funding_amount_verified);
    assert_eq!(mismatch.funding_amount_observed, Some(10));

    // Idempotent, and a funding_mismatch row can never be flipped claimable.
    let again = app
        .state
        .db
        .mark_tip_funding_mismatch(tip_id, 10)
        .await
        .expect("mismatch idempotent");
    assert!(again.is_none());
    let verify_after = app
        .state
        .db
        .mark_tip_funding_verified(tip_id, 10)
        .await
        .expect("verify after mismatch");
    assert!(verify_after.is_none(), "a funding_mismatch row must not become claimable");
}

#[tokio::test]
async fn get_tips_pending_confirmation_filters() {
    let Some(app) = tips_app().await else { return };
    // Deterministic: this is the only test that creates xmr rows. Clear leftovers
    // so the query's LIMIT 50 / ORDER BY created_at window can't hide our row.
    sqlx::query("DELETE FROM social_tips WHERE asset = 'xmr'")
        .execute(app.state.db.pool())
        .await
        .expect("clear xmr rows");

    let uid = app.create_user().await;
    let vk = "0".repeat(64);

    // XMR tip: threshold 10 + funding attached -> INCLUDED.
    let xmr_id = make_draft(&app, uid, "xmr", 500, 10, Some(vk.as_str())).await;
    app.state
        .db
        .attach_funding_to_tip(xmr_id, uid, "xmrtxid")
        .await
        .expect("attach xmr");

    // XMR draft with NO funding -> EXCLUDED (funding_txid IS NULL, status draft).
    let xmr_draft = make_draft(&app, uid, "xmr", 500, 10, Some(vk.as_str())).await;

    // BTC tip: threshold 0 -> EXCLUDED (confirmations_required > 0 guard).
    let btc_id = make_draft(&app, uid, "btc", 100_000, 0, None).await;
    app.state
        .db
        .attach_funding_to_tip(btc_id, uid, "btctxid")
        .await
        .expect("attach btc");

    let xmr_pending = app
        .state
        .db
        .get_tips_pending_confirmation("xmr")
        .await
        .expect("xmr pending");
    assert!(xmr_pending.iter().any(|t| t.id == xmr_id), "funded xmr tip must be returned");
    assert!(
        !xmr_pending.iter().any(|t| t.id == xmr_draft),
        "unfunded xmr draft must be excluded"
    );

    let btc_pending = app
        .state
        .db
        .get_tips_pending_confirmation("btc")
        .await
        .expect("btc pending");
    assert!(
        !btc_pending.iter().any(|t| t.id == btc_id),
        "btc tip (threshold 0) must be excluded from the confirmation query"
    );
}

// ── Stage 4: money-out (claim / confirm-sweep / clawback + reconciler) DB tests ──
//
// Exercises the audited money-safety guards directly on the DB layer. BTC tips
// (confirmations_required = 0) manufacture a claimable row with no chain access.

/// Manufacture a claimable (pending, amount-verified) BTC tip owned by `uid`.
async fn make_pending(app: &common::TestApp, uid: uuid::Uuid, txid: &str) -> uuid::Uuid {
    let id = make_draft(app, uid, "btc", 100_000, 0, None).await;
    app.state
        .db
        .attach_funding_to_tip(id, uid, txid)
        .await
        .expect("attach funding");
    let row = app
        .state
        .db
        .mark_tip_funding_verified(id, 100_000)
        .await
        .expect("verify")
        .expect("verify returns row");
    assert_eq!(row.status, "pending", "make_pending must land in 'pending'");
    id
}

/// Manufacture a `claiming` tip (pending -> claiming) locked by `claimant`.
async fn make_claiming(
    app: &common::TestApp,
    uid: uuid::Uuid,
    claimant: uuid::Uuid,
    txid: &str,
) -> uuid::Uuid {
    let id = make_pending(app, uid, txid).await;
    let row = app
        .state
        .db
        .mark_tip_claiming(id, claimant)
        .await
        .expect("claim")
        .expect("claiming row");
    assert_eq!(row.status, "claiming");
    id
}

/// Manufacture a settled `claimed` tip (with a sweep_block_height witness).
async fn make_claimed(
    app: &common::TestApp,
    uid: uuid::Uuid,
    claimant: uuid::Uuid,
    txid: &str,
) -> uuid::Uuid {
    let id = make_claiming(app, uid, claimant, txid).await;
    let row = app
        .state
        .db
        .confirm_sweep_onchain(id, "onchain-swp", 100, None, None)
        .await
        .expect("settle")
        .expect("claimed row");
    assert_eq!(row.status, "claimed");
    id
}

/// (a) THE DOUBLE-CLAIM GUARD: a fresh claimable tip claims once; a
/// funding_mismatch / unverified / clawed_back / already-swept row is never
/// claimable. Re-claiming a `claiming` row IS intentionally allowed (verbatim
/// `status IN ('pending','claiming')` — public-tip retry semantics).
#[tokio::test]
async fn mark_tip_claiming_double_claim_guard() {
    let Some(app) = tips_app().await else { return };
    let sender = app.create_user().await;
    let claimant = app.create_user().await;

    // Fresh claimable tip: first claim locks it into 'claiming'.
    let id = make_pending(&app, sender, "fund-claim-1").await;
    let first = app.state.db.mark_tip_claiming(id, claimant).await.expect("claim");
    assert!(first.is_some(), "first claim on a pending tip must succeed");
    assert_eq!(first.unwrap().status, "claiming");

    // Re-claim on a 'claiming' public tip is INTENTIONALLY allowed: the claim
    // state is a UX signal, not a lock — the reconciler resolves the on-chain
    // sweep-race winner. (Verbatim audit-T1 retry semantics.)
    let reclaim = app.state.db.mark_tip_claiming(id, claimant).await.expect("reclaim");
    assert!(reclaim.is_some(), "re-claim on a claiming public tip is allowed");

    // None on funding_mismatch (audit-T1 fund-loss guard).
    let mm = make_draft(&app, sender, "btc", 1_000_000, 0, None).await;
    app.state.db.attach_funding_to_tip(mm, sender, "fund-mm").await.expect("attach");
    app.state.db.mark_tip_funding_mismatch(mm, 10).await.expect("mismatch").expect("row");
    assert!(
        app.state.db.mark_tip_claiming(mm, claimant).await.expect("claim mm").is_none(),
        "a funding_mismatch tip must never be claimable"
    );

    // None on an unverified (pending_confirmation) tip.
    let pc = make_draft(&app, sender, "btc", 100_000, 0, None).await;
    app.state.db.attach_funding_to_tip(pc, sender, "fund-pc").await.expect("attach");
    assert!(
        app.state.db.mark_tip_claiming(pc, claimant).await.expect("claim pc").is_none(),
        "an unverified tip must not be claimable"
    );

    // None on a clawed_back tip.
    let cb = make_pending(&app, sender, "fund-cb").await;
    app.state.db.clawback_social_tip(cb, sender).await.expect("clawback").expect("row");
    assert!(
        app.state.db.mark_tip_claiming(cb, claimant).await.expect("claim cb").is_none(),
        "a clawed_back tip must not be claimable"
    );

    // None on an already-swept (settled) tip.
    let swept = make_claimed(&app, sender, claimant, "fund-swept").await;
    assert!(
        app.state.db.mark_tip_claiming(swept, claimant).await.expect("claim swept").is_none(),
        "a settled tip must not be re-claimable"
    );
}

/// (b) confirm_tip_sweep is first-recorder-wins: a second, DIFFERENT txid must
/// NOT overwrite the recorded winner (both calls return the live row with the
/// FIRST txid). A never-claimed tip returns None.
#[tokio::test]
async fn confirm_tip_sweep_first_recorder_wins() {
    let Some(app) = tips_app().await else { return };
    let sender = app.create_user().await;
    let claimant = app.create_user().await;
    let id = make_claiming(&app, sender, claimant, "fund-sweep").await;

    // First recorder writes txid-A; the row STAYS 'claiming' (record, not settle).
    let r1 = app.state.db.confirm_tip_sweep(id, claimant, "txid-A").await.expect("record").expect("row");
    assert_eq!(r1.sweep_txid.as_deref(), Some("txid-A"));
    assert_eq!(r1.status, "claiming", "confirm_tip_sweep records, never settles");

    // A DIFFERENT txid does not overwrite; fallthrough returns the live row (A).
    let r2 = app.state.db.confirm_tip_sweep(id, claimant, "txid-B").await.expect("second").expect("live row");
    assert_eq!(
        r2.sweep_txid.as_deref(),
        Some("txid-A"),
        "first-recorder wins: a different txid must not overwrite"
    );
    assert_eq!(r2.status, "claiming");

    // Same txid again is an idempotent no-op returning A.
    let r3 = app.state.db.confirm_tip_sweep(id, claimant, "txid-A").await.expect("idem").expect("row");
    assert_eq!(r3.sweep_txid.as_deref(), Some("txid-A"));

    // A never-claimed (pending) tip → None.
    let pending = make_pending(&app, sender, "fund-cs-pending").await;
    assert!(
        app.state.db.confirm_tip_sweep(pending, claimant, "txid-x").await.expect("cs pending").is_none(),
        "confirm-sweep on a non-claiming tip returns None"
    );
}

/// (c) confirm_sweep_onchain settles 'claiming' -> 'claimed' ONLY, and it is the
/// only path to 'claimed'. It records the height witness and preserves
/// claimed_by when passed None; a second call is a no-op.
#[tokio::test]
async fn confirm_sweep_onchain_settles_claiming_only() {
    let Some(app) = tips_app().await else { return };
    let sender = app.create_user().await;
    let claimant = app.create_user().await;

    let id = make_claiming(&app, sender, claimant, "fund-settle").await;
    let settled = app
        .state
        .db
        .confirm_sweep_onchain(id, "swp-1", 500, Some("blockhash"), None)
        .await
        .expect("settle")
        .expect("claimed row");
    assert_eq!(settled.status, "claimed");
    assert!(settled.sweep_confirmed_at.is_some());
    assert_eq!(settled.sweep_block_height, Some(500));
    assert_eq!(settled.sweep_txid.as_deref(), Some("swp-1"));
    assert_eq!(
        settled.claimed_by_user_id,
        Some(claimant),
        "claimed_by is preserved when claimed_by=None"
    );

    // Second settle is a no-op (one-way lock).
    assert!(
        app.state.db.confirm_sweep_onchain(id, "swp-2", 501, None, None).await.expect("resettle").is_none(),
        "an already-claimed row cannot be re-settled"
    );

    // A pending (non-claiming) tip cannot be settled — 'claiming' is the only
    // entry into 'claimed'.
    let pending = make_pending(&app, sender, "fund-settle-pending").await;
    assert!(
        app.state.db.confirm_sweep_onchain(pending, "swp", 1, None, None).await.expect("settle pending").is_none(),
        "confirm_sweep_onchain requires status='claiming'"
    );
    let still = app.state.db.get_social_tip(pending).await.expect("get").expect("row");
    assert_eq!(still.status, "pending", "a pending tip must not be flipped to claimed");
}

/// (d) revert_sweep_on_reorg reverts 'claimed' -> 'claiming' ONLY, clearing the
/// settlement witness (sweep_confirmed_at, block height/hash) but PRESERVING
/// sweep_txid. Address-scan chains overwrite it via confirm_sweep_onchain on the
/// next cycle; grin (voucher) needs it to re-date the re-mined sweep via
/// get_kernel, so nulling it would strand the row in 'claiming'.
#[tokio::test]
async fn revert_sweep_on_reorg_only_from_claimed() {
    let Some(app) = tips_app().await else { return };
    let sender = app.create_user().await;
    let claimant = app.create_user().await;

    let id = make_claimed(&app, sender, claimant, "fund-reorg").await;
    let reverted = app.state.db.revert_sweep_on_reorg(id).await.expect("revert").expect("reverted row");
    assert_eq!(reverted.status, "claiming");
    assert!(reverted.sweep_confirmed_at.is_none());
    assert_eq!(
        reverted.sweep_txid.as_deref(),
        Some("onchain-swp"),
        "reorg preserves sweep_txid: address-scan chains overwrite it next cycle, grin needs it to re-date via get_kernel"
    );
    assert!(reverted.sweep_block_height.is_none());

    // Second revert is a no-op (now 'claiming', not 'claimed').
    assert!(
        app.state.db.revert_sweep_on_reorg(id).await.expect("re-revert").is_none(),
        "revert requires status='claimed'"
    );

    // Revert on a plain pending tip → None.
    let pending = make_pending(&app, sender, "fund-reorg-pending").await;
    assert!(
        app.state.db.revert_sweep_on_reorg(pending).await.expect("revert pending").is_none(),
        "a pending tip cannot be reorg-reverted"
    );
}

/// (e) clawback succeeds for the SENDER on pending / pending_confirmation /
/// claiming / funding_mismatch / cancelled while sweep_confirmed_at IS NULL,
/// is owner-scoped, and is BLOCKED once the sweep confirmed.
#[tokio::test]
async fn clawback_status_matrix_and_settled_block() {
    let Some(app) = tips_app().await else { return };
    let sender = app.create_user().await;
    let claimant = app.create_user().await;

    // pending → clawable.
    let pending = make_pending(&app, sender, "cb-pending").await;
    assert!(app.state.db.clawback_social_tip(pending, sender).await.expect("cb").is_some());

    // pending_confirmation → clawable.
    let pc = make_draft(&app, sender, "btc", 100_000, 0, None).await;
    app.state.db.attach_funding_to_tip(pc, sender, "cb-pc").await.expect("attach");
    assert!(app.state.db.clawback_social_tip(pc, sender).await.expect("cb").is_some());

    // claiming → clawable (sender racing a claimer).
    let claiming = make_claiming(&app, sender, claimant, "cb-claiming").await;
    assert!(app.state.db.clawback_social_tip(claiming, sender).await.expect("cb").is_some());

    // funding_mismatch → clawable.
    let mm = make_draft(&app, sender, "btc", 1_000_000, 0, None).await;
    app.state.db.attach_funding_to_tip(mm, sender, "cb-mm").await.expect("attach");
    app.state.db.mark_tip_funding_mismatch(mm, 10).await.expect("mismatch").expect("row");
    assert!(app.state.db.clawback_social_tip(mm, sender).await.expect("cb").is_some());

    // cancelled (GC'd but still-funded draft) → clawable.
    let cancelled = make_draft(&app, sender, "btc", 100_000, 0, None).await;
    app.state.db.cancel_draft_social_tip(cancelled, sender).await.expect("cancel").expect("id");
    assert!(app.state.db.clawback_social_tip(cancelled, sender).await.expect("cb").is_some());

    // Owner-scoped: a stranger cannot claw back; the real sender can.
    let owned = make_pending(&app, sender, "cb-owner").await;
    let stranger = app.create_user().await;
    assert!(
        app.state.db.clawback_social_tip(owned, stranger).await.expect("cb stranger").is_none(),
        "only the sender can claw back"
    );
    assert!(app.state.db.clawback_social_tip(owned, sender).await.expect("cb owner").is_some());

    // BLOCKED once the sweep confirmed (sweep_confirmed_at IS NOT NULL).
    let swept = make_claimed(&app, sender, claimant, "cb-swept").await;
    assert!(
        app.state.db.clawback_social_tip(swept, sender).await.expect("cb swept").is_none(),
        "a settled tip must not be clawed back"
    );
}

/// Reconciler poll queries select the right rows. A huge limit avoids the
/// ordering / rate-limit windows hiding our rows amid other tests' rows.
#[tokio::test]
async fn reconciler_poll_queries_select_the_right_rows() {
    let Some(app) = tips_app().await else { return };
    let sender = app.create_user().await;
    let claimant = app.create_user().await;

    let claiming = make_claiming(&app, sender, claimant, "poll-claiming").await;
    let pending = make_pending(&app, sender, "poll-pending").await;
    let claimed = make_claimed(&app, sender, claimant, "poll-claimed").await;

    let awaiting = app.state.db.get_tips_awaiting_sweep_confirmation(1_000_000).await.expect("awaiting");
    assert!(awaiting.iter().any(|t| t.id == claiming), "a claiming tip awaits sweep confirmation");
    assert!(!awaiting.iter().any(|t| t.id == pending), "a pending tip does not await sweep confirmation");
    assert!(!awaiting.iter().any(|t| t.id == claimed), "a settled tip does not await sweep confirmation");

    let reorg = app.state.db.get_settled_tips_for_reorg_check(1_000_000).await.expect("reorg");
    assert!(reorg.iter().any(|t| t.id == claimed), "a settled tip with a height witness is reorg-checked");
    assert!(!reorg.iter().any(|t| t.id == claiming), "a claiming tip is not reorg-checked");
}

// ── Stage 5: lifecycle + draft garbage-collection DB tests ────────────────────
//
// The GC cancel passes filter on `created_at < NOW() - INTERVAL '7 days'` (and
// the claiming scan on `claimed_at < NOW() - INTERVAL '15 minutes'`). The normal
// insert stamps NOW(), so a test back-dates the timestamp with a raw UPDATE to
// exercise the age filter.

/// Back-date a tip's `created_at` by `interval` (e.g. "8 days") via a raw UPDATE.
async fn backdate_created_at(app: &common::TestApp, id: uuid::Uuid, interval: &str) {
    sqlx::query(&format!(
        "UPDATE social_tips SET created_at = NOW() - INTERVAL '{interval}' WHERE id = $1"
    ))
    .bind(id)
    .execute(app.state.db.pool())
    .await
    .expect("backdate created_at");
}

/// cancel_old_drafts flips a > 7d `draft` to `cancelled` and leaves a fresh draft
/// (and non-draft rows) untouched.
#[tokio::test]
async fn cancel_old_drafts_flips_stale_draft_only() {
    let Some(app) = tips_app().await else { return };
    let uid = app.create_user().await;

    let stale = make_draft(&app, uid, "btc", 100_000, 0, None).await;
    backdate_created_at(&app, stale, "8 days").await;
    let fresh = make_draft(&app, uid, "btc", 100_000, 0, None).await;

    let cancelled = app.state.db.cancel_old_drafts().await.expect("cancel_old_drafts");
    assert!(cancelled.iter().any(|r| r.id == stale), "a > 7d draft must be cancelled");
    assert!(!cancelled.iter().any(|r| r.id == fresh), "a fresh draft must NOT be cancelled");

    let stale_row = app.state.db.get_social_tip(stale).await.expect("get").expect("row");
    assert_eq!(stale_row.status, "cancelled");
    let fresh_row = app.state.db.get_social_tip(fresh).await.expect("get").expect("row");
    assert_eq!(fresh_row.status, "draft", "a fresh draft stays draft");
}

/// cancel_stuck_pending_confirmation flips a > 7d `pending_confirmation` row to
/// `cancelled` and leaves a fresh one untouched.
#[tokio::test]
async fn cancel_stuck_pending_confirmation_flips_stale_only() {
    let Some(app) = tips_app().await else { return };
    let uid = app.create_user().await;

    let stale = make_draft(&app, uid, "btc", 100_000, 0, None).await;
    app.state.db.attach_funding_to_tip(stale, uid, "gc-stale-pc").await.expect("attach");
    backdate_created_at(&app, stale, "8 days").await;

    let fresh = make_draft(&app, uid, "btc", 100_000, 0, None).await;
    app.state.db.attach_funding_to_tip(fresh, uid, "gc-fresh-pc").await.expect("attach");

    let cancelled = app
        .state
        .db
        .cancel_stuck_pending_confirmation()
        .await
        .expect("cancel_stuck_pending_confirmation");
    assert!(
        cancelled.iter().any(|r| r.id == stale),
        "a > 7d pending_confirmation must be cancelled"
    );
    assert!(
        !cancelled.iter().any(|r| r.id == fresh),
        "a fresh pending_confirmation must NOT be cancelled"
    );

    let stale_row = app.state.db.get_social_tip(stale).await.expect("get").expect("row");
    assert_eq!(stale_row.status, "cancelled");
    let fresh_row = app.state.db.get_social_tip(fresh).await.expect("get").expect("row");
    assert_eq!(fresh_row.status, "pending_confirmation");
}

/// log_stuck_claiming returns a > 15m back-dated `claiming` row, excludes a fresh
/// one, and mutates NOTHING (read-only scan).
#[tokio::test]
async fn log_stuck_claiming_returns_backdated_and_mutates_nothing() {
    let Some(app) = tips_app().await else { return };
    let sender = app.create_user().await;
    let claimant = app.create_user().await;

    let stale = make_claiming(&app, sender, claimant, "gc-stale-claiming").await;
    sqlx::query("UPDATE social_tips SET claimed_at = NOW() - INTERVAL '16 minutes' WHERE id = $1")
        .bind(stale)
        .execute(app.state.db.pool())
        .await
        .expect("backdate claimed_at");
    let fresh = make_claiming(&app, sender, claimant, "gc-fresh-claiming").await;

    let stuck = app.state.db.log_stuck_claiming().await.expect("log_stuck_claiming");
    assert!(stuck.iter().any(|r| r.id == stale), "a > 15m claiming row must be surfaced");
    assert!(!stuck.iter().any(|r| r.id == fresh), "a fresh claiming row must NOT be surfaced");

    // READ-ONLY: the surfaced row is untouched — still 'claiming', no sweep confirm.
    let row = app.state.db.get_social_tip(stale).await.expect("get").expect("row");
    assert_eq!(row.status, "claiming", "log_stuck_claiming must not mutate status");
    assert!(row.sweep_confirmed_at.is_none(), "log_stuck_claiming must not settle the sweep");
}

// ── Grin (voucher asset) tests ────────────────────────────────────────────────
//
// Grin tips carry no address+view-key: the client funds a voucher OUTPUT and
// sends its Pedersen COMMITMENT (66 hex) as both `tip_address` and
// `grin_commitment`. These cover the create-time surface (gating, validation,
// the grin_commitment column/migration, the 10-conf threshold). The
// get_outputs/get_kernel-backed worker paths need a live grin node and are
// documented manual steps (see the module docs in src/tips/{confirmation,
// sweep_reconciler}.rs).

/// Boot the app with tips + the grin chain flag on (+ a share base). The grin
/// client is built against the empty test grin config; no worker runs in-harness,
/// so the create-time surface is exercised without a live node.
async fn grin_tips_app() -> Option<common::TestApp> {
    common::try_app_with(|c| {
        c.features.tips = true;
        c.features.chains.grin = true;
        c.tip_share_base = Some("https://tips.example".into());
    })
    .await
}

/// A valid Grin voucher commitment shape: 66 hex chars (33-byte compressed point).
fn grin_commit() -> String {
    format!("09{}", "a1".repeat(32))
}

#[tokio::test]
async fn grin_public_tip_create_returns_draft_and_share_url() {
    let Some(app) = grin_tips_app().await else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let (_uid, token, _refresh) = app.mint_session().await;
    let commit = grin_commit();

    // No funding_txid -> the backend creates status='draft' (voucher funds later).
    let body = json!({
        "asset": "grin",
        "amount": 500,
        "is_public": true,
        "claim_key_hash": CLAIM_HASH,
        "encrypted_key": ENC_KEY_HEX,
        "tip_address": commit,
        "grin_commitment": commit,
    });
    let (status, resp) = app
        .request("POST", "/api/v1/tips/social", Some(&token), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK, "create grin: {resp}");
    assert_eq!(resp["status"], "draft");
    let tip_id = resp["tip_id"].as_str().expect("tip_id").to_string();
    assert_eq!(resp["share_url"], format!("https://tips.example/{tip_id}"));

    // Migration applied: the grin_commitment column round-trips, tip_address
    // mirrors it, and the grin funding threshold is 10.
    let uuid = tip_id.parse::<uuid::Uuid>().unwrap();
    let row = app.state.db.get_social_tip(uuid).await.expect("get").expect("row");
    assert_eq!(row.asset, "grin");
    assert_eq!(row.grin_commitment.as_deref(), Some(commit.as_str()));
    assert_eq!(row.tip_address.as_deref(), Some(commit.as_str()));
    assert_eq!(row.confirmations_required, 10);
}

#[tokio::test]
async fn grin_create_falls_back_to_tip_address_for_commitment() {
    let Some(app) = grin_tips_app().await else { return };
    let (_uid, token, _refresh) = app.mint_session().await;
    let commit = grin_commit();

    // Omit grin_commitment entirely -> the backend stores tip_address as the
    // commitment (the client sends the same value for both).
    let body = json!({
        "asset": "grin",
        "amount": 500,
        "is_public": true,
        "claim_key_hash": CLAIM_HASH,
        "tip_address": commit,
    });
    let (status, resp) = app
        .request("POST", "/api/v1/tips/social", Some(&token), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK, "create grin (no commit field): {resp}");
    let uuid = resp["tip_id"].as_str().unwrap().parse::<uuid::Uuid>().unwrap();
    let row = app.state.db.get_social_tip(uuid).await.expect("get").expect("row");
    assert_eq!(row.grin_commitment.as_deref(), Some(commit.as_str()));
}

#[tokio::test]
async fn grin_create_rejects_junk_commitment() {
    let Some(app) = grin_tips_app().await else { return };
    let (_uid, token, _refresh) = app.mint_session().await;

    // tip_address that isn't a 66-hex commitment -> clean 400.
    for bad in [
        "deadbeef".to_string(),               // too short
        "z".repeat(66),                       // right length, not hex
        format!("09{}", "a1".repeat(33)),     // 68 chars, too long
    ] {
        let body = json!({
            "asset": "grin",
            "amount": 500,
            "is_public": true,
            "claim_key_hash": CLAIM_HASH,
            "tip_address": bad,
        });
        let (status, resp) = app
            .request("POST", "/api/v1/tips/social", Some(&token), Some(body))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "junk grin address must 400: {resp}");
    }

    // A valid tip_address but a junk explicit grin_commitment is also rejected
    // (the explicit field is preferred, so it must validate too).
    let body = json!({
        "asset": "grin",
        "amount": 500,
        "is_public": true,
        "claim_key_hash": CLAIM_HASH,
        "tip_address": grin_commit(),
        "grin_commitment": "z".repeat(66),
    });
    let (status, resp) = app
        .request("POST", "/api/v1/tips/social", Some(&token), Some(body))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "junk grin_commitment must 400: {resp}");
}

#[tokio::test]
async fn grin_create_rejected_when_chain_disabled() {
    // supported_tip_asset gates on the feature flag: grin OFF -> 400 even though
    // the wire is otherwise valid.
    let Some(app) = common::try_app_with(|c| {
        c.features.tips = true;
        c.features.chains.grin = false;
        c.tip_share_base = Some("https://tips.example".into());
    })
    .await else {
        return;
    };
    let (_uid, token, _refresh) = app.mint_session().await;
    let commit = grin_commit();
    let body = json!({
        "asset": "grin",
        "amount": 500,
        "is_public": true,
        "claim_key_hash": CLAIM_HASH,
        "tip_address": commit,
        "grin_commitment": commit,
    });
    let (status, resp) = app
        .request("POST", "/api/v1/tips/social", Some(&token), Some(body))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "grin disabled must 400: {resp}");
}

/// The grin voucher flows through the SAME draft -> attach-funding -> claiming
/// lifecycle as the other assets: attach a client bookkeeping id, mark it
/// funded+verified (as the workers would), claim it, and record the sweep's
/// kernel excess as sweep_txid. Pure DB-level (no node), asserting the columns
/// the grin worker arms depend on.
#[tokio::test]
async fn grin_tip_db_lifecycle_columns() {
    let Some(app) = grin_tips_app().await else { return };
    let uid = app.create_user().await;
    let commit = grin_commit();

    use smirk_backend_core::infra::db::NewSocialTip;
    let new = NewSocialTip {
        sender_user_id: uid,
        asset: "grin",
        amount: 500,
        claim_key_hash: Some(CLAIM_HASH),
        encrypted_key: None,
        tip_address: Some(&commit),
        funding_txid: None,
        tip_view_key: None,
        confirmations_required: 10,
        grin_commitment: Some(&commit),
    };
    let tip_id = app.state.db.create_draft_social_tip(new).await.expect("create draft").id;

    // attach-funding with the client's bookkeeping id (grin has no real txid).
    let r = app
        .state
        .db
        .attach_funding_to_tip(tip_id, uid, "grin-bookkeeping-uuid")
        .await
        .expect("attach");
    assert_eq!(r.status, "pending_confirmation");
    assert_eq!(r.grin_commitment.as_deref(), Some(commit.as_str()));

    // Simulate the funding worker: 10 confs reached + amount auto-verified.
    app.state.db.update_tip_confirmations(tip_id, 10).await.expect("confs");
    let verified = app
        .state
        .db
        .mark_tip_funding_verified(tip_id, 500)
        .await
        .expect("verify")
        .expect("row");
    assert_eq!(verified.status, "pending");
    assert!(verified.funding_amount_verified);

    // Claim, then record the sweep's kernel excess as sweep_txid.
    let claimant = app.create_user().await;
    app.state.db.mark_tip_claiming(tip_id, claimant).await.expect("claim").expect("row");
    let excess = format!("08{}", "bc".repeat(32)); // kernel excess (66 hex)
    let swept = app
        .state
        .db
        .confirm_tip_sweep(tip_id, claimant, &excess)
        .await
        .expect("confirm sweep")
        .expect("row");
    assert_eq!(swept.status, "claiming");
    assert_eq!(swept.sweep_txid.as_deref(), Some(excess.as_str()));
}
