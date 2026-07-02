//! `smirk-admin` — break-glass admin CLI.
//!
//! Talks to Postgres directly, bypassing the HTTP admin plane and all network
//! rate limits, so it is the recovery path when the network plane is unreachable
//! or a solo admin key is compromised. Authority is shell access + the DB creds +
//! `ADMIN_KEY_INTEGRITY_SECRET` (the same MAC secret the server uses). Every
//! mutation writes a hash-chained audit row (`actor_kind = cli`).
//!
//! Commands:
//!   list-keys
//!   add-key            --pubkey <64hex> [--label <s>]
//!   revoke-key         --id <uuid>            (may revoke the LAST key)
//!   replace-key        --old <uuid> --pubkey <64hex> [--revoke-all]
//!   create-admin-wallet --out <path>          (generates a key; writes the
//!                                              secret 0600; registers the pubkey
//!                                              as pending; latches the bootstrap
//!                                              on a fresh instance — a complete
//!                                              first-run, no `setup` needed)
//!   migrate-legacy     --source-url <pg-url> [--commit]  (import legacy v0.2.x
//!                                              user identity, joined on the
//!                                              derivation-independent seed_fingerprint)
//!   doctor
//!
//! Deferred (documented): remac-keys (integrity-secret rotation must also
//! re-chain the audit log) and setup/reset-setup (first-run bootstrap subsystem).

use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::process::ExitCode;

use rand::rngs::OsRng;
use rand::RngCore;
use uuid::Uuid;
use zeroize::Zeroize;

use smirk_backend_core::api::users::validate_username;
use smirk_backend_core::core::invite::{generate_invite_code, hash_invite_code};
use smirk_backend_core::infra::db::{AddKeyOutcome, Database, RevokeKeyOutcome};
use smirk_backend_core::models::db::{NewAdminAudit, NewAdminKey, NewUser};

const USAGE: &str = "\
smirk-admin — break-glass admin CLI

USAGE:
    smirk-admin <COMMAND> [FLAGS]

COMMANDS:
    setup               --pubkey <64hex>          (first-run: seed the admin + latch)
    reset-setup         --i-understand
    list-keys
    add-key             --pubkey <64hex> [--label <s>]
    revoke-key          --id <uuid>
    replace-key         --old <uuid> --pubkey <64hex> [--revoke-all]
    create-admin-wallet --out <path>              (generate a key + bootstrap a fresh instance)
    mint-invite         [--count <n>] [--label <s>]  (registration invite codes)
    migrate-legacy      --source-url <pg-url> [--commit] [--limit <n>]
                                                 (import v0.2.x user identity into this v0.3 DB,
                                                  joined on seed_fingerprint; dry-run unless --commit)
    doctor
";

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &[String]) -> Result<(), String> {
    let Some(cmd) = args.first() else {
        print!("{USAGE}");
        return Ok(());
    };
    let rest = &args[1..];

    // The CLI handles its own secrets; refuse to run if .env is world/group
    // readable (a leaked DATABASE_URL / integrity secret defeats everything).
    preflight_env_perms()?;

    let _ = dotenvy::dotenv();
    let secret = std::env::var("ADMIN_KEY_INTEGRITY_SECRET")
        .map_err(|_| "ADMIN_KEY_INTEGRITY_SECRET must be set".to_string())?;
    if secret.len() < 32 {
        return Err("ADMIN_KEY_INTEGRITY_SECRET must be at least 32 bytes".into());
    }
    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set".to_string())?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .map_err(|e| format!("connect database: {e}"))?;
    // The admin paths never pepper identity columns, so empty peppers are fine.
    let db = Database::new(pool, String::new(), String::new());

    match cmd.as_str() {
        "setup" => setup_cmd(&db, &secret, rest).await,
        "reset-setup" => reset_setup_cmd(&db, &secret, rest).await,
        "list-keys" => list_keys(&db).await,
        "add-key" => add_key(&db, &secret, rest).await,
        "revoke-key" => revoke_key(&db, &secret, rest).await,
        "replace-key" => replace_key(&db, &secret, rest).await,
        "create-admin-wallet" => create_admin_wallet(&db, &secret, rest).await,
        "mint-invite" => mint_invite(&db, rest).await,
        "migrate-legacy" => migrate_legacy(&db, rest).await,
        "doctor" => doctor(&db, &secret).await,
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    }
}

// ── flag parsing ─────────────────────────────────────────────────────────────

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn require_flag(args: &[String], name: &str) -> Result<String, String> {
    flag(args, name).ok_or_else(|| format!("missing required {name}"))
}

fn validate_pubkey(pubkey: &str) -> Result<String, String> {
    let pk = pubkey.to_lowercase();
    let ok = pk.len() == 64
        && pk
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    ok.then_some(pk)
        .ok_or_else(|| "pubkey must be 64 lowercase hex chars".into())
}

fn cli_audit(action: &str, target: Option<String>) -> NewAdminAudit {
    NewAdminAudit {
        action: action.into(),
        actor_kind: "cli".into(),
        actor_pubkey_prefix: None,
        target,
        details: None,
        ip_address: None,
    }
}

/// Refuse to run if a present `.env` is group/other-accessible.
fn preflight_env_perms() -> Result<(), String> {
    match std::fs::metadata(".env") {
        Ok(m) => {
            let mode = m.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(format!(
                    ".env is group/other-accessible (mode {:o}); chmod 600 it first",
                    mode & 0o777
                ));
            }
            Ok(())
        }
        Err(_) => Ok(()), // no .env (env supplied another way) — nothing to check
    }
}

// ── commands ─────────────────────────────────────────────────────────────────

async fn setup_cmd(db: &Database, secret: &str, args: &[String]) -> Result<(), String> {
    let pubkey = validate_pubkey(&require_flag(args, "--pubkey")?)?;
    db.bootstrap_admin(&pubkey, secret)
        .await
        .map_err(|e| e.to_string())?;
    println!("bootstrapped: active admin {pubkey}");
    println!("setup latched (locked); the network admin plane is now usable");
    Ok(())
}

async fn reset_setup_cmd(db: &Database, secret: &str, args: &[String]) -> Result<(), String> {
    if !has_flag(args, "--i-understand") {
        return Err(
            "reset-setup re-opens first-run setup; existing admin keys are preserved. \
             Re-run with --i-understand to confirm"
                .into(),
        );
    }
    db.reset_setup(secret).await.map_err(|e| e.to_string())?;
    println!("setup reset to uninitialized (existing admin keys preserved)");
    Ok(())
}

async fn list_keys(db: &Database) -> Result<(), String> {
    let keys = db.list_admin_keys().await.map_err(|e| e.to_string())?;
    if keys.is_empty() {
        println!("(no admin keys)");
        return Ok(());
    }
    for k in keys {
        let status = if k.revoked_at.is_some() {
            "revoked"
        } else if k.activated_at.is_none() {
            "pending"
        } else {
            "active"
        };
        println!(
            "{}  {}  {:<7}  added {}",
            k.id,
            &k.pubkey,
            status,
            k.created_at.to_rfc3339()
        );
    }
    Ok(())
}

async fn add_key(db: &Database, secret: &str, args: &[String]) -> Result<(), String> {
    let pubkey = validate_pubkey(&require_flag(args, "--pubkey")?)?;
    let new = NewAdminKey {
        pubkey: pubkey.clone(),
        label: flag(args, "--label"),
        scope: "admin".into(),
        created_by_kind: "cli".into(),
        activation_deadline: None, // CLI-added keys do not auto-expire
    };
    // No cap from the CLI (shell == authority): pass an effectively-unbounded max.
    match db
        .create_admin_key_audited(
            new,
            &cli_audit("admin_key_added", Some(pubkey)),
            secret,
            i64::MAX,
        )
        .await
        .map_err(|e| e.to_string())?
    {
        AddKeyOutcome::Created(k) => {
            println!("added pending admin key {} ({})", k.id, k.pubkey);
            println!("it activates on its holder's first login");
            Ok(())
        }
        AddKeyOutcome::CapReached => Err("unexpected: cap reached".into()),
    }
}

async fn revoke_key(db: &Database, secret: &str, args: &[String]) -> Result<(), String> {
    let id = parse_uuid(&require_flag(args, "--id")?)?;
    // keep_min_live = false: the CLI MAY revoke the last key (it is the authority).
    match db
        .revoke_admin_key_full(
            id,
            &cli_audit("admin_key_revoked", Some(id.to_string())),
            secret,
            false,
        )
        .await
        .map_err(|e| e.to_string())?
    {
        RevokeKeyOutcome::Revoked(_) => {
            println!("revoked admin key {id} (and its sessions)");
            Ok(())
        }
        RevokeKeyOutcome::NotFound => Err("key not found or already revoked".into()),
        RevokeKeyOutcome::WouldEmptyAllowlist => unreachable!("keep_min_live is false"),
    }
}

async fn replace_key(db: &Database, secret: &str, args: &[String]) -> Result<(), String> {
    let old = parse_uuid(&require_flag(args, "--old")?)?;
    let pubkey = validate_pubkey(&require_flag(args, "--pubkey")?)?;
    let revoke_all = has_flag(args, "--revoke-all");
    let new = NewAdminKey {
        pubkey: pubkey.clone(),
        label: flag(args, "--label"),
        scope: "admin".into(),
        created_by_kind: "cli".into(),
        activation_deadline: None,
    };
    let created = db
        .rotate_admin_key(
            old,
            new,
            &cli_audit("admin_key_rotated", Some(old.to_string())),
            secret,
        )
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "old key not found or already revoked".to_string())?;
    println!(
        "replaced {old} -> new pending key {} ({})",
        created.id, created.pubkey
    );

    if revoke_all {
        // Global break-glass: revoke every OTHER live key, leaving only the new one.
        let mut revoked = 0u32;
        for k in db.list_admin_keys().await.map_err(|e| e.to_string())? {
            if k.revoked_at.is_some() || k.id == created.id {
                continue;
            }
            if let RevokeKeyOutcome::Revoked(_) = db
                .revoke_admin_key_full(
                    k.id,
                    &cli_audit("admin_key_revoked", Some(k.id.to_string())),
                    secret,
                    false,
                )
                .await
                .map_err(|e| e.to_string())?
            {
                revoked += 1;
            }
        }
        println!("--revoke-all: revoked {revoked} other live key(s)");
    }
    println!("the new key activates on its holder's first login");
    Ok(())
}

async fn create_admin_wallet(db: &Database, secret: &str, args: &[String]) -> Result<(), String> {
    let out = require_flag(args, "--out")?;

    // Generate a valid x-only schnorr keypair from OS entropy.
    let mut seed = [0u8; 32];
    let pubkey = loop {
        OsRng.fill_bytes(&mut seed);
        if let Ok(sk) = k256::schnorr::SigningKey::from_bytes(&seed) {
            break hex::encode(sk.verifying_key().to_bytes());
        }
    };
    // The secret, as hex, in a buffer that zeroizes on drop. Written as raw bytes
    // straight to a 0600 file (never stdout/journald, never interpolated/logged).
    let mut secret_hex = zeroize::Zeroizing::new(hex::encode(seed));
    seed.zeroize();

    let write_res = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true) // never clobber an existing file
            .mode(0o600)
            .open(&out)?;
        f.write_all(secret_hex.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()
    })();
    secret_hex.zeroize();
    write_res.map_err(|e| format!("write secret to {out}: {e}"))?;

    // Register the PUBLIC key only (pending), and latch the bootstrap if this is a
    // fresh instance — so `create-admin-wallet` alone fully bootstraps, atomically,
    // rather than leaving setup half-open for a later `setup` to collide with.
    let latched = match db
        .create_admin_key_bootstrapping(
            NewAdminKey {
                pubkey: pubkey.clone(),
                label: Some("cli-generated".into()),
                scope: "admin".into(),
                created_by_kind: "cli".into(),
                activation_deadline: None,
            },
            &cli_audit("admin_wallet_created", Some(pubkey.clone())),
            secret,
            i64::MAX,
        )
        .await
        .map_err(|e| e.to_string())?
    {
        (AddKeyOutcome::Created(_), latched) => latched,
        (AddKeyOutcome::CapReached, _) => return Err("unexpected: cap reached".into()),
    };

    println!("generated admin key; secret written to {out} (mode 0600)");
    println!("pubkey: {pubkey}");
    if latched {
        println!("fresh instance bootstrapped: setup latched (locked) — no `setup` needed");
        println!("import the secret into your NIP-98 signer and log in to activate.");
        println!(
            "if you lose this secret before that first login, recover by re-running \
             `create-admin-wallet` (adds a fresh key), then `revoke-key` the stale one"
        );
    } else {
        println!("instance already bootstrapped: added a pending admin key");
        println!("import the secret into your NIP-98 signer; it activates on first login");
    }
    Ok(())
}

/// Mint single-use registration invite codes. Generates random 128-bit codes,
/// stores only their sha256 hashes, and prints the RAW codes to stdout once for
/// distribution — they are not recoverable afterward (only the hash is kept).
async fn mint_invite(db: &Database, args: &[String]) -> Result<(), String> {
    let count: u32 = match flag(args, "--count") {
        Some(s) => s
            .parse()
            .map_err(|_| "--count must be a number".to_string())?,
        None => 1,
    }
    .clamp(1, 1000);
    let label = flag(args, "--label");
    eprintln!(
        "Minting {count} single-use invite code(s){}:",
        label
            .as_deref()
            .map(|l| format!(" [{l}]"))
            .unwrap_or_default()
    );
    for _ in 0..count {
        let code = generate_invite_code();
        db.insert_invite_code(&hash_invite_code(&code), label.as_deref())
            .await
            .map_err(|e| format!("insert invite: {e}"))?;
        println!("{code}");
    }
    eprintln!("\nDistribute now — only the hash is stored; raw codes are not recoverable.");
    Ok(())
}

async fn doctor(db: &Database, secret: &str) -> Result<(), String> {
    println!("database: {}", health(db).await);
    let live = db
        .count_live_admin_keys()
        .await
        .map_err(|e| e.to_string())?;
    println!("live admin keys: {live}");
    if live == 0 {
        println!("  WARNING: no live admin keys — run create-admin-wallet or add-key");
    }
    let chain_ok = db
        .verify_admin_audit_chain(secret)
        .await
        .map_err(|e| e.to_string())?;
    println!(
        "admin audit chain: {}",
        if chain_ok {
            "OK"
        } else {
            "BROKEN (tampered, or wrong ADMIN_KEY_INTEGRITY_SECRET)"
        }
    );
    if !chain_ok {
        return Err("audit chain verification failed".into());
    }
    Ok(())
}

async fn health(db: &Database) -> &'static str {
    match db.health_check().await {
        Ok(_) => "OK",
        Err(_) => "UNREACHABLE",
    }
}

fn parse_uuid(s: &str) -> Result<Uuid, String> {
    Uuid::parse_str(s).map_err(|_| format!("invalid uuid: {s}"))
}

// ── legacy (v0.2.x) user import ──────────────────────────────────────────────

/// One identity row read from the legacy v0.2.x `users` table. Only the columns
/// that have a home in the v0.3 schema — socials (telegram/discord/…), keys, and
/// wallets are intentionally not carried (the v0.3 client re-registers keys +
/// wallets at v3 derivation on first unlock; socials/tips have no v0.3 model).
#[derive(sqlx::FromRow)]
struct LegacyUser {
    username: Option<String>,
    pubkey_hash: String,
    nostr_pubkey: Option<String>,
    seed_fingerprint: Option<String>,
    wallet_birthday: Option<chrono::DateTime<chrono::Utc>>,
    xmr_start_height: Option<i64>,
    wow_start_height: Option<i64>,
}

/// Import user identity from a legacy v0.2.x backend database into this v0.3 DB.
///
/// Join key is the derivation-independent `seed_fingerprint` (`SHA256(SHA256(seed))`);
/// `pubkey_hash` is carried too so a v3-derivation wallet reclaims its row on the
/// first `/auth/extension` without a rotation step. `pubkey_hash` and
/// `seed_fingerprint` are peppered at rest by the DB layer, so this constructs a
/// target `Database` with the real `SEED_FINGERPRINT_PEPPER` (the other admin
/// paths run pepper-less and must not touch identity columns) — run this with the
/// v0.3 server's own `.env`.
///
/// Idempotent: a legacy user already present (by peppered `pubkey_hash` or
/// `seed_fingerprint`) is skipped, so it is safe to re-run during the transition
/// and once more at cutover. Dry-run unless `--commit`.
async fn migrate_legacy(admin_db: &Database, args: &[String]) -> Result<(), String> {
    let source_url = require_flag(args, "--source-url")?;
    let commit = has_flag(args, "--commit");
    let limit: Option<usize> = match flag(args, "--limit") {
        Some(s) => Some(
            s.parse()
                .map_err(|_| "--limit must be a whole number".to_string())?,
        ),
        None => None,
    };

    // The peppered target: reuse the connection pool run() already opened to
    // DATABASE_URL, but rebuild the Database with the identity pepper so
    // create_user() writes at-rest values that match what the live server
    // computes (empty pepper here would silently produce unmatchable rows).
    let pepper = std::env::var("SEED_FINGERPRINT_PEPPER").map_err(|_| {
        "SEED_FINGERPRINT_PEPPER must be set (run with the v0.3 server's .env)".to_string()
    })?;
    if pepper.len() < 32 {
        return Err("SEED_FINGERPRINT_PEPPER must be at least 32 bytes".into());
    }
    let target = Database::new(admin_db.pool().clone(), pepper, String::new());

    let source = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&source_url)
        .await
        .map_err(|e| format!("connect source (legacy) db: {e}"))?;

    // Deterministic first-n via a SQL LIMIT (bounds memory + source load); the
    // `id` tiebreak makes a staged `--limit` select the same rows every run. The
    // limit is a parsed usize, so interpolating it is injection-safe.
    let sql = format!(
        "SELECT username, pubkey_hash, nostr_pubkey, seed_fingerprint, wallet_birthday, \
                xmr_start_height, wow_start_height \
         FROM users WHERE pubkey_hash IS NOT NULL ORDER BY created_at, id{}",
        limit.map(|n| format!(" LIMIT {n}")).unwrap_or_default()
    );
    let legacy: Vec<LegacyUser> = sqlx::query_as::<_, LegacyUser>(&sql)
        .fetch_all(&source)
        .await
        .map_err(|e| format!("read legacy users: {e}"))?;

    println!("legacy users read : {}", legacy.len());
    println!(
        "mode              : {}",
        if commit {
            "COMMIT (writing to this v0.3 DB)"
        } else {
            "DRY-RUN (no writes; pass --commit to apply)"
        }
    );
    println!();

    let (mut created, mut skipped, mut uname_dropped, mut nostr_dropped, mut errors) =
        (0u32, 0u32, 0u32, 0u32, 0u32);
    // In-batch dedup: a v0.2.x table can hold pre/post-rotation rows sharing a
    // seed_fingerprint/pubkey_hash. Without this a dry-run would double-count
    // them (a commit self-heals via the exists-check, but the numbers should
    // match). Keys are namespaced so a pubkey_hash can't alias a fingerprint.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for u in &legacy {
        // Best-effort per row: a transient lookup OR insert error on one user
        // must not abort the whole pass — idempotent re-runs rely on the run
        // making forward progress across a flaky window.
        match import_one(&target, u, commit, &mut seen).await {
            Ok(ImportOutcome::Skipped) => skipped += 1,
            Ok(ImportOutcome::Created {
                username_dropped,
                nostr_dropped: nd,
            }) => {
                created += 1;
                if username_dropped {
                    uname_dropped += 1;
                }
                if nd {
                    nostr_dropped += 1;
                }
                println!(
                    "  {}: {}",
                    if commit { "imported" } else { "would import" },
                    legacy_label(u)
                );
            }
            Err(e) => {
                errors += 1;
                eprintln!("  ERROR importing {}: {e}", legacy_label(u));
            }
        }
    }

    println!();
    println!(
        "summary: {}={created} skipped(already present)={skipped} \
         username-dropped={uname_dropped} nostr-dropped={nostr_dropped} errors={errors}",
        if commit { "imported" } else { "would-import" }
    );
    if !commit {
        println!("dry-run only — re-run with --commit to apply.");
    }
    Ok(())
}

/// Outcome of importing one legacy row.
enum ImportOutcome {
    /// Created (or, in dry-run, would be). Flags note fields dropped on collision.
    Created {
        username_dropped: bool,
        nostr_dropped: bool,
    },
    /// Already present on the target (idempotent re-run, in-batch duplicate, or a
    /// concurrent native onboarding that won a race) — nothing to do.
    Skipped,
}

/// Display label for a legacy row: its original username, else a pubkey-hash
/// prefix. Used in per-row log lines even when the username is later dropped.
fn legacy_label(u: &LegacyUser) -> String {
    u.username
        .as_deref()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("pk:{}…", &u.pubkey_hash[..8.min(u.pubkey_hash.len())]))
}

/// True if this legacy identity is already on the target (by peppered
/// `pubkey_hash` or `seed_fingerprint`). A read error bubbles up so the caller
/// counts it as a per-row error rather than aborting the whole run.
async fn identity_present(target: &Database, u: &LegacyUser) -> Result<bool, String> {
    if target
        .get_user_by_pubkey_hash(&u.pubkey_hash)
        .await
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Ok(true);
    }
    if let Some(fp) = &u.seed_fingerprint {
        if target
            .get_user_by_seed_fingerprint(fp)
            .await
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Import a single legacy row. Skips if already present (idempotency / in-batch
/// duplicate). Drops a username or `nostr_pubkey` that is reserved/malformed/taken
/// (the user is still imported). On `commit`, inserts via `create_user` (which
/// peppers `pubkey_hash`/`seed_fingerprint`); a UNIQUE violation from a concurrent
/// native onboarding is reconciled — the identity is re-checked (→ `Skipped`) and,
/// failing that, retried once with the contended handle/npub dropped so the user
/// still lands rather than failing the whole row.
async fn import_one(
    target: &Database,
    u: &LegacyUser,
    commit: bool,
    seen: &mut std::collections::HashSet<String>,
) -> Result<ImportOutcome, String> {
    // In-batch dedup (source rotation duplicates); namespaced keys.
    if !seen.insert(format!("pk:{}", u.pubkey_hash)) {
        return Ok(ImportOutcome::Skipped);
    }
    if let Some(fp) = &u.seed_fingerprint {
        if !seen.insert(format!("fp:{fp}")) {
            return Ok(ImportOutcome::Skipped);
        }
    }
    if identity_present(target, u).await? {
        return Ok(ImportOutcome::Skipped);
    }

    // Username: drop (keep the user) if reserved/malformed/already taken. Mirrors
    // the HTTP handler's guards, which create_user bypasses.
    let mut username = u
        .username
        .as_deref()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());
    let mut username_dropped = false;
    if let Some(name) = username.clone() {
        let taken = validate_username(&name).is_err()
            || target
                .get_user_by_username(&name)
                .await
                .map_err(|e| e.to_string())?
                .is_some();
        if taken {
            println!("  username {name:?} invalid/reserved/taken -> importing without it");
            username = None;
            username_dropped = true;
        }
    }

    // nostr_pubkey: carried verbatim (public, unpeppered), but dropped on a target
    // UNIQUE collision (a native user already linked it) — re-linked on v0.3 then.
    let mut nostr_pubkey = u
        .nostr_pubkey
        .as_deref()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());
    let mut nostr_dropped = false;
    if let Some(npub) = nostr_pubkey.clone() {
        if target
            .find_user_by_nostr_pubkey(&npub)
            .await
            .map_err(|e| e.to_string())?
            .is_some()
        {
            println!(
                "  nostr_pubkey {}… already linked on target -> importing without it",
                &npub[..8.min(npub.len())]
            );
            nostr_pubkey = None;
            nostr_dropped = true;
        }
    }

    if !commit {
        return Ok(ImportOutcome::Created {
            username_dropped,
            nostr_dropped,
        });
    }

    let new_user = |username: Option<String>, nostr_pubkey: Option<String>| NewUser {
        username,
        pubkey_hash: Some(u.pubkey_hash.clone()),
        nostr_pubkey,
        wallet_birthday: u.wallet_birthday,
        seed_fingerprint: u.seed_fingerprint.clone(),
        xmr_start_height: u.xmr_start_height,
        wow_start_height: u.wow_start_height,
    };

    match target
        .create_user(new_user(username.clone(), nostr_pubkey.clone()))
        .await
    {
        Ok(_) => Ok(ImportOutcome::Created {
            username_dropped,
            nostr_dropped,
        }),
        Err(e) => {
            // A UNIQUE violation means a concurrent native onboarding won a race
            // (v0.3 runs alongside v0.2.x during the transition). If the identity
            // is now present it's a benign skip; otherwise a username/npub was
            // claimed out from under us — retry once with both dropped so the user
            // still imports (handle-less) instead of failing the whole row.
            if identity_present(target, u).await? {
                return Ok(ImportOutcome::Skipped);
            }
            if username.is_some() || nostr_pubkey.is_some() {
                target
                    .create_user(new_user(None, None))
                    .await
                    .map_err(|e2| e2.to_string())?;
                return Ok(ImportOutcome::Created {
                    username_dropped: username_dropped || username.is_some(),
                    nostr_dropped: nostr_dropped || nostr_pubkey.is_some(),
                });
            }
            Err(e.to_string())
        }
    }
}
