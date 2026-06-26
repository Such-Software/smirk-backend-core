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
//!                                              secret 0600; registers the pubkey)
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

use smirk_backend_core::infra::db::{AddKeyOutcome, Database, RevokeKeyOutcome};
use smirk_backend_core::models::db::{NewAdminAudit, NewAdminKey};

const USAGE: &str = "\
smirk-admin — break-glass admin CLI

USAGE:
    smirk-admin <COMMAND> [FLAGS]

COMMANDS:
    list-keys
    add-key             --pubkey <64hex> [--label <s>]
    revoke-key          --id <uuid>
    replace-key         --old <uuid> --pubkey <64hex> [--revoke-all]
    create-admin-wallet --out <path>
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
        "list-keys" => list_keys(&db).await,
        "add-key" => add_key(&db, &secret, rest).await,
        "revoke-key" => revoke_key(&db, &secret, rest).await,
        "replace-key" => replace_key(&db, &secret, rest).await,
        "create-admin-wallet" => create_admin_wallet(&db, &secret, rest).await,
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

    // Register the PUBLIC key only.
    match db
        .create_admin_key_audited(
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
        AddKeyOutcome::Created(_) => {}
        AddKeyOutcome::CapReached => return Err("unexpected: cap reached".into()),
    }

    println!("generated admin key; secret written to {out} (mode 0600)");
    println!("pubkey: {pubkey}");
    println!("import the secret into your NIP-98 signer; it activates on first login");
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
