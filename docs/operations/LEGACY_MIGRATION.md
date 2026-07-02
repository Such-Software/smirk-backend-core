# Legacy (v0.2.x → v0.3) user migration

`smirk-admin migrate-legacy` imports **user identity** from a legacy v0.2.x Smirk
backend database into this v0.3 backend, so users keep their handle (and their
NIP-05 `name@your-domain`) when they move to a v0.3 client.

It exists because v0.3 is a fresh, clean, non-custodial backend with its own
database — nothing is shared with v0.2.x automatically. Funds are on-chain and
seed-derived, so they never need migrating; the only thing worth carrying is the
**identity** a user chose (their username) plus the small hints that make first
sync fast (wallet birthday, chain restore heights).

## What it migrates

Joined on the **`seed_fingerprint`** (`SHA256(SHA256(bip39_seed))`) — the one
identifier that is stable for the same human across both backends and across key
rotation:

| Column | Carried? | Why |
|---|---|---|
| `seed_fingerprint` | ✅ | the join key; lets a v0.3 login find the imported row |
| `pubkey_hash` | ✅ | so a **v3-derivation** wallet reclaims its row on the first `/auth/extension` with no rotation step |
| `username` | ✅ | the whole point — preserves `name@your-domain` (NIP-05) |
| `nostr_pubkey` | ✅ | preserves an already-linked Nostr identity; dropped only if that npub is already linked to a *different* v0.3 user (they re-link on v0.3) |
| `wallet_birthday`, `xmr_start_height`, `wow_start_height` | ✅ | bound the first chain scan |
| socials (telegram/discord/twitter/…) | ❌ | v0.3 identity is Nostr-native; there are no social columns to import into |
| tips / tip-links | ❌ | the v0.3 public backend has no tips subsystem |
| `user_keys` / `wallets` | ❌ | the v0.3 client re-registers these at v3 derivation on first unlock; importing legacy (possibly v1/v2) keys would just plant stale rows |

`pubkey_hash` and `seed_fingerprint` are **peppered at rest** by the DB layer, so
the importer builds its target connection with the real `SEED_FINGERPRINT_PEPPER`
— run it with the v0.3 server's own `.env` (see below), or the imported rows
won't match what the live server computes.

## How a user reclaims their row on first v0.3 login

- **v3-derivation users** (the common case, and all fresh wallets): the client
  sends the same `pubkey_hash`; `get_or_create_user_by_pubkey_hash` finds the
  imported row → **instant reclaim, username intact**.
- **v1/v2-derivation users**: their `pubkey_hash` differs, but the
  `seed_fingerprint` matches → v0.3's existing **key-rotation path** reclaims the
  row (the client signs with the old key). No data is lost either way; at worst a
  user briefly lands on a fresh row and re-picks a username.

## Running it

Prerequisites: shell access to the v0.3 host, the v0.3 `.env` (for
`DATABASE_URL` + `SEED_FINGERPRINT_PEPPER` + `ADMIN_KEY_INTEGRITY_SECRET`), and a
read path to the legacy Postgres database (same cluster is easiest).

```bash
cd /path/to/smirk-backend-core        # so .env is loaded and readable-only (chmod 600)

# 1. Dry run — reports exactly what WOULD be imported, no writes:
smirk-admin migrate-legacy --source-url 'postgres://USER:PASS@localhost/smirk_db'

# 2. Apply:
smirk-admin migrate-legacy --source-url 'postgres://USER:PASS@localhost/smirk_db' --commit
```

Flags:

- `--source-url <pg-url>` — the **legacy** database (read-only; never written).
- `--commit` — actually write. Omit for a dry run (the default).
- `--limit <n>` — import only the first `n` legacy users (useful for a staged test).

## Properties & safety

- **Read-only on the source.** The legacy DB is only `SELECT`ed.
- **Dry-run by default.** Nothing is written without `--commit`.
- **Idempotent / re-runnable.** A legacy user already present (matched by peppered
  `pubkey_hash` *or* `seed_fingerprint`) is skipped. Run it repeatedly during the
  transition and once more at cutover; already-migrated and already-on-v0.3-natively
  users are left untouched (never clobbered).
- **Username / npub collisions are non-fatal.** A legacy `username` that is
  reserved, malformed, or already taken — or a legacy `nostr_pubkey` already linked
  to a different v0.3 user — is dropped (reported), and the user is still imported
  without it. They re-pick a handle / re-link their npub on v0.3.
- **Users with no username or no `seed_fingerprint`** are still imported (matched
  later by `pubkey_hash`, the identity anchor). A legacy row with **no
  `pubkey_hash`** is skipped — there is nothing to anchor it to.
- **Best-effort per row.** A transient DB error or a concurrent native onboarding
  on one user is reported and skipped/reconciled — it never aborts the whole pass.
- **The source DB is trusted.** `pubkey_hash` / `seed_fingerprint` / `username` /
  `nostr_pubkey` are imported verbatim, so only point `--source-url` at your own
  v0.2.x database — never an untrusted dump.

## Transition strategy

Run v0.3 **alongside** v0.2.x (see the deployment notes). During the transition,
re-run `migrate-legacy` periodically so newly-active legacy users are present on
v0.3 before they upgrade their client; do a final pass at cutover; then retire the
legacy backend once its active users reach ~zero.

A reproducible end-to-end test of this flow lives in
[`scripts/test-legacy-migration.sh`](../../scripts/test-legacy-migration.sh).
