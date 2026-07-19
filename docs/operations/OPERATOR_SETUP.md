# Operator setup

Deploy a `smirk-backend-core` instance. It holds no seed and no spend key; it
forwards view credentials to your chain backends per request and relays signed
bytes. Run your own for full privacy.

## Prerequisites

- Rust (stable) and PostgreSQL 14+.
- A chain backend for each chain you enable (all optional, feature-flagged):
  - Bitcoin / Litecoin — an Electrum/Fulcrum server (your own, or public).
  - Monero / Wownero — a light-wallet-server (LWS) and a daemon.
  - Grin — grin-wallet (owner/foreign API) and a grin node.
- A reverse proxy terminating TLS in front of the public port (production).

## 1. Database

```sh
createdb smirk_backend_core     # or point DATABASE_URL at an existing database
```

Migrations run automatically on first start.

## 2. Secrets and configuration

```sh
cp .env.example .env
```

Generate each required secret with `openssl rand -hex 32`:

- `JWT_SECRET`, `SEED_FINGERPRINT_PEPPER`, `REFRESH_TOKEN_PEPPER`, `IP_SALT` — always required.
- `ADMIN_JWT_SECRET`, `ADMIN_KEY_INTEGRITY_SECRET` — required when `ADMIN_ENABLED=true`. Back up `ADMIN_KEY_INTEGRITY_SECRET`; losing it locks out admin.

Then set:

- `DATABASE_URL` — the database from step 1.
- `PUBLIC_API_URL` — the public absolute base URL, e.g. `https://backend.example.org/api/v1`. It is the canonical value NIP-98 tokens bind (never the request `Host`), and is required for Nostr identity and erasure.
- `ENVIRONMENT=production` — enforces HTTPS on external URLs and rejects placeholder secrets.

The server fails closed: it refuses to start on a missing or weak secret, or an
inconsistent feature configuration. `.env.example` documents every key.

## 3. Chain backends

Enable a chain with its `FEATURE_*` flag and configure its source. A chain whose
flag is on but whose source is unconfigured reports `enabled: false` via
`/capabilities` instead of failing at call time.

| Chain | Keys |
|-------|------|
| BTC / LTC | `{BTC,LTC}_ELECTRUM_URL` (primary) and `{BTC,LTC}_ELECTRUM_FALLBACKS` (comma-separated). `ssl://` / `tls://` verify TLS with hostname checking; `tcp://` is plaintext (LAN only). Primary is tried first, then fallbacks in random order. |
| XMR / WOW | `{XMR,WOW}_LWS_URL`, `{XMR,WOW}_LWS_ADMIN_URL`, `{XMR,WOW}_LWS_ADMIN_KEY`, `{XMR,WOW}_DAEMON_URL`. |
| Grin | `GRIN_OWNER_API_URL` + `GRIN_OWNER_API_SECRET`, `GRIN_WALLET_PASSWORD`, `GRIN_FOREIGN_API_URL`, and the node's `GRIN_NODE_*`. |

## 4. Run

```sh
cargo run --release       # or run the built ./target/release/smirk-backend-core
```

Verify:

```sh
curl -s localhost:8080/health
curl -s localhost:8080/api/v1/capabilities    # enabled chains, features, restore + registration policy
```

## 5. First admin (optional)

Admin functions — key management, erasure, tamper-evident audit — run on a
separate loopback listener; the public API needs no admin. To enable it, set
`ADMIN_ENABLED=true` and the two admin secrets, then bootstrap with **one** of
two mutually-exclusive first-run commands:

```sh
# A) You already have a Sign-in-with-Smirk (Nostr) key — seed its pubkey (active now):
smirk-admin setup --pubkey <x-only-hex>    # seed the first admin + latch the bootstrap

# B) You want the CLI to generate a key — writes the secret 0600, registers it
#    PENDING, and latches in one step (no `setup` needed):
smirk-admin create-admin-wallet --out admin-key.hex

smirk-admin doctor                         # database, live keys, audit chain
```

`<x-only-hex>` is the admin's Sign-in-with-Smirk (Nostr) public key; the admin
authenticates with the matching key over NIP-98. Both commands latch the
bootstrap, so run **only one** — after either, the other is refused by design (a
live admin key already exists). With (B) the generated key is *pending* and
activates on the holder's first NIP-98 login; import `admin-key.hex` into your
signer and log in. If you lose that secret before the first login, re-run
`create-admin-wallet` (adds a fresh key) and `revoke-key` the stale one.

The bootstrap latch is MAC-protected and one-way — a live deployment is adopted
as already-bootstrapped, and tampering fails closed (the CLI and the boot path
both refuse a tampered latch; run `reset-setup --i-understand` to re-open setup).

Expose the admin plane over a Tor onion or an SSH tunnel; never bind it to a
public interface. `ADMIN_BIND` defaults to loopback, and a non-loopback bind
requires an explicit `ADMIN_ALLOW_PUBLIC_BIND=true`.

- **SSH tunnel:** `ssh -L 8081:127.0.0.1:8081 you@server`, then reach the plane at
  `http://127.0.0.1:8081`. The loopback Host passes the admin allowlist with no
  extra config.
- **Tor onion:** point a hidden service at `127.0.0.1:8081` and set
  `TOR_ADMIN_ONION=<hash>.onion`. That onion host is added to the admin Host
  allowlist; without it, a request whose `Host` header is the onion is rejected
  (`403`), because the allowlist only accepts loopback names plus the one
  configured onion (anti DNS-rebinding).

The Operator Console (an embedded admin SPA served at `/admin` on this same
plane) gives you a browser front end for keys, invites, status, and the runtime
config overlay. See [CONSOLE.md](CONSOLE.md).

## 6. Registration policy (optional)

Gates are composable and advertised via `/capabilities`; returning wallets and
self-hosting bypass them. All default off or open.

- **Invite codes** — `REGISTRATION_REQUIRE_INVITE=true`; mint with `smirk-admin mint-invite --count <n>`.
- **Proof-of-work** — `FEATURE_POW=true`, `POW_REQUIRED=true`, `ALTCHA_HMAC_KEY`.
- **Restore policy** — `WALLET_RESTORE_POLICY=create-only|bounded|unlimited` (default `create-only`), with optional proof-of-work pricing on restore depth.
- **Pay-to-register** — `REGISTRATION_REQUIRE_PAYMENT=true` against a BTCPay-compatible processor (`PAYMENT_*`); a new wallet settles an invoice, paid to your own wallet, before it can register.

## 7. Nostr relay (optional)

Run a first-party, locked-down Nostr relay as your users' encrypted-DM inbox
(`RELAY_ENABLED=true` + `RELAY_*`). Off by default; write-restricted via a gRPC
admission service, advertised through `/capabilities` + NIP-05. Full guide:
[RELAY.md](RELAY.md).

## Testing an instance

The `@smirk/smoke-tests` harness drives the API client end-to-end. Point it at an
instance with `SMOKE_BACKEND_URL`, and set `SMOKE_API_STYLE=namespaced` — this
backend serves namespaced `/wallet/utxo/*` routes, not the legacy flat paths:

```sh
SMOKE_BACKEND_URL=https://backend.example.org/api/v1 SMOKE_API_STYLE=namespaced \
  npm run check-balance -w @smirk/smoke-tests
```
