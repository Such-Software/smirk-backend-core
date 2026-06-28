# smirk-backend-core

Open, self-hostable backend for the [Smirk](https://smirk.cash) non-custodial
multi-chain wallet. Rust + Axum + PostgreSQL.

It gives a wallet chain access (balances, history, UTXOs, spend inputs, fee
estimation, broadcast), Nostr-native identity, a fiat price feed, and an async
Grin slatepack relay — **without ever holding a spend key or seed**. Run your
own; the wallet is backend-agnostic.

> **Status:** v0.3.0 — feature-complete and security-reviewed, but young. The
> schema/API may still evolve. Run your own chain backends where you can, review
> the code, and treat early deployments accordingly.

## Non-custodial by construction

The server stores **public addresses, public keys, and (for Monero/Wownero)
incoming view keys only** — never a spend key, never a seed. View credentials are
**forwarded per request** to the chain backends that scan with them and are not
persisted here. The wallet signs and broadcasts locally; the backend reads chains
and relays bytes.

## Chains

| Chain | Source | Notes |
|-------|--------|-------|
| Bitcoin, Litecoin | Electrum / Fulcrum | reads, fee estimation, broadcast |
| Monero, Wownero | light-wallet-server (LWS) | stateless view-key forwarding |
| Grin | grin-wallet (view-only) + node | `rewind_hash` scan, broadcast, slatepack relay |

Each chain is independently feature-flagged; a chain whose source isn't configured
is reported `enabled: false` by `/capabilities` rather than failing at call time.

## API

The HTTP contract is generated from the handlers and committed to
[`openapi.json`](openapi.json) — the single source of truth for the API and the
wallet's generated client. A CI gate fails the build on any drift.

Public surface (`/api/v1`):

- **Identity & auth** — NIP-98 (Nostr) sign-in + link, wallet-signature auth,
  audience-separated JWT sessions, NIP-05 directory (`/.well-known/nostr.json`).
- **Chain access** — per-chain balance / history / UTXOs / spend inputs / fee /
  broadcast.
- **Grin relay** — non-custodial store-and-forward mailbox for interactive Grin
  transfers (feature-flagged).
- **Capabilities** (`/capabilities`) — what this instance enables, so the wallet
  adapts per-instance.
- **Prices** (`/prices`) — cached fiat feed, per-feed operator control.
- **Self-service erasure** (`/account/erasure`, `/account/export`) — action-bound,
  two-phase delete-my-data + export.
- **Health** (`/health`) and an optional, default-off public landing (`/`).

## Operator surface

Operator/admin functions live on a **separate loopback listener** (front it with
Tor or an SSH tunnel) — confidentiality by socket, never merged into the public
router or OpenAPI.

- **Sign-in-with-Smirk admin auth** — a NIP-98 *signed action* over a single-use
  nonce (AUTHN) + a MAC-protected key allowlist (AUTHZ), composed so a route can't
  run without both.
- **First-run bootstrap** — an explicit, MAC-protected latch (no trust-on-first-
  use); a live deployment adopts as already-bootstrapped; tampering fails closed.
- **`smirk-admin` CLI** — break-glass key management, `create-admin-wallet`
  (zeroized), `doctor`. Talks to Postgres directly, bypassing the network plane.
- **Tamper-evident audit** — privileged actions are written to a hash-chained
  audit trail, fail-closed (the state change rolls back if the audit write fails).

## Running it

Requires Rust (stable) and PostgreSQL.

```sh
cp .env.example .env          # then edit: DATABASE_URL + the required secrets
createdb smirk_backend_core   # or point DATABASE_URL at an existing database
cargo run --release           # migrations run automatically on startup
```

The server **fails closed**: it refuses to start on a missing/weak secret or an
inconsistent feature configuration rather than booting with a control silently
defeated. Generate secrets with `openssl rand -hex 32`. See
[`.env.example`](.env.example) for the full, documented configuration surface.

First admin (headless — the supported bootstrap):

```sh
smirk-admin create-admin-wallet --out admin.secret  # generates a key, registers the pubkey
# import admin.secret into your NIP-98 signer; it activates on first admin login
```

## Security posture

- **Fail-closed configuration** — the only place that reads the environment;
  validates secrets (length + placeholder checks) and feature consistency at boot.
- **Identity at rest is peppered** — `pubkey_hash` / `seed_fingerprint` are stored
  as HMACs, so the database is not a seed-existence oracle or a cross-instance
  linker.
- **Strict JWTs** — HS256 pinned, zero leeway, audience-separated; admin tokens
  are cryptographically distinct from user tokens.
- **Bounded, hardened upstream I/O** — TLS with hostname verification, streaming
  size caps, and per-request timeouts on every external call.
- **Adversarially reviewed** — every security-critical subsystem was built clean
  (never ported) and put through a multi-agent adversarial review before landing.

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Please do not
open public issues for security reports.

## Testing

```sh
cargo test                                        # unit + doc tests (no database needed)
TEST_DATABASE_URL=postgres://… cargo test --tests # + L1 integration against Postgres
```

Integration tests self-skip when `TEST_DATABASE_URL` is unset. They use only
deterministic, non-sensitive test secrets and ephemeral identities — never a
funded or otherwise sensitive wallet seed.

## License

[MIT](LICENSE) © Such Software LLC — run it, embed it, modify it. Built for interop.
