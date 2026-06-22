# smirk-backend-core

Open, self-hostable backend for the [Smirk](https://smirk.cash) non-custodial,
multi-chain wallet. It provides the chain-access and identity surface a Smirk
wallet needs — authentication, per-chain wallet access (Bitcoin, Litecoin,
Monero, Wownero, Grin), the Grin slatepack relay, and Nostr-based identity —
so anyone can run their own backend and a Smirk wallet can connect to it.

> **Status: early, under active development.** Interfaces and the database
> schema may change before the first tagged release. Not yet recommended for
> production self-hosting.

## What it is

- **Non-custodial.** The server never holds spend keys or seeds. It brokers
  access to blockchain data and relays wallet-to-wallet messages.
- **Open core, feature-flagged.** Every feature ships in this codebase and is
  toggled per deployment; the wallet reads `GET /api/v1/capabilities` and
  adapts to what a given backend offers.
- **Identity via "Sign in with Smirk".** Authentication uses a seed-derived
  Nostr key (NIP-98); the server stores only public keys.
- **Privacy first.** No PII is required to use it; operator and user privacy
  are explicit design goals.

## Architecture

Rust + [Axum](https://github.com/tokio-rs/axum), PostgreSQL via
[sqlx](https://github.com/launchbadge/sqlx). The public HTTP contract is
generated from the handlers with [utoipa](https://github.com/juhaku/utoipa)
(OpenAPI), which in turn drives the wallet's generated TypeScript client —
one source of truth, checked for drift in CI.

## Quickstart

```sh
cp .env.example .env        # then fill in DATABASE_URL, JWT_SECRET, node URLs
cargo run                   # starts the API server
```

A full self-hosting guide (node requirements, reverse proxy, Tor admin onion,
backups) will live in `docs/` as it stabilises.

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).
Do not open public issues for security reports.

## License

To be finalized (MIT vs AGPL-3.0-or-later). Until a `LICENSE` file is added,
all rights are reserved.
