# Operator cookbook

`smirk-backend-core` is one binary with **composable knobs** — registration gates
(PoW / invite / pay-to-register), an optional Nostr relay with a configurable write
policy, restore policy, and per-feature flags. This directory turns those knobs into
**ready-to-run recipes**, one per operator persona.

Each recipe is a directory with:
- **`.env.example`** — the tuned config (only the lines that differ from defaults are
  called out; copy the full `../../.env.example` and apply the deltas).
- **`README.md`** — what it's for, what it costs to run, the legal/operational notes.

> **Status.** `personal/`, `public-free/`, and `paid-relay/` (the flagship — it
> uses the shipped [premium-relay feature](../docs/design/premium-relay.md)) have
> full `.env.example`s. `friends/`, `paid-access/`, and `community/` are summarized
> below and get their own directories on the next pass.

## Every recipe, the same three steps
1. `cp ../../.env.example .env`, then apply the recipe's deltas.
2. Generate each secret: `openssl rand -hex 32` (`JWT_SECRET`, `SEED_FINGERPRINT_PEPPER`,
   `REFRESH_TOKEN_PEPPER`, `IP_SALT`, `ALTCHA_HMAC_KEY`, `ADMIN_*_SECRET`). Fill chain
   endpoints. `chmod 600 .env`.
3. Run the binary (migrations apply on boot). Reverse-proxy TLS; bind the API to
   `127.0.0.1`.

**Non-custodial in every recipe** — the backend never holds seeds, spend keys, or
funds. **Self-hosting bypasses every gate.** Secrets are never committed.

## The menu

| Recipe | For | Registration | Relay | Pitch | Status |
|---|---|---|---|---|---|
| [`personal/`](personal/) | Just you | open, no gate | off (or open, just you) | Your own sovereign backend | ✅ boots today |
| [`public-free/`](public-free/) | A free public instance | **open + PoW** | off (v1) | What `api.smirk.cash` runs | ✅ boots today |
| `friends/` | Your circle | **invite-only** | on, `inbox-outbox` | A backend for people you trust | 📝 2nd pass |
| `paid-access/` | A paid wallet service | **pay-to-register** | optional | Charge once for a hosted wallet backend | 📝 2nd pass |
| `paid-relay/` | Monetize a relay | **open + PoW** (free wallet) | on, **`premium-post`** | Free wallet, paid ($/quarter) Nostr posting | ✅ premium-relay shipped |
| `community/` | A project/DAO space | invite | on, `author-allowlist` | A gated relay for a named group | 📝 2nd pass |

## Recipe summaries (config deltas)

- **`personal`** — `POW_REQUIRED=false`, all registration gates off,
  `WALLET_RESTORE_POLICY=unlimited`, `RELAY_ENABLED=false` (or on, just for you),
  `ADMIN_ENABLED=false`. Minimal footprint; you are the only user.
- **`public-free`** — `POW_REQUIRED=true`, gates off, `WALLET_RESTORE_POLICY=bounded`
  + PoW-priced, `FEATURE_PRICES=true`, `FEATURE_TIPS=false`, `RELAY_ENABLED=false` at
  launch. Open to all, spam-gated by compute.
- **`friends`** — `REGISTRATION_REQUIRE_INVITE=true` (mint with
  `smirk-admin mint-invite`), `RELAY_ENABLED=true` + `RELAY_WRITE_POLICY=inbox-outbox`,
  `WALLET_RESTORE_POLICY=unlimited`. Hand out codes; run a locked-down relay for the group.
- **`paid-access`** — `REGISTRATION_REQUIRE_PAYMENT=true` + `PAYMENT_*` (a BTCPay-compatible
  processor paying *your* wallet). A one-time access fee gates wallet creation. Non-custodial;
  you never touch funds (pull-model invoice reads only).
- **`paid-relay`** — free wallet (open + PoW) **plus** `PREMIUM_ENABLED=true`,
  `RELAY_ENABLED=true`, `RELAY_WRITE_POLICY=premium-post`, `PREMIUM_AMOUNT` /
  `PREMIUM_CURRENCY` / `PREMIUM_PERIOD_DAYS`. Recurring revenue for relay posting; reads
  open (v1). **Content posture:** running a relay carries user content — see the NCMEC/DMCA
  clauses in the published Terms (§6, §9.1). Spec: [premium-relay](../docs/design/premium-relay.md).
- **`community`** — `REGISTRATION_REQUIRE_INVITE=true`, `RELAY_ENABLED=true` +
  `RELAY_WRITE_POLICY=author-allowlist` (only your registered members publish).

## Choosing

- Want **freedom**? `personal` (or `friends` for a group).
- Want a **free public good**? `public-free`.
- Want it to **pay for itself**? `paid-relay` (recurring, real utility) or `paid-access`
  (one-time). `paid-relay` is the flagship — recurring revenue tied to a service people
  actually value, and the live demo runs at `api.smirk.cash`.
