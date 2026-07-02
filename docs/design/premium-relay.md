# Spec — Premium relay access (recurring)

Status: **DRAFT / spec-first** · Owner: Such Software · Target: v0.4

## 1. Summary

A **premium tier**: registration and wallet use stay **free** (PoW-gated); an
optional **recurring fee** (e.g. $5 / quarter) grants **posting access to the
Smirk-operated Nostr relay**. This reframes payment from *pay-to-register* (a
one-time gate on wallet creation) to a *subscription* (a recurring gate on relay
writes). Everything else — register, unlock, balances, tip stats, receiving DMs,
posting to public relays — remains free.

This is the flagship **cookbook recipe** (`examples/paid-relay/`): the live,
dogfooded demonstration of operator monetization, built entirely on seams that
already exist (PaymentProvider + the relay admission engine).

## 2. Goals / non-goals

**Goals**
- Recurring revenue with real utility (relay posting), not a cosmetic badge.
- Compose from existing seams — no new architecture.
- Operator-configurable + advertised via `/capabilities`; self-hosting bypasses it.
- Rigorous: migration, OpenAPI, capabilities golden, unit + L2 + E2E tests.

**Non-goals (v1)**
- **Read-gating.** Reads stay open (or DM-reads via NIP-42 later). Paid relays
  conventionally gate *writes*; gating reads needs NIP-42 AUTH + a premium check
  and is a possible v2.
- **Auto-charge subscriptions.** Crypto has no card-on-file; premium is a
  **prepaid period** — the user re-pays each term or posting lapses. Honest + simple.
- **Fiat.** Uses the existing crypto PaymentProvider; fiat on-ramp is separate.

## 3. Model

The free tier includes everything that makes the **wallet** work — including
publishing **wallet-functional events** to our relay (encrypted DMs that ride with
tips, and future P2P atomic-swap coordination). Premium adds using our relay as a
**general-purpose Nostr relay** (notes, reactions, anything).

| Capability | Free | Premium |
|---|---|---|
| Register / unlock / use wallet (all chains) | ✅ | ✅ |
| Login, view tip/balance stats | ✅ | ✅ |
| Receive DMs (gift-wrap delivery to you) | ✅ | ✅ |
| Publish **wallet events** to the Smirk relay (encrypted DMs, tips, swap coordination) | ✅ | ✅ |
| Publish to **public** relays (damus, nos.lol…) | ✅ | ✅ |
| Publish **general Nostr** to the Smirk relay (kind-1 notes, reactions, …) | ❌ | ✅ while `premium_until > now` |

The value line: **the relay is free for what makes your wallet work; you pay to use
it as your everyday Nostr relay.** Free users are never cut off from wallet features.

## 4. Data model

Migration `..._premium.sql`:
```sql
ALTER TABLE users ADD COLUMN premium_until TIMESTAMPTZ;  -- NULL = never premium
CREATE INDEX users_premium_until_idx ON users (premium_until);
```
A **dedicated `premium_invoices` table** (not a `purpose` column on `payment_invoices`),
because premium binds on the authenticated `user_id` (a logged-in purchase) while
registration invoices bind on plaintext `pubkey_hash` — cleaner than a nullable
either-or. Columns: `invoice_id` PK, `user_id` FK (ON DELETE CASCADE), `provider`,
`plan_id`, `period_days`, `amount`, `currency`, `created_at`, `consumed_at`; a partial
`WHERE consumed_at IS NULL` index for the single-use lookup + a per-user pending cap.

DB fns (`infra/db/premium_invoices.rs` + `users.rs`):
- `is_premium_npub(nostr_pubkey) -> bool` — `SELECT EXISTS(... WHERE nostr_pubkey = $1 AND premium_until > NOW())` (npub is public → not peppered).
- `activate_premium(invoice_id, user_id, days) -> Option<premium_until>` — consume the
  single-use invoice AND extend `premium_until` in **one transaction** (so a mid-flight
  failure rolls the consume back and the paid invoice stays redeemable). Extends from
  `GREATEST(COALESCE(premium_until, NOW()), NOW())`, so early/longer renewals stack.
- `count_unconsumed_premium_invoices(user_id)` — bounds pending invoices per user.

## 5. Admission policy change

The pure engine (`infra/relay/policy.rs::decide`) classifies each event and gates on
**kind × membership**. A new `WritePolicy::PremiumPost` and an `author_premium` input:

- **Wallet-functional kinds are free for registered users.** Define `WALLET_KINDS` —
  the events that make the wallet + its peer features work: `1059` (NIP-59 gift-wrap /
  encrypted DMs, incl. tip + swap-coordination payloads), `10050` (NIP-17 DM relay
  list), and the tip / atomic-swap coordination kinds as those features define their
  on-Nostr shape. Extensible constant.
- **`PremiumPost` decision order** in the pure engine (first match wins). The
  `max_event_bytes` size cap is enforced in the `nauthz` adapter *before* the pure
  engine runs (fail-closed), so it is not a branch here:
  1. `author_premium` → **Permit** (any kind — the general-purpose relay).
  2. `author_registered` && `kind ∈ WALLET_KINDS` → **Permit** (free wallet use).
  3. `author_registered` (non-wallet kind, not premium) → **Deny** (premium required).
  4. external author → gift-wrap inbox delivery only (`kind == 1059` to a registered
     recipient, PoW-gated), else **Deny**.
- Existing `Open` / `AuthorAllowlist` / `InboxOutbox` unchanged.

`nauthz.rs::event_admit` passes the event `kind`, `is_registered_npub(author)`, and
the new `is_premium_npub(author)` into `decide`. Fail-closed on error (deny).

Config (`config.rs`): `RELAY_WRITE_POLICY=premium-post`; validate() keeps the
loopback-admission requirement (non-open policies need the admission service).

## 6. Payment flow (recurring + tiered, reuses the PaymentProvider seam)

- `POST /premium/invoice` (JWT auth), body `{ plan }` → mint an invoice for the
  selected plan's amount via the PaymentProvider, atomically bound to the caller with
  `purpose='premium'` and the plan's `days`. Returns the invoice (pay URL / address).
- Settle (pull model, same poller as pay-to-register): on a `premium` invoice
  settling, call `extend_premium(user_id, plan_days)` **once** (idempotent on invoice
  id). Never holds funds — pull-only.
- `GET /premium/status` (JWT auth) → `{ active, premium_until }`.

**Tiered plans (a discount feature we build + exercise).** `PREMIUM_PLANS` is a list
of `{ id, days, amount }`:

| id | days | price | vs. quarterly |
|---|---|---|---|
| `quarter` | 90 | $5 | — |
| `halfyear` | 182 | $9 | ~10% off |
| `year` | 365 | $15 | ~25% off |

The invoice endpoint validates `plan` against the configured list; `/capabilities`
advertises it so the client shows the tiers with the discount visible.
`extend_premium` stacks from `max(now, current_expiry)`, so buying early (or a longer
plan) just extends. Single shared `PREMIUM_CURRENCY`.

Config: `PREMIUM_ENABLED` (default false), `PREMIUM_CURRENCY`, `PREMIUM_PLANS`
(`id:days:amount` entries), reuses `PAYMENT_PROVIDER_*`. `validate()`:
`PREMIUM_ENABLED` ⇒ provider configured **and** `RELAY_ENABLED` **and**
`RELAY_WRITE_POLICY=premium-post` **and** ≥1 valid plan (fail closed otherwise).

## 6.5 Resource governance — the box is shared

The reference instance runs the relay **on the same box as the wallet backend and the
LWS scanners**, so the relay must stay within a budget and never starve them. A paid
base is naturally bounded (only paying users post general content), but we set hard
limits regardless:
- **Size + retention** — `RELAY_MAX_EVENT_BYTES` (64 KB) and `RELAY_RETENTION_DAYS`
  (30) cap storage; general (non-DM) content can carry a shorter retention than
  gift-wraps if needed.
- **Connection / subscription / rate limits** — cap max connections, subscriptions
  per connection, and ingest rate in the nostr-rs-relay config so a burst can't
  monopolize CPU / DB / bandwidth.
- **DB isolation** — the relay uses its own tables + retention job; the wallet
  backend's hot auth / LWS paths are untouched.
- **Watch + escape hatch** — the `paid-relay` recipe ships a suggested cap set and
  says: if relay load approaches the wallet backend's headroom, move the relay to its
  own box — the seam already supports `RELAY_MODE=external`.

## 7. Capabilities + OpenAPI

- `/capabilities`: `features.premium_relay: bool` + a `premium` object
  `{ currency, plans: [{ id, days, amount }], relay_url }` (present only when enabled),
  so the client renders the plan tiers with the discount visible. The client greys the
  **general-Nostr-posting** affordance unless `premium.active`; wallet events + DMs
  stay available free.
- OpenAPI: document `POST /premium/invoice` + `GET /premium/status`; the existing
  **OpenAPI no-drift check** must pass. Capabilities **golden test** updated to
  include `premium_relay` + `premium`.

## 8. Free ↔ premium enforcement points (defense in depth)

1. **Relay admission (authoritative):** the gRPC hook denies non-premium *general*
   writes to our relay regardless of client behavior (wallet events stay free). This
   is the real gate.
2. **Client UX:** reads `premium.active` from `/premium/status` and disables the
   affordance — a courtesy, never the enforcement.

The client is never trusted; a user who bypasses the UI still hits admission-deny.

## 9. Migration / compatibility

- Additive column; existing users get `premium_until = NULL` (free). No break.
- v0.2 backend unaffected. `PREMIUM_ENABLED=false` (default) → zero behavior change;
  `/premium/*` return 404/feature-off and `/capabilities` omits `premium`.
- The relay stays **off** until an operator opts in (`RELAY_ENABLED=true` +
  `premium-post`); `api.smirk.cash` enables it as the reference paid relay.

## 10. Testing (Ps and Qs)

- **Unit** — `policy.rs`: PremiumPost permit (premium author), deny (lapsed /
  non-premium), gift-wrap delivery to premium recipient, PoW on external inbound.
- **Unit** — `extend_premium` stacks from `max(now, current)`; `is_premium_npub`
  respects expiry (peppered lookup).
- **L2** — admission service: premium author PERMIT, lapsed author DENY.
- **L2** — settle handler: a `premium` invoice extends `premium_until` once (idempotent).
- **Golden** — capabilities includes `premium_relay` + `premium` when enabled, omits when off.
- **No-drift** — OpenAPI covers the two new endpoints.
- **E2E** — pay invoice → post to Smirk relay PERMITted → fast-forward past expiry
  → post DENIED → renew → PERMITted again.

## 11. Open questions

1. **Grace period** on expiry (e.g. 3-day soft window) vs hard cutoff? (Lean hard;
   `extend_premium` early-renewal stacking softens it.)
2. **Read-gating** (NIP-42) — defer to v2; note it in the cookbook recipe.
3. **Default price/period** for the reference instance — product call.
4. **Refunds** — none (prepaid access to a service); state in ToS/recipe README.

## 12. Cookbook tie-in

`examples/paid-relay/` = `PREMIUM_ENABLED=true` + `RELAY_ENABLED=true` +
`RELAY_WRITE_POLICY=premium-post` + open+PoW registration. Its README is the
operator playbook: pricing, the NCMEC/DMCA content posture (Terms §6/§9.1),
resource expectations, and the "reads open, writes paid" decision. See
[`examples/README.md`](../../examples/README.md).
