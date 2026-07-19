# Nostr relay (messaging plane) — operator guide

The relay is **optional**. It gives your users a first-party, **locked-down**
Nostr relay that acts as their **encrypted-DM inbox** — the transport foundation
for messaging (and, later, P2P coordination). It is **off by default**; a Smirk
backend is fully functional without it.

## What it is (and isn't)

- **It is the user's inbox relay**, advertised via `/capabilities` and NIP-05
  relay hints, and **write-restricted** by policy (see below).
- **It is NOT the only relay.** For cross-wallet delivery (e.g. to/from Goblin or
  any Nostr user), clients also connect to the public interop relays
  (`relay.damus.io`, `nos.lol`). A private relay alone would black-hole DMs to
  outsiders — so the NIP-05 hints list your relay **first**, then the public set.
- The backend **does not run the relay process** — it *connects to + advertises*
  it and enforces the write policy. You run the relay (bundled or external).

## Architecture

```
wallet ──ws──▶ your relay (nostr-rs-relay) ──gRPC EventAdmit──▶ smirk-backend
                                                                (RELAY_WRITE_POLICY
                                                                 + NIP-13 PoW,
                                                                 registered-npub DB)
```

`nostr-rs-relay`'s `[grpc] event_admission_server` calls the backend once per
inbound event; the backend runs the pure policy engine (`src/infra/relay/policy.rs`)
against the user DB and returns PERMIT/DENY. This is dynamic (per-event, per-
recipient), which a static pubkey whitelist can't do.

## Write policies (`RELAY_WRITE_POLICY`)

| policy | who may publish |
| --- | --- |
| `inbox-outbox` (default) | registered npubs publish their own events (outbox); **anyone** may deliver a NIP-17 gift-wrap (kind 1059) **addressed to a registered user** (inbox) |
| `author-allowlist` | only registered Smirk npubs may publish anything (no external inbound) |
| `open` | accept everything (the relay's resource caps still apply) |
| `premium-post` | registered users post wallet-functional events (DMs, tips, swap coordination) free; **general** notes require an active premium subscription (see the premium tier below). This is the flagship monetized relay policy |

`RELAY_INBOUND_POW_BITS` (0 = off) requires a NIP-13 proof-of-work on
cross-ecosystem (non-registered-author) inbound events — spam friction without an
author allowlist. Only the `inbox-outbox` external-inbound branch is gated.

`RELAY_WRITE_ALLOWLIST_NPUBS` (comma-separated `npub1…` or 64-char hex; empty by
default) lists write-exempt npubs that may publish **any** kind regardless of the
write policy or premium status. The intended use is an announcements or
feed-owner account that seeds a `premium-post` feed without itself holding a
subscription. It is an exemption list, not the `author-allowlist` policy.

## Premium tier (`premium-post`)

The `premium-post` policy pairs with the premium subscription block
(`PREMIUM_ENABLED=true`, `PREMIUM_CURRENCY`, `PREMIUM_PLANS`) and the `PAYMENT_*`
processor. Wallet use stays free; premium unlocks general Nostr posting to your
relay. `Config::validate` fails closed if `PREMIUM_ENABLED` is set without
`RELAY_ENABLED=true`, `RELAY_WRITE_POLICY=premium-post`, the processor
credentials, and at least one priced `PREMIUM_PLANS` entry. Full design:
[../design/premium-relay.md](../design/premium-relay.md); ready-to-copy config:
the [`paid-relay`](../../examples/paid-relay/) recipe.

## Enable it

1. Set the relay env (see `.env.example` → *Nostr relay*):
   ```sh
   RELAY_ENABLED=true
   RELAY_MODE=bundled                    # or external
   RELAY_URL=wss://relay.yourdomain.tld  # what clients connect to (wss in prod)
   RELAY_WRITE_POLICY=inbox-outbox
   RELAY_INBOUND_POW_BITS=0
   RELAY_ADMISSION_BIND=127.0.0.1:8090   # loopback gRPC admission
   ```
   The backend fail-closes at startup on a bad relay config, and for any non-`open`
   policy it spawns the gRPC admission service on `RELAY_ADMISSION_BIND`.

2. **Bundled** (`RELAY_MODE=bundled`): run the reference `nostr-rs-relay` in
   [`deploy/relay/`](../../deploy/relay/):
   ```sh
   # set relay_url + event_admission_server in deploy/relay/config.toml first
   docker compose -f deploy/relay/docker-compose.yml up -d
   ```
   It uses host networking so the relay reaches the loopback admission socket
   while that socket stays private (Linux; see the compose comments for other
   hosts). Front `RELAY_URL` with your TLS terminator.

3. **External** (`RELAY_MODE=external`): point `RELAY_URL` at any relay you run,
   and configure *its* `[grpc] event_admission_server` at `RELAY_ADMISSION_BIND`.

## Verify

- `GET /capabilities` → `features.nostr_relay: true` and a `messaging` object
  (`relay_url`, `write_policy`, `inbound_pow_bits`, `supported_nips`).
- `GET /.well-known/nostr.json?name=<user>` lists your relay first in `relays`.
- Publish a registered-npub event → accepted; a random-author, non-gift-wrap
  event → rejected (`inbox-outbox`); an under-PoW cross-ecosystem event →
  rejected (when `RELAY_INBOUND_POW_BITS > 0`).

## Security notes (read before exposing a public relay)

- **The relay fails OPEN if admission is unreachable.** `nostr-rs-relay` treats an
  unreachable gRPC admission server as PERMIT. So a down/crashed admission service
  = an unrestricted relay. Two defences: (1) the backend **exits** if its admission
  service stops (so your supervisor restarts a clean pair — don't run them
  independently), and (2) run the relay + backend as one supervised unit so the
  relay isn't serving while admission is down. Pin the relay image to a **digest**,
  not `:latest` — the fail-open semantics can change across versions.
- **The admission socket is a registration oracle** (it answers "is this npub
  registered?"). It MUST stay loopback; `validate()` refuses a non-loopback
  `RELAY_ADMISSION_BIND` unless you set `RELAY_ADMISSION_ALLOW_PUBLIC=true` and
  firewall it yourself.
- **Default `RELAY_INBOUND_POW_BITS=0` has no spam friction.** Under `inbox-outbox`
  a `p` tag is public, so anyone can address gift-wraps to a registered user's
  inbox. A PUBLIC operator should raise the PoW bits (e.g. 8–16) to blunt inbox
  flooding; content is always encrypted, so this is a storage/spam concern, not a
  confidentiality one.
- **Clients verify the sender.** A gift-wrap's inner author is only trusted after
  the wallet checks the seal signature + `seal.pubkey == rumor.pubkey`, so a
  relay/sender cannot forge the displayed "from".

## Modularity

`nostr-rs-relay` is the first adapter behind the `RelayProvider` seam
(`src/infra/relay/`). The write policy lives in a pure engine; the gRPC transport
is the adapter's concern. A different relay (strfry, or another messaging
protocol) can enforce the same policy over a different mechanism without touching
the policy or the advertising.
