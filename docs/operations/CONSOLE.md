# Operator Console: admin surface guide

The Operator Console is an embedded single-page app served at `/admin` on the
backend's loopback admin plane. It is the browser front end for the same admin
JSON API the `smirk-admin` CLI complements: sign in with your admin key, review
status, manage admin keys and invite codes, and edit the runtime config overlay.

The console ships inside the binary (built from `admin-ui/` and embedded at
compile time), so self-hosting needs no separate front-end deploy. It is off
unless the admin plane is enabled.

## 1. Enable and reach the admin plane

The admin plane is a separate listener from the public API; confidentiality is by
socket, not by middleware ordering. It never joins the public router or the
OpenAPI surface.

Enable it in your `.env`:

```sh
ADMIN_ENABLED=true
ADMIN_BIND=127.0.0.1:8081                 # loopback by default
ADMIN_PUBLIC_URL=https://admin.example.org
ADMIN_JWT_SECRET=<openssl rand -hex 32>
ADMIN_KEY_INTEGRITY_SECRET=<openssl rand -hex 32>   # back this up; losing it locks out admin
```

`ADMIN_BIND` defaults to loopback. Boot refuses a non-loopback bind unless you
also set `ADMIN_ALLOW_PUBLIC_BIND=true`, so the plane cannot be exposed on a
public interface by accident. Never bind it to a public address; reach it one of
two ways instead:

- **SSH tunnel.** `ssh -L 8081:127.0.0.1:8081 you@your-server`, then open
  `http://127.0.0.1:8081/admin` in your local browser. Because the Host is
  `127.0.0.1`, the admin plane's Host allowlist accepts it with no extra config.
- **Tor onion service.** Point a hidden service at `127.0.0.1:8081` and set
  `TOR_ADMIN_ONION=<hash>.onion`. The onion host is added to the admin Host
  allowlist; without `TOR_ADMIN_ONION`, a request whose `Host` header is the
  onion is rejected with `403` (the allowlist defends the loopback socket against
  DNS rebinding, and only loopback names plus the one configured onion pass).
  Then browse `http://<hash>.onion/admin` in Tor Browser.

The console shell (`GET /admin`, `/admin/`, `/admin/assets/*`) is served
unauthenticated: it loads without a session and runs the login client-side. Every
JSON route it calls (`/admin/keys`, `/admin/config`, `/admin/invites`, ...) is
guarded, so serving the shell openly exposes nothing.

### `ADMIN_PUBLIC_URL` is the per-node identity

`ADMIN_PUBLIC_URL` is the value your wallet's signed action binds against (the
NIP-98 `u` tag), and a per-node id is derived from it so a challenge signed for
one node cannot be replayed to another node in a fleet. Give each node in a fleet
a distinct `ADMIN_PUBLIC_URL`. The server dictates and verifies this value from
config, never from the request `Host` header, so the value you reach the plane at
(loopback, tunnel, onion) does not have to equal `ADMIN_PUBLIC_URL`.

## 2. Sign in with your admin key

Login is a NIP-98 signed action ("Sign in with Smirk"): you prove control of your
admin private key by signing a single-use, server-issued challenge with your
Smirk wallet. Only admin public keys are ever stored; the server never holds an
admin seed or private key.

1. Bootstrap a first admin key if you have not already (see
   [OPERATOR_SETUP.md](OPERATOR_SETUP.md) section 5): `smirk-admin setup --pubkey
   <x-only-hex>` seeds your pubkey active, or `smirk-admin create-admin-wallet`
   generates a pending key that activates on its first login.
2. Open the console and start login. It calls `POST /admin/auth/challenge`, which
   returns a nonce, the `u` URL to bind, and the instance id.
3. Sign the kind-27235 (NIP-98) challenge event with the Smirk wallet holding your
   admin key. The console posts it to `POST /admin/auth/verify`.
4. On success you receive an admin access token plus a refresh token, and the
   console loads the authenticated tabs. A pending key activates on this first
   login.

Every admin-auth rejection (bad signature, a valid signature for a non-admin key,
a missing session) collapses to the same opaque `401`, so the surface is not an
enumeration oracle. Login and privileged actions are written to a hash-chained,
tamper-evident audit trail.

## 3. Console tabs

- **Status**: the effective feature/capability view, including any downgrades
  (a flag that is on in config but serving as disabled because its secret or URL
  is unset, e.g. `xmr` on with `XMR_LWS_ADMIN_KEY` empty).
- **Keys**: add, list, revoke, and rotate admin keys. A new key is added pending
  and activates on its holder's first login. Revoking the last live key over the
  network is refused (use the CLI); rotate is allowed on a solo key because it is
  add-plus-revoke, the in-band recovery for a compromised sole key.
- **Invites**: mint single-use invite codes (`POST /admin/invites`) and list
  them (`GET /admin/invites`). Raw codes are shown once; only their hash is
  stored.
- **Config**: the runtime config overlay editor (below).

## 4. Config: the env-vs-DB precedence model

Effective config is layered:

```
defaults  ->  environment (.env)  ->  DB overlay (operator settings)  ->  validate
```

The DB overlay is a sparse, per-section patch stored in the `operator_settings`
table, one MAC'd row per section. A field present in the overlay overrides env for
that field; an absent field keeps its env (or default) value. `GET /admin/config`
returns, for every editable field, its effective value, the DB overlay, the
per-section version, its runtime class, and whether a restart is pending. So the
console can show each field's current value and whether its source is env/default
or the DB overlay.

Editing goes through `PUT /admin/config` with a sparse patch. The patch is merged
onto the persisted overlay and re-run through the exact same `Config::validate`
that boot uses, so a bad edit is rejected with the identical error boot would
raise and nothing invalid is ever persisted or applied. Secrets are excluded from
the editable surface by construction: no overlay field maps to a secret (JWT
secrets, peppers, the ALTCHA HMAC key, the payment processor API key, the relay
admission bind), so the console can neither read nor set one. Secrets stay in env.

The nine editable sections are: `landing`, `retention`, `restore`, `console`,
`registration`, `pow`, `features`, `relay`, `premium`.

### Runtime-safe vs restart-required fields

Each field is classified as runtime-safe (the change hot-swaps onto the live
config and takes effect on the next request) or restart-required (the change is
persisted and applied on the next graceful restart, because a boot-built client,
socket, or worker captured the old value). The classification is the single
source of truth in `runtime_class()` and is returned per field by
`GET /admin/config`. The exact classification:

| Section | Class | Notes |
| --- | --- | --- |
| `landing.*` | runtime-safe | read per request on the landing/render path |
| `retention.*` | runtime-safe | **except** `retention.erasure_enabled` |
| `retention.erasure_enabled` | restart-required | gates a boot-spawned erasure sweep worker |
| `restore.*` | runtime-safe | restore policy is read per request |
| `console.*` | runtime-safe | `restart_apply_mode` is read at save time |
| `registration.*` | runtime-safe | **except** `registration.require_payment` |
| `registration.require_payment` | restart-required | gates the boot-built payment client (the provider is `None` at boot unless payment or premium is on) |
| `pow.*` | runtime-safe | the PoW gate is read per request |
| `features.*` | restart-required | every field: feature flags and per-chain enablement gate boot-built clients/workers (price poller, chain adapters) |
| `relay.*` | restart-required | the relay/admission service is boot-bound and the URL is advertised at boot |
| `premium.*` | restart-required | premium is enforced by the boot-bound relay admission service |

Any `(section, field)` not listed defaults to restart-required, the safe default:
never hot-swap something whose consumers have not been reasoned about.

A `PUT` that touches only runtime-safe fields hot-swaps just that patch onto the
running config and reports `applied: "runtime"`. A `PUT` that touches any
restart-required field persists the change and reports `applied:
"restart-required"` with `restart_pending: true`. `restart_pending` stays true
until a restart applies it, and it reflects any restart-required change saved by
an earlier `PUT`, even when the current edit was itself live.

### Optimistic concurrency (`expected_versions`)

Each section carries a version that increments on every write. To guard against
two operators editing at once, send `expected_versions` in the `PUT` body with the
version you last read per touched section. If the stored version has moved on, the
write is rejected with `409 Conflict` and nothing is persisted; reload and retry.
Omitting `expected_versions` skips the check (last write wins).

### `restart_apply_mode`: manual vs auto

`console.restart_apply_mode` (env `RESTART_APPLY_MODE`, default `manual`) decides
how a restart-required change is applied:

- `manual` (default): the change is persisted and flagged `restart_pending`. You
  apply it yourself with a graceful restart of the service.
- `auto`: after saving a restart-required change, the instance self-restarts
  shortly after responding so the change takes effect. The console warns before
  saving in this mode.

Auto mode REQUIRES the service to be brought back on exit. The self-restart is a
graceful shutdown (it drains in-flight requests and exits); nothing relaunches the
process on its own. Run under systemd with `Restart=always` (or an equivalent
supervisor) so the instance comes back with the new config applied. Without that,
`auto` takes the instance down and leaves it down. Do not use `auto` for a
process you start by hand.

### Clearing a DB override to fall back to env

The overlay is stored per section, and a value you set through the console is a DB
override that wins over env for that field. Note the behavior in this version:

- There is no per-field null clear. A `null` in a `PUT` patch means "leave this
  field unchanged" and is skipped, so sending `null` does not remove an existing
  override.
- To make a field's effect match env again, set it back through the console to the
  same value env provides. The effective value then equals env, though the field's
  source still reports `db`.
- `landing.title` is the one special case: setting it to an empty string clears it
  back to the env value (unset).
- To fully drop a section's DB overlay so its source returns to env/default (and
  future env edits for that section flow through again), delete that section's row
  from the `operator_settings` table and restart, for example:

  ```sql
  DELETE FROM operator_settings WHERE section = 'landing';
  ```

  On load, any section whose row is absent, whose MAC fails, or which fails to
  decode is ignored and falls back to env, fail-closed on tamper and
  fail-open-to-env on a missing section. There is no console/API/CLI command to
  clear a section in this version; the direct table delete is the supported path.

## 5. Reserved / inert config

- `ADMIN_PUBKEYS` is parsed from the environment but is NOT consumed anywhere in
  this version: it does not gate admin access. Admin authorization is the
  MAC-protected key allowlist in the database (managed via `smirk-admin` and the
  Keys tab), never this variable. Treat `ADMIN_PUBKEYS` as reserved and leave it
  unset; setting it has no effect and does not grant access.

## Related

- [OPERATOR_SETUP.md](OPERATOR_SETUP.md): full deployment and admin bootstrap.
- [RELAY.md](RELAY.md): the optional Nostr relay messaging plane.
- The root [`.env.example`](../../.env.example) documents every environment key.
