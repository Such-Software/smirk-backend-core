# Privacy Policy

The canonical Smirk privacy policy lives at **https://smirk.cash/privacy** and
describes the data practices of the instance operated by Such Software LLC
(api.smirk.cash).

## For operators who self-host

This backend is open source and self-hostable. **If you run your own instance, you
are an independent data controller for it** and the Such Software policy does not
speak for you. What your instance receives from wallets that connect to it:

- **Monero/Wownero view keys** (to scan for users' incoming funds; a view key
  cannot spend) and their scan/registration state.
- **Public addresses** for BTC/LTC balance lookups and **signed transactions** to
  broadcast. Recipient address and amount are not sent on broadcast.
- A one-way **seed fingerprint** (SHA-256) as a non-reversible wallet identifier.
- If enabled: the **username to npub** mapping published in your NIP-05 directory,
  and, for the relay, encrypted message envelopes (ciphertext only).
- IP addresses **never in raw form**. The per-IP rate limiter keeps its counters
  in memory, and the only IP-derived value written to disk is a salted one-way
  hash on `restore_attempts`, which the seed-restore abuse limiter reads back.
  Login events record no IP at all, and the raw-IP columns that older schemas
  carried on `sessions` and `audit_logs` were dropped in migration
  `20260722000001_privacy_drop_pii`. One exception, and it is about you rather
  than your users: the tamper-evident operator audit chain (`admin_audit_logs`)
  records the IP of privileged admin actions.

Private keys and seed phrases are never transmitted to the backend.

## Retention

Retention is enforced by the backend, not merely advertised. A background sweep
deletes `login_events` older than `RETENTION_LOGIN_EVENTS_DAYS` and `audit_logs`
older than `RETENTION_AUDIT_DAYS`, in bounded batches so a long-running instance
drains its backlog without stalling writers. Setting either knob to `0` means
keep indefinitely, so an unset value never destroys data by surprise.

The `admin_audit_logs` chain is deliberately exempt: it is hash-chained and
MAC'd, so a deleted row reads as tampering to the verifier. Prune it on purpose
if your policy calls for it.

Self-service erasure (`ERASURE_ENABLED`) is separate and user-initiated: a
confirmed request deletes the account and its owned rows after a grace window,
purging or anonymizing that user's login events per `ERASURE_PURGE_LOGIN_EVENTS`.

If you offer your instance to others, publish your own privacy policy describing
how you handle this data, your retention, and your jurisdiction. The knobs that
affect retention and data exposure (login-event and audit retention, erasure,
relay retention, landing-page exposure) are documented in
[docs/operations/CONSOLE.md](docs/operations/CONSOLE.md) and the root `.env.example`.
