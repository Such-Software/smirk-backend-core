# friends — a backend for a known group

Invite-only registration plus a locked-down relay (`inbox-outbox`) so your circle
has a private DM inbox. No payment; generous restore.

- **Config:** [`.env.example`](.env.example) — `REGISTRATION_REQUIRE_INVITE=true`,
  `RELAY_ENABLED=true`, `RELAY_WRITE_POLICY=inbox-outbox`.
- **Invites:** mint codes with `smirk-admin mint-invite --count <n>` and hand them out.
- **Relay:** you host user messages — review the content notes in
  [`../LEGAL_AND_OPS.md`](../LEGAL_AND_OPS.md).
