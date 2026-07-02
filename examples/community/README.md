# community — a members-only space for a project or group

Invite-only registration plus a relay that ONLY your registered members may publish
to (`author-allowlist`) — a members-only Nostr space with its own DM inbox.

- **Config:** [`.env.example`](.env.example) — `REGISTRATION_REQUIRE_INVITE=true`,
  `RELAY_ENABLED=true`, `RELAY_WRITE_POLICY=author-allowlist`.
- **Membership:** mint codes with `smirk-admin mint-invite`.
- **Relay:** you host member content — see [`../LEGAL_AND_OPS.md`](../LEGAL_AND_OPS.md).
