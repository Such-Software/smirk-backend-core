# Backend builds and candidate provenance

> Status: implemented, enrollment pending · Updated: 2026-09-27 · Applies to: backend maintainers and release operators

GitHub `Such-Software/smirk-backend-core` remains canonical source. Gitea
`Builds/smirk-backend-core` is private CI and candidate ingress. A workflow file
in source does not prove that the repository, runner, branch protection or
required status has been enrolled. Those are reviewed Fleet operations.

`.gitea/workflows/ci.yml` owns the fundless backend gate: formatting, strict
Clippy, every integration target with disposable PostgreSQL, documentation
tests, generated OpenAPI and embedded-console agreement, redacted credential
scanning and dependency policy. Its final gate refuses failed, skipped or
cancelled mandatory jobs. GitHub Actions is not the build authority.

`tools/ci-fundless.sh` creates a temporary PostgreSQL cluster with a private Unix
socket and no TCP listener. It never accepts a database URL or a test-command
override, refuses a local `.env`, supplies `TEST_DATABASE_URL`, and removes its
cluster on exit. Without a database, ordinary `cargo test` can skip integration
targets and is not equivalent evidence. Tests use only unfunded fixtures.

## Private Linux candidate

`.gitea/workflows/backend-build.yml` accepts only the required `expected_sha`
input. The reviewed Fleet dispatcher verifies the admitted canonical GitHub
commit before dispatch. The workflow checks out that exact Builds commit and
requires a two-parent merge wrapper with a tree identical to its second parent.
That parent is recorded as canonical source. It is fetched from the declared
GitHub repository; an arbitrary tree with different ancestry is refused.

The workflow builds with Rust 1.98.0 in a digest-pinned Debian 12 container.
`tools/stage-backend-candidate.py` refuses an unexpected binary architecture,
missing GNU libc evidence, or a binary requiring GNU libc newer than 2.36.
The private artifact contains the executable and `manifest.json`, which records
source and Builds commits, source tree, workflow and lockfile digests, compiler,
target, GNU libc requirements, executable digest and size. Artifact identity is
`smirk-backend-core-linux-x86_64-<Builds commit>`.

This is a candidate, not a deployment or public release. Fleet must independently
admit its source, workflow, artifact digest and host compatibility before a
reviewed plan. A successful upload does not prove production health. The current
configuration adapter does not install this binary or prepare a new host.

## Reusable build checklist

- [ ] Exact canonical source and Builds wrapper are admitted by reviewed Fleet authority.
- [ ] Actual Gitea required CI status is green for the selected source.
- [ ] Every fundless PostgreSQL target ran against disposable data.
- [ ] Candidate manifest, executable digest and target match the reviewed build.
- [ ] Host compatibility and deployment evidence are separate from build success.
- [ ] No credential values, funded wallets or production database were used.
