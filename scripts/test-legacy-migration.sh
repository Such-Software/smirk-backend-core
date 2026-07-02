#!/usr/bin/env bash
#
# End-to-end test for `smirk-admin migrate-legacy` (v0.2.x → v0.3 user import).
#
# Spins up two throwaway Postgres databases (a legacy-schema source and a
# freshly-migrated v0.3 target), seeds the source with alice/bob/carol plus edge
# cases (reserved name, anonymous, null-fingerprint, target-username collision,
# uppercase-normalization collision, over-length name, carried nostr_pubkey, and
# a nostr_pubkey collision), runs the importer, and asserts the outcome. Cleans
# up after itself.
#
# Usage:  scripts/test-legacy-migration.sh
# Env:    PG_BASE   Postgres base URL WITHOUT a dbname (default: local socket).
#                   e.g. PG_BASE='postgres://user:pass@localhost' scripts/…
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PG_BASE="${PG_BASE:-postgresql://?host=/var/run/postgresql}"
SRC_DB=smirk_legacy_src_test
TGT_DB=smirk_v3_mig_test
PEPPER="test-pepper-0123456789abcdef-0123456789"
ADMIN_SECRET="test-admin-secret-0123456789abcdef-xyz"
BIN="$ROOT/target/debug/smirk-admin"

# PG_BASE may be "scheme://host?params" or "scheme://user:pass@host"; splice the
# dbname in before any '?'.
dburl() { local db="$1"; if [[ "$PG_BASE" == *\?* ]]; then echo "${PG_BASE/\?//$db?}"; else echo "$PG_BASE/$db"; fi; }
ADMIN=$(dburl postgres); SRC=$(dburl "$SRC_DB"); TGT=$(dburl "$TGT_DB")
h() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() { psql "$ADMIN" -q -c "DROP DATABASE IF EXISTS $SRC_DB;" -c "DROP DATABASE IF EXISTS $TGT_DB;" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> build smirk-admin"
[ -x "$BIN" ] || cargo build --manifest-path "$ROOT/Cargo.toml" --bin smirk-admin

echo "==> (re)create databases"
cleanup
psql "$ADMIN" -q -c "CREATE DATABASE $SRC_DB;" -c "CREATE DATABASE $TGT_DB;"

echo "==> apply v0.3 migrations to target"
for f in "$ROOT"/migrations/*.sql; do psql "$TGT" -q -v ON_ERROR_STOP=1 -f "$f"; done

LONGNAME=$(printf 'a%.0s' {1..40})   # 40 chars > the 32-char limit -> dropped
echo "==> seed legacy source (alice/bob/carol + edge cases)"
psql "$SRC" -q -v ON_ERROR_STOP=1 <<SQL
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username varchar, pubkey_hash varchar, nostr_pubkey varchar, seed_fingerprint varchar,
  wallet_birthday timestamptz, xmr_start_height bigint, wow_start_height bigint,
  created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO users (username,pubkey_hash,nostr_pubkey,seed_fingerprint,wallet_birthday,xmr_start_height,wow_start_height,created_at) VALUES
 ('alice','$(h alice-pk)','$(h alice-npub)','$(h alice-fp)','2026-01-15T00:00:00Z',2800000,500000,'2026-01-15'),
 ('bob',  '$(h bob-pk)',  NULL,             '$(h bob-fp)',  '2026-02-20T00:00:00Z',2850000,510000,'2026-02-20'),
 ('carol','$(h carol-pk)',NULL,             '$(h carol-fp)','2026-03-01T00:00:00Z',2900000,520000,'2026-03-01'),
 ('root', '$(h root-pk)', NULL,             '$(h root-fp)', '2026-03-05T00:00:00Z',NULL,NULL,'2026-03-05'),
 (NULL,   '$(h anon-pk)', NULL,             '$(h anon-fp)', NULL,NULL,NULL,'2026-03-06'),
 ('nofp', '$(h nofp-pk)', NULL,             NULL,           '2026-03-07T00:00:00Z',2910000,NULL,'2026-03-07'),
 ('dave', '$(h dave-pk)', NULL,             '$(h dave-fp)', '2026-03-08T00:00:00Z',NULL,NULL,'2026-03-08'),
 ('Eve',  '$(h eve-pk)',  NULL,             '$(h eve-fp)',  '2026-03-09T00:00:00Z',NULL,NULL,'2026-03-09'),
 ('$LONGNAME','$(h long-pk)',NULL,          '$(h long-fp)', '2026-03-10T00:00:00Z',NULL,NULL,'2026-03-10'),
 ('heidi','$(h heidi-pk)','$(h shared-npub)','$(h heidi-fp)','2026-03-11T00:00:00Z',NULL,NULL,'2026-03-11');
SQL

echo "==> pre-seed native v0.3 rows to force collisions (username dave/eve, nostr shared-npub)"
psql "$TGT" -q \
  -c "INSERT INTO users (username, pubkey_hash) VALUES ('dave', '$(h native-dave)');" \
  -c "INSERT INTO users (username, pubkey_hash) VALUES ('eve',  '$(h native-eve)');" \
  -c "INSERT INTO users (pubkey_hash, nostr_pubkey) VALUES ('$(h native-holder)', '$(h shared-npub)');"

run() { env DATABASE_URL="$TGT" SEED_FINGERPRINT_PEPPER="$PEPPER" ADMIN_KEY_INTEGRITY_SECRET="$ADMIN_SECRET" "$BIN" migrate-legacy --source-url "$SRC" "$@"; }

echo "==> commit import (run 1)"
OUT1=$(run --commit); echo "$OUT1" | tail -3
echo "$OUT1" | grep -q "imported=10 skipped(already present)=0 .*username-dropped=4 nostr-dropped=1 errors=0" \
  || fail "run-1 summary unexpected:\n$OUT1"

TOTAL=$(psql "$TGT" -Atc "SELECT count(*) FROM users;")
UNAMES=$(psql "$TGT" -Atc "SELECT string_agg(username, ',' ORDER BY username) FROM users WHERE username IS NOT NULL;")
[ "$TOTAL" = "13" ] || fail "expected 13 users, got $TOTAL"
[ "$UNAMES" = "alice,bob,carol,dave,eve,heidi,nofp" ] || fail "unexpected usernames: $UNAMES"

# nostr_pubkey: carried for alice (no collision), dropped for heidi (native holds it).
[ "$(psql "$TGT" -Atc "SELECT nostr_pubkey FROM users WHERE username='alice';")" = "$(h alice-npub)" ] \
  || fail "alice nostr_pubkey not carried"
[ -z "$(psql "$TGT" -Atc "SELECT nostr_pubkey FROM users WHERE username='heidi';")" ] \
  || fail "heidi nostr_pubkey should have been dropped (native holds shared-npub)"

# peppering: stored pubkey_hash must be a 64-hex HMAC, not the plaintext.
STORED=$(psql "$TGT" -Atc "SELECT pubkey_hash FROM users WHERE username='alice';")
[ "$STORED" != "$(h alice-pk)" ] && [ "${#STORED}" = "64" ] || fail "alice pubkey_hash not peppered: $STORED"

echo "==> idempotent re-run (must skip all 10)"
OUT2=$(run --commit); echo "$OUT2" | tail -1
echo "$OUT2" | grep -q "imported=0 skipped(already present)=10" || fail "re-run not idempotent:\n$OUT2"

echo "PASS: legacy migration imports identity (+nostr), peppers at rest, handles"
echo "      reserved/taken/over-length/uppercase usernames + nostr collisions, and is idempotent."
