#!/usr/bin/env bash
# Own a disposable Unix-socket PostgreSQL cluster. Never use a caller's database.
set -euo pipefail
set +x
if [[ $# != 0 ]]; then
  echo 'Fundless CI does not accept a database or test-command override.' >&2
  exit 1
fi
if [[ -f .env ]]; then
  echo 'Fundless CI refuses a checkout containing .env.' >&2
  exit 1
fi
pg_bin=$(pg_config --bindir)
for tool in initdb pg_ctl createdb psql; do
  [[ -x "$pg_bin/$tool" ]] || { echo "Fundless CI requires PostgreSQL $tool." >&2; exit 1; }
done
ci_pg_dir=$(mktemp -d /tmp/smirk-ci-pg.XXXXXXXX)
chmod 700 "$ci_pg_dir"
pg_user=$(id -un)
if [[ $(id -u) == 0 ]]; then
  pg_user=postgres
  id "$pg_user" >/dev/null 2>&1 || { echo 'The isolated CI container requires the postgres service account.' >&2; exit 1; }
  chown "$pg_user" "$ci_pg_dir"
fi
pg_exec() {
  if [[ $(id -u) == 0 ]]; then
    runuser -u "$pg_user" -- "$@"
  else
    "$@"
  fi
}
cleanup() {
  pg_exec "$pg_bin/pg_ctl" -D "$ci_pg_dir/data" -m immediate -w stop >/dev/null 2>&1 || true
  rm -rf "$ci_pg_dir"
}
trap cleanup EXIT
pg_exec "$pg_bin/initdb" -D "$ci_pg_dir/data" --auth-local=trust --auth-host=reject --no-locale >/dev/null
# No TCP listener and a private socket directory: no password or shared service.
pg_exec "$pg_bin/pg_ctl" -D "$ci_pg_dir/data" -l "$ci_pg_dir/postgres.log" \
  -o "-k $ci_pg_dir -c listen_addresses='' -c unix_socket_permissions=0700" -w start >/dev/null
pg_exec "$pg_bin/createdb" -h "$ci_pg_dir" smirk_ci
export TEST_DATABASE_URL="postgresql:///smirk_ci?host=$ci_pg_dir&user=$pg_user"
# A failing or missing DB is an error; tests must not quietly take their no-DB path.
pg_exec "$pg_bin/psql" -h "$ci_pg_dir" -d smirk_ci -Atc 'SELECT 1' | grep -qx 1
cargo test --locked --tests
cargo test --locked --doc
