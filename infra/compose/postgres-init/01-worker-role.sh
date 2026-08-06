#!/bin/sh
set -eu

# A separate login role for the queue worker. It is separate from siembiot_app on
# purpose: the row-level security policies added in migration 0009 let the worker write
# within one tenant without a human membership, and that permission must not be
# reachable from the API's credentials. A role requires a password to assume; a session
# flag would only require knowing to set it.
psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=worker_password="$SIEMBIOT_POSTGRES_WORKER_PASSWORD" <<'SQL'
SELECT format(
  'CREATE ROLE siembiot_worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD %L',
  :'worker_password'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'siembiot_worker') \gexec
SQL
