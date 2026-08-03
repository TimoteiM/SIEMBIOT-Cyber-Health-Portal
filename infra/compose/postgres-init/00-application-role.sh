#!/bin/sh
set -eu

psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=app_password="$SIEMBIOT_POSTGRES_APP_PASSWORD" \
  --set=worker_password="$SIEMBIOT_POSTGRES_WORKER_PASSWORD" <<'SQL'
SELECT format(
  'CREATE ROLE siembiot_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD %L',
  :'app_password'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'siembiot_app') \gexec
SELECT format(
  'CREATE ROLE siembiot_worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD %L',
  :'worker_password'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'siembiot_worker') \gexec
SQL
