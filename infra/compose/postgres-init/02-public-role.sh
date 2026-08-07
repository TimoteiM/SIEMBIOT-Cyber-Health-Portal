#!/bin/sh
set -eu

# The observatory role, which serves the unauthenticated published pages.
#
# It is created here with a password and given its grants by migration 0015, which
# revokes USAGE on the schema holding tenant tables from PUBLIC and grants it back only
# to the owner, app and worker. The result is that this role cannot read a tenant table,
# cannot join to one, and cannot name one.
#
# A separate role rather than the application's, for the same reason the worker has one:
# serving public pages from a connection that can reach private data would break nothing,
# return the same bytes, and leave the schema separation meaningful only on paper. The
# API re-checks the capability at startup and refuses to serve if it has changed.
psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=public_password="$SIEMBIOT_POSTGRES_PUBLIC_PASSWORD" <<'SQL'
SELECT format(
  'CREATE ROLE siembiot_public LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD %L',
  :'public_password'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'siembiot_public') \gexec
SQL
