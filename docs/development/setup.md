# Local Development Setup

Milestone 2 adds domain normalization, DNS/HTTPS ownership verification, explicit signed authorization manifests, centralized network safety, emergency controls, and the Romanian domain workflow. Tyche, model providers, collectors, scoring, queues, public scans, and assessment execution remain intentionally absent.

## Prerequisites

- Git;
- Node.js exactly `24.18.1` and Corepack;
- a Python 3.12+ launcher (uv installs the pinned Python 3.13 runtime);
- Docker Desktop/Engine with Compose v2;
- GNU Make optionally; direct PowerShell equivalents are shown below.

Bootstrap only locked dependencies:

```powershell
python scripts/bootstrap.py
```

## Local configuration

Copy `.env.example` to the ignored `.env` and replace every `CHANGEME_LOCAL_ONLY` value with a local-only value.

## Identity

Authentication is owned by a separate team and terminates upstream of this service.
There is no login flow here and no identity provider to configure locally — see
[the identity boundary](../security/identity-boundary.md) for the header contract, the
gateway shared secret, and the fail-closed rules.

In development the API reads the identity headers directly. Outside development,
`SIEMBIOT_IDENTITY_GATEWAY_SECRET` is mandatory and the service refuses to start
without it.

## PostgreSQL and migrations

Start the digest-pinned PostgreSQL 17.6 service. Compose creates distinct `siembiot_owner` and least-privilege `siembiot_app` roles from local environment values:

```powershell
docker compose --env-file .env -f infra/compose/postgres.compose.yml up -d --wait
python -m uv run --frozen alembic -c services/api/alembic.ini upgrade head
```

An empty database upgrades through:

1. `0001_identity_tenancy_audit`;
2. `0002_invites_org_discovery`;
3. `0003_global_audit_rls`.
4. `0004_domain_scope_safety`;
5. `0005_authorization_consent`.

Production data rollback is not an Alembic downgrade. Production follows expand/backfill/verify/contract, then a forward fix or point-in-time restore. For disposable development databases only, rollback/re-upgrade is tested with:

```powershell
python -m uv run --frozen alembic -c services/api/alembic.ini downgrade base
python -m uv run --frozen alembic -c services/api/alembic.ini upgrade head
```

Stop the local database without deleting its named volume:

```powershell
docker compose --env-file .env -f infra/compose/postgres.compose.yml down
```

## Run the application

In one terminal, export the values from `.env` using your preferred local environment loader and run the API:

```powershell
python -m uv run --frozen uvicorn siembiot.main:app --app-dir services/api/src --host 127.0.0.1 --port 8000
```

In a second terminal, run the HTTPS development web server. HTTPS is required because the session cookie is always `Secure`:

```powershell
corepack pnpm --filter @siembiot/web dev
```

Open `https://localhost:3000`. The local development certificate is self-signed. The Next.js same-origin rewrite forwards `/api/*` to the API; the browser receives a `Secure`, `HttpOnly`, `SameSite=Lax`, `__Host-` opaque cookie. CSRF values live only in JavaScript memory and are rotated by the session endpoint.

## Verification

The complete gate starts a disposable, named PostgreSQL test project, migrates from empty, runs RLS/security/migration tests, removes only that test project and volume, tests/builds the web app, checks generated-contract drift, and runs all repository gates:

```powershell
python scripts/verify_repo.py
```

Focused commands are:

```powershell
python -m uv run --frozen pytest tests/api tests/contracts -q
python -m uv run --frozen pytest tests/database -q
python -m uv run --frozen pytest tests/security/test_auth_tenant_authorization.py -q
python -m uv run --frozen pytest tests/domain tests/network tests/security -q
python -m uv run --frozen python scripts/check_contracts.py
corepack pnpm --filter @siembiot/web test
corepack pnpm --filter @siembiot/web typecheck
corepack pnpm --filter @siembiot/web build
```

The Docker-backed tests use only fixed test placeholders and reserved domains. They do not access assessment targets or Tyche.

## Production blocker

The upstream Tyche credential exposure remains unresolved and is a production launch blocker. Its rotation and Git-history remediation are separately authorized security actions. This repository does not contain, access, test, rotate, or modify that credential.

## Running the whole application locally

`infra/compose/local-stack.compose.yml` starts the infrastructure only — PostgreSQL.
The API and web application run on the host, because production container images are
Milestone 10 work and `scripts/verify_repo.py` fails the build if a Dockerfile appears
earlier.

Authentication is owned by a separate team and terminates upstream of this service, so
no identity provider runs locally. In development the identity is read straight from
request headers; see [the identity boundary](../security/identity-boundary.md).

```bash
cp .env.example .env        # then set the local placeholders
make stack-up               # digest-pinned PostgreSQL
make migrate                # apply all Alembic migrations
make api-serve              # http://127.0.0.1:8000
make web-serve              # http://localhost:3000
```

The browser reaches the app through the Next.js dev proxy, which forwards the
development identity headers. No credential is involved and no real domain is used.

`make stack-down` stops the containers. If port 5432 is already taken, set
`SIEMBIOT_POSTGRES_PORT` in `.env` and update the two database URLs to match.
