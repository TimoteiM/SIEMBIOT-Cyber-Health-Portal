# Local Development Setup

Milestones 3 and 4 provide fixture-only collection, normalization, evaluation, scoring, and evidence-history validation. These paths use deterministic local scenario data only. Live targets/providers, queues, public scans, Tyche, model providers, and assessment execution remain intentionally absent.

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

Copy `.env.example` to the ignored `.env` and replace every `CHANGEME_LOCAL_ONLY` value with a local-only value. Generate the required Fernet session-encryption key locally:

```powershell
python -m uv run python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Configure any standards-compatible OIDC issuer that exposes discovery, authorization, token, JWKS, and optionally end-session endpoints. Register exactly this callback for the default setup:

```text
https://localhost:3000/api/v1/auth/callback
```

The API validates issuer, signed ID token, audience, expiry, state, nonce, and PKCE. It does not accept tenant or platform-role claims from the provider. Access and refresh tokens are never returned to the browser or stored in browser storage.

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

Validate and test the fixture boundary with:

```powershell
make fixture-stack test-adapters test-collectors
```

`fixture-stack` validates the local scenario manifest and starts no process or service. The UI/API/report status is **fixture-only**. Collector results are synthetic and non-publishable. Milestone 4 may deterministically transform them into visibly classified demo evaluations, findings, and scores, but none may be represented as a live assessment or real-world finding. Provider credentials are neither configured nor required.

Validate and reproduce the fixture-only methodology with:

```powershell
python -m uv run --frozen python scripts/validate_policy.py
python -m uv run --frozen pytest tests/normalization -q
python -m uv run --frozen pytest tests/evaluation tests/scoring tests/findings -q
python -m uv run --frozen python scripts/reproduce_methodology.py
```

The reproduction output is always classified `DEMO/FIXTURE`; it is not a live assessment or publishable real-world score.

The Docker-backed tests use only fixed test placeholders and reserved domains. They do not access assessment targets or Tyche.

### Evidence migration rollback

Migration `0006_evidence_scoring` may be downgraded to `0005_authorization_consent` only in a disposable local development database. The downgrade removes all Milestone 4 evidence, evaluations, snapshots, findings, and history. Shared, staging, or production-like databases must preserve append-only assessment history and use a reviewed forward fix or point-in-time recovery instead. Test both an empty upgrade and the `0005 -> 0006` path before integration.

## Production blocker

The upstream Tyche credential exposure remains unresolved and is a production launch blocker. Its rotation and Git-history remediation are separately authorized security actions. This repository does not contain, access, test, rotate, or modify that credential.
