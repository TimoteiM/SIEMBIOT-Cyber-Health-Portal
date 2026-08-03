# Changelog

All notable changes are documented here. The project has no supported release yet.

## Unreleased

### Added

- Independent Phase 0 architecture, ADRs, threat model, methodology draft, and implementation plan.
- Milestone 0 reproducible toolchain pins for Node.js 24.18.1, pnpm 10.34.5, Python 3.13, and uv 0.12.1.
- Frozen JavaScript and Python dependency locks.
- Cross-platform bootstrap and 14-gate repository verification commands.
- Repository invariant, toolchain, secret-scanner, Windows command-shim, runtime, and CI pinning tests.
- Commit-pinned CI foundation workflow with least-privilege permissions.
- Milestone 1 versioned JSON Schema/OpenAPI contracts and generated TypeScript API definitions with drift checks.
- Digest-pinned PostgreSQL startup and Alembic migrations for identities, organizations, memberships, invitations, OIDC transactions, server sessions, explicit support grants, and audit events.
- Actor-isolated global audit-event reads in addition to tenant-scoped audit RLS.
- Provider-neutral OIDC discovery, state/nonce/PKCE callback, opaque session, CSRF, logout, organization, membership, invitation, RBAC, and audit APIs.
- Romanian-first accessible login, onboarding, team, and audit web shells with HTTPS local development.

### Security

- Safe environment template with the model disabled by default.
- Tracked secret/key/generated-file rejection and assignment-shaped secret scanning.
- No Tyche configuration, credentials, dependencies, source, or ticket functionality imported.
- Forced PostgreSQL RLS plus application-layer tenant/action/object authorization, with no implicit platform-admin tenant access.
- Append-only structured audit events protected by application-role grants, RLS, and an immutability trigger.
- Negative tests for unauthenticated, cross-tenant, IDOR/BOLA, forged tenant, role escalation, revoked membership, expired session, OIDC replay/nonce, CSRF origin, and support-access assurance cases.
- Browser security invariant prohibits access/refresh token storage and keeps CSRF state in memory.

### Verification

- On 2026-08-03, fast-forwarded `main` from `0647393` to the unchanged Milestone 0 commit `40d639f` from `implementation/milestone-0`.
- Verified the merged `main` state with `python scripts/bootstrap.py` (exit 0), `python scripts/verify_repo.py` (14/14 gates), `python -m uv run --frozen pytest -q` (13 passed), and `git show --check --oneline --stat HEAD` (exit 0).

### Known limitations

- Tyche/agents, assessments, domain verification, collectors, providers, queues, evidence, scoring, reports, public projection, production deployment, and operational hardening are not implemented yet.
- The upstream Tyche credential exposure remains a production launch blocker outside this repository's authority.
