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
- Milestone 2 canonical IDN/domain registration backed by a pinned, provenance-recorded Public Suffix List.
- Digest-only DNS TXT and fixed-path HTTPS ownership challenges with expiry, attempt, replay, and rate budgets.
- Explicit consent capture, exact domain targets, canonical immutable Ed25519 scope manifests, and key rotation support.
- Purpose-specific address-pinned network broker with DNS rebinding, redirect, SSRF, framing, concurrency, time, and size defenses.
- Global, organization, domain, and operation-class emergency controls with audited activation/deactivation.
- Romanian-first domain verification and authorization workflow with one-time in-memory challenge display.
- Milestone 3 operation-class collection boundary generalizing the network broker to DNS queries, TLS handshakes, and multi-path HTTP fetches under the same authorization, pinning, and redirect revalidation rules.
- Record-type allowlisted, budget-bounded DNS client and handshake-only TLS inspector with bounded protocol probing.
- Declarative provider adapter contract covering capabilities, terms, data classification, secrets, timeout, rate limit, cost unit, cache policy, and mandatory fixture support.
- Adapter registry plus token-bucket rate limiting, circuit breaking, quota accounting, TTL caching, and provider-disagreement summaries.
- Keyless DNS resilience, e-mail trust, TLS/certificate, HTTP surface, RDAP, and Certificate Transparency collectors with golden pass/fail/warning/unknown/error and hostile-input fixtures.
- Generated provider matrix with a CI drift check, and `test-collectors`, `test-adapters`, `providers-check`, `test-domain`, `test-network-safety`, and `fixture-stack` targets.
- Milestone 4 versioned evidence contracts for normalized observations, check evaluations, score snapshots, findings, and multi-dimensional confidence.
- Policy-as-data methodology v1.0.0 with 22 checks across all six pillars, declared weights, severities, public-safety classes, remediation templates, and bilingual titles.
- Deterministic normalizers turning collector payloads into content-addressed observations that keep proven absence and inconclusive collection distinct.
- Pure evaluation engine producing all eight result states, with ordered rules, applicability gating, and expiring authorized overrides.
- Reproducible scoring engine with pillar weighting, high-confidence-only critical caps, coverage floor, and minimum-based confidence roll-up.
- Stable finding fingerprints with resolve/regress reconciliation, expiring suppression, accepted risk, and methodology-aware score-change attribution.
- Append-only migration for assessments, observations, evaluations, score snapshots, findings, suppressions, and finding history under row-level security.
- Published methodology v1 documentation, reference snapshot, and `policy-validate`, `test-normalization`, `test-scoring`, and `methodology-reproduce` targets.

### Security

- DKIM selectors are collected only from organization declarations; selector wordlists are never tried.
- RDAP entity and contact objects are discarded at parse time; only registration facts are retained.
- Certificate Transparency names are recorded as confidence-labelled candidates, never as confirmed organizational assets.
- Architecture test extended to confine `dns`, `ssl`, `http`, `smtplib`, and `asyncio` imports to the network-safety boundary.
- Observations, evaluations, score snapshots, and finding history are append-only at the database level, so a completed assessment cannot be rewritten.
- A critical cap can only lower a score, is rejected by a database constraint otherwise, and never fires on a low-confidence or shared-hosting observation.
- Suppression requires a reason, an actor, and an expiry; an indefinite suppression is not representable in the schema.

- Safe environment template with the model disabled by default.
- Tracked secret/key/generated-file rejection and assignment-shaped secret scanning.
- No Tyche configuration, credentials, dependencies, source, or ticket functionality imported.
- Forced PostgreSQL RLS plus application-layer tenant/action/object authorization, with no implicit platform-admin tenant access.
- Append-only structured audit events protected by application-role grants, RLS, and an immutability trigger.
- Negative tests for unauthenticated, cross-tenant, IDOR/BOLA, forged tenant, role escalation, revoked membership, expired session, OIDC replay/nonce, CSRF origin, and support-access assurance cases.
- Browser security invariant prohibits access/refresh token storage and keeps CSRF state in memory.
- Network imports are confined to the centralized safety module; every resolution and redirect fails closed on any unsafe answer.
- Ownership and assessment authority are distinct: challenges never grant assessment scope and parent domains never grant child domains.
- Emergency controls are checked authoritatively during in-flight reads; global controls require phishing-resistant platform administration.

### Verification

- On 2026-08-03, fast-forwarded `main` from `0647393` to the unchanged Milestone 0 commit `40d639f` from `implementation/milestone-0`.
- Verified the merged `main` state with `python scripts/bootstrap.py` (exit 0), `python scripts/verify_repo.py` (14/14 gates), `python -m uv run --frozen pytest -q` (13 passed), and `git show --check --oneline --stat HEAD` (exit 0).
- On 2026-08-03, GitHub PR #1 passed remote `phase0` run `30804463289` and `ci` run `30804461427`, then merged Milestone 1 into `main` as merge commit `683fcfe03dbc97e89e5eda77ec2dcacc5098dcb1` without squashing its verified checkpoints.
- Verified the merged Milestone 1 `main` state with `python scripts/bootstrap.py` (exit 0), `python scripts/verify_repo.py` (14/14 gates; 44 Python and 3 web tests), an independent empty-database migration test (1 passed), `python -m uv run --frozen pytest -q` (44 passed), `corepack pnpm --filter @siembiot/web build` (exit 0), and `git show --check --stat --oneline 683fcfe03dbc97e89e5eda77ec2dcacc5098dcb1` (exit 0).

### Known limitations

- Tyche/agents, assessment execution, collectors, providers, queues, evidence, scoring, reports, public projection, restricted-egress deployment, and production operational hardening are not implemented yet.
- The upstream Tyche credential exposure remains a production launch blocker outside this repository's authority.
