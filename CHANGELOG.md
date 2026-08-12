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

- Milestone 5 durable assessment orchestration: a step graph with per-step retry, idempotency keys, cancellation, and recovery of evidence lost to an in-memory context on resume.
- Milestone 5 asset discovery from Certificate Transparency, with human review before any discovered host enters scope.
- Milestone 7 maturity questionnaire, deterministic 0-5 scoring, and a 30/60/90 remediation roadmap.
- Milestone 8 self-contained bilingual HTML assessment reports, marked CONFIDENTIAL, rendered from the stored snapshot and delivered through a hashed, single-use, five-minute grant bound to the person who asked.
- Milestone 9 Public Observatory: a separate database role and schema, a moderated projection, consent capture, corrections and takedowns.
- Milestone 10 data retention: every table classified, evidence expiring at ninety days, and a dedicated role that is the only one able to delete it.
- Milestone 10 erasure of an organization on request, deriving the tables from the catalogue rather than a list, with a tombstone recording that it happened.
- Milestone 10 a tamper-evident audit trail: events chained per organization by a database trigger, with `audit_chain_breaks()` to verify one.
- Milestone 10 Prometheus, Alertmanager and a receiver, demonstrated firing and resolving end to end.
- Milestone 10 measured performance baselines and a deliberately configured connection pool.
- Collectors for exposed ports (authorized only), announcing-network attribution, and mail transport security, taking the total from six to nine.
- Methodology 1.1.0, adding four checks by naming an additional check directory so 1.0.0 keeps loading exactly what it was published with.

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

- On 2026-08-12, audited the repository against the implementation plan and recorded the result in `docs/product/status-audit-2026-08-12.md`. Commands and exact results:
  - `python scripts/bootstrap.py` — exit 0, on the second attempt. The first failed with `error: failed to remove directory ...\.venv\...: Access is denied. (os error 5)`, which is OneDrive holding files under sync on this path, not a repository defect. It recurred once and cleared on retry both times.
  - `python scripts/verify_repo.py` — exit 0, **15/15 gates**: phase0 (395 files, 11 ADRs), repository (6 tests), locks, format, lint, types, unit, contracts, migrations, secrets, images, i18n, sbom, docs, diff.
  - `python -m uv run --frozen pytest -q` — **1129 passed**, 0 failed, 0 skipped, exit 0.
  - `corepack pnpm --filter @siembiot/web test` — **60 passed** across 8 files, exit 0.
- The entry below this one, dated 2026-08-03, recorded 14 gates and 44 Python tests. That understated the suite by one gate and 1085 tests for nine days, because milestones 5 and 7 through 10 were merged without a changelog entry. `CONTRIBUTING.md` now requires one.

- On 2026-08-03, fast-forwarded `main` from `0647393` to the unchanged Milestone 0 commit `40d639f` from `implementation/milestone-0`.
- Verified the merged `main` state with `python scripts/bootstrap.py` (exit 0), `python scripts/verify_repo.py` (14/14 gates), `python -m uv run --frozen pytest -q` (13 passed), and `git show --check --oneline --stat HEAD` (exit 0).
- On 2026-08-03, GitHub PR #1 passed remote `phase0` run `30804463289` and `ci` run `30804461427`, then merged Milestone 1 into `main` as merge commit `683fcfe03dbc97e89e5eda77ec2dcacc5098dcb1` without squashing its verified checkpoints.
- Verified the merged Milestone 1 `main` state with `python scripts/bootstrap.py` (exit 0), `python scripts/verify_repo.py` (14/14 gates; 44 Python and 3 web tests), an independent empty-database migration test (1 passed), `python -m uv run --frozen pytest -q` (44 passed), `corepack pnpm --filter @siembiot/web build` (exit 0), and `git show --check --stat --oneline 683fcfe03dbc97e89e5eda77ec2dcacc5098dcb1` (exit 0).

### Known limitations

- **Milestone 6 (Tyche gateway) is not started.** There is no `services/agent-gateway/`, no agent JSON schemas, no `tests/agent_security/`, and no model integration of any kind. The workflow's `agent_analysis` step exists and is a permanent stub returning `skipped_model_disabled`, so the one acceptance clause that is met is "complete workflows remain usable with model disabled". The other three cannot be evidenced because the subject of them does not exist.
- Milestone 8 has no dedicated e-mail or web/TLS posture page, no providers or settings page, no PDF output, and no visual-regression or accessibility test suite.
- Milestone 10 has no scheduled off-host backups, no point-in-time recovery, no dashboards, no log aggregation, no provider cost metric, no TLS termination in the stack, no `infra/deploy/`, no container or IaC scanning, and no signed release artifacts.
- Eight policy documents remain `review_status: draft` and are labelled as draft wherever they are displayed. Milestone 7's acceptance requires a licensing and legal review of the NIS2 Article 21 and CIS v8.1 mappings before they are finalised; that review has not happened.
- Milestone 9's acceptance requires a recorded counsel and privacy review before live catalogue data. No such record exists.
- No independent penetration test has been carried out.
- The upstream Tyche credential exposure remains a production launch blocker outside this repository's authority.
