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
- Milestone 3 versioned collection observations, adapter manifests, and run-summary contracts with content-addressed fixture evidence.
- Integrity-checked in-memory fake internet and purpose-specific DNS, HTTP, TLS, RDAP, and CT broker operations.
- Fixture-only DNS, e-mail DNS, HTTP, TLS, RDAP, and CT collectors with deterministic partial completion and reporting.
- Typed adapter registry/runtime with zero-secret fixture policy, budgets, cancellation, circuit breaking, and retained disagreement.
- Typed capability-status API and persistent Romanian fixture-only UI/report warnings; no collection execution endpoint.
- Milestone 4 canonical evidence contracts, six-pillar policy catalog, deterministic normalizers, evaluation, scoring, and immutable finding history.
- Append-only tenant evidence migration with forced RLS, fixture lineage constraints, restricted grants, and database mutation guards.
- Typed findings, history, and snapshot API with audited suppression, accepted-risk, reopening, and remediation-verification events.
- Published fixture-only methodology 1.0 and deterministic reproduction command.
- Review-hardened policy evaluation with closed rule semantics, stable check-ID history, stale/future evidence rejection, source-adapter provenance, methodology-driven coverage, required-evidence caps, and typed score-change attribution.
- Dedicated tenant-scoped evidence-writer database role; interactive application identities can read evidence but cannot forge generated observations, evaluations, scores, findings, or occurrences.
- Tenant/scope/actor-bound finding events with database-enforced lifecycle transitions, composite audit linkage, collision diagnostics, fixture export labeling, and typed evaluation reads.
- Immutable duplicate-safe policy loading, rule-bound stable IDs, authoritative cap evidence requirements, full scoring-input persistence, applicability attribution, database-verified finding fingerprints, and serialized decision transitions.
- Explicit affirmative scope authorization for cap eligibility, strictly monotonic finding-event chronology, required structured provenance, and deferred relational/canonical lineage reconciliation.
- Score-bearing outcomes require non-empty, policy-type-matching evidence in runtime, shared contracts, and PostgreSQL; fixture provenance values are structurally validated at every boundary.

### Security

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
- Adapter/collector architecture tests reject direct network/process capabilities, and a runtime socket/DNS trap proves the full fixture suite opens no connection.
- Fixture provenance is broker-bound, hash-verified, recursively immutable, timezone-aware, and cannot be relabeled as live, published, converted into real-world findings, or scored.
- Fixture mode now propagates structurally through normalized evidence, evaluations, findings, snapshots, API responses, and methodology output; fixture critical caps and publication are rejected.
- Duplicate JSON keys, arbitrary canonical-hash projections, unsupported policy operators, stable-ID repurposing, unsafe fingerprint keys, cross-tenant audit linkage, forged decision actors, and fixture publication views fail closed.

### Verification

- On 2026-08-03, fast-forwarded `main` from `0647393` to the unchanged Milestone 0 commit `40d639f` from `implementation/milestone-0`.
- Verified the merged `main` state with `python scripts/bootstrap.py` (exit 0), `python scripts/verify_repo.py` (14/14 gates), `python -m uv run --frozen pytest -q` (13 passed), and `git show --check --oneline --stat HEAD` (exit 0).
- On 2026-08-03, GitHub PR #1 passed remote `phase0` run `30804463289` and `ci` run `30804461427`, then merged Milestone 1 into `main` as merge commit `683fcfe03dbc97e89e5eda77ec2dcacc5098dcb1` without squashing its verified checkpoints.
- Verified the merged Milestone 1 `main` state with `python scripts/bootstrap.py` (exit 0), `python scripts/verify_repo.py` (14/14 gates; 44 Python and 3 web tests), an independent empty-database migration test (1 passed), `python -m uv run --frozen pytest -q` (44 passed), `corepack pnpm --filter @siembiot/web build` (exit 0), and `git show --check --stat --oneline 683fcfe03dbc97e89e5eda77ec2dcacc5098dcb1` (exit 0).
- On 2026-08-03, verified Milestone 3 fixture-only collection with `python scripts/bootstrap.py` (exit 0), `python scripts/verify_repo.py` (15/15 gates; 241 Python and 7 web tests; production web build passed), `python -m uv run --frozen pytest -q` (241 passed), contract drift and migration-head checks, and the runtime broker-bypass/network trap. GNU Make was unavailable on the Windows host, so the `fixture-stack`, `test-adapters`, and `test-collectors` target bodies were run directly; CI retains the Make target invocation.
- On 2026-08-03, review-hardened Milestone 4 passed `python scripts/bootstrap.py` (exit 0) and `python scripts/verify_repo.py` (17/17 gates; 335 Python and 7 web tests; empty-database migration, policy, methodology, contract drift, and production web build passed).

### Known limitations

- Live assessment execution, live providers, durable queues/workers, Tyche/agents, public projection, restricted-egress deployment, and production operational hardening are not implemented yet. Milestone 4 persistence and scoring remain fixture-only and are not validated for live assessments.
- Milestone 3 validates collection behavior only against local fixtures. Live activation requires all eight controls in `docs/plans/live-execution-activation-dependency.md` and explicit approval.
- The upstream Tyche credential exposure remains a production launch blocker outside this repository's authority.
