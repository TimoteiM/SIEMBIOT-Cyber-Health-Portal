# SIEMBIOT Production Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Deliver the complete production-ready SIEMBIOT Cyber Health Portal while preserving the security and disclosure invariants defined in Phase 0.

**Architecture:** A typed monorepo uses Next.js for web/BFF, FastAPI for control-plane APIs, PostgreSQL as authoritative state, Redis/Celery for durable delivery, isolated collectors/egress and Semantic Kernel gateway, S3-compatible artifacts, and a sanitized public projection. Deterministic services own evidence and scores; agent output is grounded, bounded, and optional.

**Tech Stack:** Node.js 24 LTS + pnpm 10; Next.js/TypeScript; Python 3.13 + uv; FastAPI, SQLAlchemy, Alembic, Pydantic, Celery; PostgreSQL, Redis, MinIO/S3, Keycloak/OIDC, OpenTelemetry; pytest, Vitest, Playwright, axe, Ruff, mypy; Docker Compose and OCI/Kubernetes-compatible deployment.

---

## Execution rules

- Expand each milestone into a reviewed TDD task plan before code for that milestone; do not batch the entire program into an unreviewable change.
- Every behavioral change follows failing test → minimal implementation → passing test → refactor → relevant full gate → narrow commit.
- Use reserved domains and local fixtures only. No real scan is a test dependency.
- Schema, migration, methodology, public projection, and security-boundary changes require explicit review.
- Keep the app runnable at every milestone. Never weaken assertions or security gates to pass CI.

## Milestone 0: Repository and reproducible toolchain

**Create:** `pnpm-workspace.yaml`, root `package.json`, `pyproject.toml`, `uv.lock`, `.python-version`, `.nvmrc`, `.env.example`, `Makefile`, `.github/workflows/ci.yml`, `scripts/verify_repo.py`, `docs/development/setup.md`.

1. Write repository-structure and forbidden-secret/generated-file tests in `tests/repository/`.
2. Pin Node/Python/package-manager versions and lock all dependencies; enable `uv lock --check` and `pnpm --frozen-lockfile`.
3. Add CI stages for formatting, lint, type, unit, contracts, migrations, secrets, SAST/SCA, images, SBOM, and docs; initially gates may target empty packages but may not be skipped.
4. Add one-command bootstrap and safe placeholder configuration.
5. Verify: `make bootstrap && make check`; expected zero failures and clean Git status.

**Acceptance:** clean clone bootstraps without paid keys; no secret values; every dependency is locked; CI is reproducible.

## Milestone 1: Contracts, database, auth, tenancy, audit

**Create:** `packages/contracts/{openapi,jsonschema}/`, `services/api/src/siembiot/{config,db,auth,authorization,audit,organizations}/`, `services/api/migrations/`, `apps/web/src/`, `tests/security/test_tenant_isolation.py`.

1. Write failing JSON Schema tests for error envelope, IDs, pagination, timestamps, and versioned core contracts.
2. Implement minimal OpenAPI-first FastAPI skeleton and generate the TypeScript client; add drift check.
3. Write migrations/tests for users, organizations, memberships, roles, invitations, sessions/revocation metadata, and append-only audit events.
4. Implement OIDC BFF session flow, CSRF/origin checks, generic errors, membership/role matrix, object authorization, and support-access workflow.
5. Add PostgreSQL RLS and tests that deliberately change tenant context, object IDs, roles, revoked membership, and concurrent invitations.
6. Build Romanian-first accessible login/onboarding/team/audit shells and real permission/error states.
7. Verify: `make contracts-check api-test web-test e2e-auth`.

**Acceptance:** deny-by-default tenant isolation at API and DB layers; platform admin cannot silently read tenant data; admin assurance requirements enforced.

## Milestone 2: Domain verification, authorization, and network safety

**Create:** `services/api/src/siembiot/domains/`, `services/worker/src/siembiot_worker/network_safety/`, `packages/contracts/jsonschema/scope/`, `tests/fixtures/network/`, `docs/security/scan-authorization.md`.

1. Write property tests for IDN/domain normalization, PSL eTLD+1, public suffix rejection, delegated zones, and challenge transitions.
2. Migrate domains, challenges, verification events, authorizations, signed scope manifests, suspensions, and kill switches with constraints.
3. Implement digest-only expiring DNS TXT, safe well-known HTTPS, and restricted role-address e-mail challenges.
4. Write adversarial tests for every forbidden IPv4/IPv6 class/encoding, DNS rebinding, multi-answer DNS, redirects, userinfo, scheme/port, metadata, proxies, and TOCTOU.
5. Implement one structured egress client with immediate resolution, address pinning, revalidation, budgets, audit, and network-policy hooks. Ban direct clients/sockets in collectors via architecture test.
6. Build verification/scope/consent UI with explicit authorization language and emergency controls.
7. Verify: `make test-domain test-network-safety e2e-verification`.

**Acceptance:** no out-of-scope connection across the adversarial suite; active mode cannot run without current verification and signed authorization.

## Milestone 3: Provider framework and deterministic collectors

**Create:** `services/worker/src/siembiot_worker/adapters/`, `collectors/{dns,email,tls,http,rdap,ct}/`, `tests/fixtures/{dns,http,tls,providers}/`, `docs/providers/matrix.md`.

1. Test the adapter capability/terms/classification/secret/health/timeout/rate/cost/cache/fixture contract.
2. Implement no-key DNS/RDAP, declared-selector e-mail DNS, TLS/certificate, HTTP redirect/header/cookie, and local CT fixture adapters.
3. Add golden fixtures for pass/fail/warning/unknown/error and malformed/oversized/hostile outputs.
4. Enforce safe handshakes/HEAD/GET limits; no forms, auth crawl, fuzzing, injection, brute force, objects, or intrusive scripts.
5. Add rate limits, circuit breakers, quota accounting, provider disagreement, and explicit unavailable outcomes.
6. Verify entirely against local fake internet: `make fixture-stack test-collectors test-adapters`.

**Acceptance:** core collection demo works with zero paid keys and makes no external connection.

## Milestone 4: Evidence, policy catalog, scoring, and findings

**Create:** `packages/policy/checks/v1/`, `services/worker/src/siembiot_worker/{normalization,evaluation,scoring,findings}/`, `services/api/src/siembiot/evidence/`, `docs/methodology/v1/`.

1. Define and test `NormalizedObservation`, `CheckEvaluation`, `Finding`, score snapshot, confidence, and provenance schemas.
2. Migrate append-only observations/evaluations/snapshots/findings/history and raw artifact metadata; enforce tenant/scope/hash constraints.
3. Implement deterministic normalizers and all minimum check families with golden fixtures.
4. Implement pure applicability/result/weight/pillar/cap/coverage/confidence engines; add reproducibility, monotonicity, sensitivity, missing-data, and critical-cap tests.
5. Implement stable finding fingerprints, history, suppression/accepted-risk authorization, verification, and score-change attribution.
6. Publish methodology version/changelog and machine-readable catalog.
7. Verify: `make policy-validate test-normalization test-scoring methodology-reproduce`.

**Acceptance:** identical signed inputs/policy always yield identical outputs; no model dependency; every score explains inputs, exclusions, caps, coverage, and version.

## Milestone 5: Durable assessment orchestration and assets

**Create:** `services/worker/src/siembiot_worker/workflows/`, `services/api/src/siembiot/{assessments,assets}/`, `tests/workflows/`, `docs/operations/jobs.md`.

1. Write lifecycle transition, duplicate, retry, deadline, cancellation, partial, dead-letter, replay, and circuit tests.
2. Migrate runs, steps, attempts, leases, idempotency keys, schedules, quiet hours, attribution candidates, decisions, and asset history.
3. Implement Celery queues with PostgreSQL state, step graph, known-step progress, cooperative cancellation, and operator replay.
4. Add passive asset candidates from CT/DNS/user fixtures, confidence, shared-hosting context, and accept/reject workflow.
5. Build assessment progress and asset review UI with live real state and screen-reader announcements.
6. Run queue-burst and failure-injection tests.

**Acceptance:** duplicate/out-of-order delivery cannot duplicate evidence or corrupt state; partial completion survives worker/provider failure.

## Milestone 6: Tyche gateway and grounded analysis

**Create:** `services/agent-gateway/`, `packages/contracts/jsonschema/agent/`, `services/worker/src/siembiot_worker/agent_analysis/`, `tests/agent_security/`.

1. Write schemas for assessment scope, execution plan, tool request/result, narrative, remediation, and agent audit.
2. Test allowlisting, scope enforcement, cross-tenant requests, injection corpus, hostile tool output, unsupported claims, budgets, cancellation, provider outage, and tool escalation.
3. Implement Semantic Kernel behind provider abstraction with no direct network/data credentials; policy service mediates every tool request.
4. Implement instruction/data separation, minimized evidence views, claim/reference validator, Measured/Inferred/Recommended labels, and sentence omission.
5. Implement deterministic explanation/remediation/report templates for model absence/failure.
6. Build contextual analyst panel and investigation view with real states/cancel/evidence references.
7. Verify: `make test-agent-security e2e-agent-fallback`.

**Acceptance:** agent cannot expand authority, change evidence/scores, or leak another tenant; complete workflows remain usable with model disabled.

## Milestone 7: Maturity assessment and remediation

**Create:** `packages/policy/questionnaires/v1/`, `services/api/src/siembiot/{maturity,remediation}/`, `apps/web/src/features/{maturity,roadmap}/`, `docs/methodology/maturity-v1.md`.

1. Define baseline/extended localized questions and versioned NIS2 Article 21/CIS v8.1 IG1 mappings after licensing/legal review.
2. Migrate assignments, responses, evidence support, uploads, scores, gaps, actions, owners, due dates, status/history.
3. Implement deterministic 0–5 scoring/completeness and evidence-supported distinction.
4. Implement quarantine, signature/type/size/decompression/malware/object-auth controls for uploads.
5. Build accessible questionnaire collaboration and 30/60/90 roadmap flows.
6. Verify: `make test-maturity test-upload-security e2e-maturity`.

**Acceptance:** baseline completes in validated 10–15 minute usability target; output states it is readiness guidance, not certification.

## Milestone 8: Dashboards, findings, history, and bilingual reports

**Create:** dashboard/finding/domain/e-mail/web/history pages; `services/worker/src/siembiot_worker/reports/`; `docs/reports/`.

1. Implement design tokens from the brief, Romanian/English catalogs, keyboard/focus/reduced-motion/contrast behavior, accessible tables/charts, and all real data states.
2. Build overview, findings explorer, technical posture, assets, history/diff, team/providers/audit/settings pages.
3. Implement deterministic HTML and sandboxed PDF with CONFIDENTIAL label, private cache controls, authorization, and short single-use downloads.
4. Add report injection, URL guessing, cache, snapshot, font/diacritics, and bilingual content tests.
5. Add visual regression and axe tests for critical desktop/tablet/mobile views.

**Acceptance:** required private journeys are complete with no placeholder core screens; reports are reproducible and private.

## Milestone 9: Public Observatory and moderation

**Create:** `services/api/src/siembiot/publication/`, public schema/read model, catalog/moderation/correction APIs, public pages, `docs/publication/safety-policy.md`.

1. Write schema tests proving forbidden private fields cannot enter public projection/analytics.
2. Migrate moderated catalog, provenance, consent, projection, corrections, claims, takedowns, suppression, and aggregate releases.
3. Implement passive-only schedule and separate public projector/API/cache.
4. Implement cohort/privacy thresholding, safe profiles/trends, claim/correction/moderation, and revocation.
5. Build landing, methodology/safety, observatory list/map, safe profile, legal/accessibility/status/contact pages.
6. Verify public disclosure snapshots, reidentification cases, suppression latency, and correction audit E2E.

**Acceptance:** public routes cannot reach private tables and expose only the documented allowlist; counsel/privacy review is recorded before live catalog data.

## Milestone 10: Operations, hardening, and production-like deployment

**Create:** production Dockerfiles, `infra/compose/`, `infra/deploy/`, dashboards/alerts, runbooks, backup/restore, incident response, retention/deletion, provider budgets, SLOs.

1. Build minimal non-root read-only images with health/readiness and least secrets.
2. Enforce collector egress and service ingress policies; run production-like smoke tests.
3. Add structured redacted telemetry, dashboards, alerts, quota/cost monitoring, privacy-safe analytics.
4. Implement backup/PITR and execute/document a restore; exercise kill switches, model/provider outage, cancellation, report failure, and public suppression.
5. Run accessibility/manual keyboard-screen-reader checks, API/queue/load tests, security suite, SAST/SCA/container/IaC/secret scans, SBOM/provenance signing.
6. Complete staging, security, privacy/legal, and go-live checklists; obtain independent penetration test and remediate critical/high findings.

**Acceptance:** measured SLO/load targets, verified restore, signed release artifacts, zero known critical/high defects, and zero release-invariant failures.

## Milestone 11: Demo, release candidate, and handoff

**Create:** deterministic fictional seed, reserved-domain fixture environment, demo accounts bootstrap, `docs/demo.md`, architecture/setup/operations/provider/methodology/safety/deployment/limitations/release docs.

1. Script enrollment → fixture verification → assessment → evidence/findings → Tyche/fallback → maturity → roadmap → bilingual PDF → reassessment delta → optional safe publication/correction.
2. Run the entire script from a clean clone with no paid keys or real targets.
3. Run `make release-check` including lock, lint, types, unit/integration/contract/E2E/accessibility/security/load/migration/image/smoke/SBOM/provenance gates.
4. Record exact commands, versions, counts, failures/waivers, migration/config requirements, deployment URLs only if real, and known limitations.
5. Tag a release candidate only after accountable security/privacy/legal approvals and upstream credential-exposure disposition.

**Acceptance:** every master Definition of Done item has direct evidence or the product is explicitly reported incomplete.

## Migration and rollback strategy

All schema changes are Alembic migrations. Pre-release may squash only before shared environments. Production follows expand/backfill/verify/contract; old and new application versions coexist during expansion. Rollback reverts code only while compatible; data changes use forward fixes or point-in-time restore under an incident decision. Every release tests empty install and previous-release upgrade, takes/validates backup prerequisites, and documents irreversible steps.

## Program dependencies

Legal/privacy decisions gate live public catalog, active checks, provider/model transfers, retention, and report claims. Identity/hosting jurisdiction gates production topology. Domain/network safety gates all collectors. Contracts/auth/tenancy/audit gate every private feature. Evidence/policy/scoring gate Tyche and reports. No later milestone may bypass an earlier invariant.

## Out of scope for initial production release

Exploit validation, intrusive scanning, authenticated crawling, password testing, broad repository secret scraping, typosquat ownership claims, native mobile apps, billing, automated legal compliance certification, and a light theme. Each requires a separate threat model/ADR and explicit authorization.
