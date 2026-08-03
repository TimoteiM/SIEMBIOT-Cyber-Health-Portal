# Milestone 4 Evidence, Policy, Scoring, and Findings Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build an append-only, tenant-isolated evidence and findings system with a versioned policy catalog and pure deterministic evaluation and scoring whose historical outputs remain reproducible.

**Architecture:** Milestone 3 observations enter a versioned canonicalization and normalization boundary, then pure policy evaluation, scoring, attribution, and finding engines produce immutable typed records. PostgreSQL persists tenant-scoped records with forced RLS, composite tenant foreign keys, restricted privileges, and mutation-denial triggers; fixture mode propagates structurally through the complete lineage and is never publishable or eligible for critical caps.

**Tech Stack:** Python 3.13, Pydantic v2, JSON Schema 2020-12, FastAPI, PostgreSQL 16, Alembic, psycopg, pytest/Hypothesis, Ruff, mypy, existing Node 24/pnpm contract generation.

**Stacked ancestry:** `implementation/milestone-4` starts at exact verified Milestone 3 commit `8a50687bb8cd10fe5dc18712d1672aed3dfa147c`. Do not merge it before Milestone 3, rewrite the Milestone 3 commits, or rebase silently. After Milestone 3 reaches `main`, explicitly reconcile ancestry and rerun every baseline and Milestone 4 gate.

---

## Execution rules

- Follow red-green-refactor for every behavior. Capture the expected focused-test failure before production implementation.
- Treat all evidence as untrusted, bounded data. Never log raw payloads, secrets, or global content-hash lookups.
- Keep fixture mode immutable from source through report/export. Reject mixed-mode inputs and all fixture publication.
- Keep posture, coverage, evidence confidence, and attribution confidence separate.
- Commit every completed task after its focused tests, Ruff, and strict mypy pass.
- Keep the app runnable and the full Milestone 3 fixture/network boundary green.

### Task 1: Versioned canonical JSON and evidence contracts

**Files:**
- Create: `packages/contracts/jsonschema/evidence/v1/common.json`
- Create: `packages/contracts/jsonschema/evidence/v1/normalized-observation.json`
- Create: `packages/contracts/jsonschema/evidence/v1/check-evaluation.json`
- Create: `packages/contracts/jsonschema/evidence/v1/finding.json`
- Create: `packages/contracts/jsonschema/evidence/v1/finding-event.json`
- Create: `packages/contracts/jsonschema/evidence/v1/score-snapshot.json`
- Create: `services/worker/src/siembiot_worker/evidence/__init__.py`
- Create: `services/worker/src/siembiot_worker/evidence/canonical.py`
- Create: `services/worker/src/siembiot_worker/evidence/models.py`
- Test: `tests/contracts/test_evidence_contracts.py`
- Test: `tests/evidence/test_canonical.py`
- Fixture: `tests/fixtures/evidence/canonical-v1.json`

1. Write failing tests for all required fields, closed enums, bounded identifiers/strings, timezone-aware UTC timestamps, immutable mode, non-publishable fixture records, mixed-mode rejection, and all eight evaluation outcomes.
2. Add golden canonicalization tests proving key-order independence, Unicode preservation, UTC normalization, stable SHA-256 v1 hashes, explicit volatile-field exclusion, meaningful-change sensitivity, and rejection of duplicate keys, non-finite numbers, naive timestamps, bytes, secrets, and unsupported values.
3. Run `python -m uv run pytest tests/contracts/test_evidence_contracts.py tests/evidence/test_canonical.py -q`; expect missing schemas/modules.
4. Implement strict frozen models plus `canonical-json-v1` and `sha256-v1`. Identity projections must enumerate included fields and never accept arbitrary exclusion lists.
5. Re-run focused tests, Ruff, and mypy; expect pass.
6. Commit `feat: define canonical evidence contracts`.

### Task 2: Versioned policy catalog and repository validator

**Files:**
- Create: `packages/policy/schema/v1/check.schema.json`
- Create: `packages/policy/schema/v1/methodology.schema.json`
- Create: `packages/policy/checks/v1/methodology.json`
- Create: `packages/policy/checks/v1/references.json`
- Create: `packages/policy/checks/v1/{domain-dns,email-trust,web-tls,public-surface,reputation,exposure-hygiene}.json`
- Create: `services/worker/src/siembiot_worker/evaluation/policy.py`
- Create: `scripts/validate_policy.py`
- Modify: `scripts/verify_repo.py`
- Modify: `Makefile`
- Test: `tests/policy/test_catalog.py`
- Test: `tests/repository/test_foundation_commands.py`

1. Write failing tests rejecting duplicate or repurposed stable IDs, unsupported schema/content versions, missing remediation, dangling references/replacements, invalid observation schemas, unsafe public classifications, non-positive check weights, inconsistent pillar totals, invalid result rules, and caps without evidence/freshness/confidence/attribution requirements.
2. Define six pillar records and minimum supported checks for DNS/DNSSEC/CAA, SPF/DMARC/MTA-STS, HTTP headers/cookies, TLS protocol/certificate validity, CT/RDAP attribution signals, provider-unavailable reputation state, and exposure/change hygiene. Unsupported evidence produces `unknown` rather than invented pass/fail.
3. Run the focused tests; expect missing validator/catalog failure.
4. Implement a deterministic loader that validates schemas, cross-file references, stable IDs, independent versions, and canonical policy/content hashes.
5. Add `policy-validate` to `Makefile` and a `policy` repository-verifier gate.
6. Re-run focused tests and `python -m uv run python scripts/validate_policy.py`; expect pass.
7. Commit `feat: add versioned policy catalog`.

### Task 3: Deterministic evidence normalizers

**Files:**
- Create: `services/worker/src/siembiot_worker/normalization/__init__.py`
- Create: `services/worker/src/siembiot_worker/normalization/registry.py`
- Create: `services/worker/src/siembiot_worker/normalization/{dns,email,http,tls,rdap,ct}.py`
- Create: `tests/normalization/test_{dns,email,http,tls,rdap,ct}.py`
- Create: `tests/normalization/test_registry.py`
- Fixture: `tests/fixtures/evidence/normalized-v1.json`

1. Write failing golden tests mapping every Milestone 3 collector family into bounded normalized values while preserving evidence ID, scope reference, collector/adapter versions, timestamp, fixture scenario provenance, classification, mode, freshness, source confidence, attribution confidence, and provider-disagreement state.
2. Add adversarial tests for oversized arrays/strings, malformed shapes, unknown fields, hostile markup, secret-like fields, unsupported collector versions, missing evidence, and deterministic reruns.
3. Run `python -m uv run pytest tests/normalization -q`; expect missing normalizers.
4. Implement an allowlisted `(collector_id, version) -> normalizer` registry and pure family normalizers. Do not store arbitrary source bodies or exception text.
5. Re-run focused tests, Ruff, and mypy; expect pass.
6. Commit `feat: normalize fixture evidence deterministically`.

### Task 4: Pure applicability and evaluation engine

**Files:**
- Create: `services/worker/src/siembiot_worker/evaluation/__init__.py`
- Create: `services/worker/src/siembiot_worker/evaluation/engine.py`
- Create: `services/worker/src/siembiot_worker/evaluation/rules.py`
- Test: `tests/evaluation/test_engine.py`
- Test: `tests/evaluation/test_outcomes.py`
- Fixture: `tests/fixtures/evidence/evaluations-v1.json`

1. Write failing tests for deterministic applicability and `pass`, `fail`, `warning`, `unknown`, `error`, and `not_applicable`; verify missing/unknown/error never becomes pass/fail and not-applicable does not reduce coverage.
2. Write failing tests requiring exact policy content hash, check and behavior versions, evidence references, reasons, evaluated-at clock, freshness result, confidence, attribution, execution mode, and fixture non-publishability.
3. Add tests proving unsupported or mixed evidence modes, stale evidence, disagreement, and insufficient attribution have explicit outcomes/reasons.
4. Run focused tests; expect missing engine.
5. Implement a closed allowlist of pure rule operators needed by catalog v1; do not evaluate arbitrary expressions or executable policy.
6. Re-run focused tests, Ruff, and mypy; expect pass.
7. Commit `feat: evaluate evidence with versioned policy`.

### Task 5: Pure scoring, caps, and change attribution

**Files:**
- Create: `services/worker/src/siembiot_worker/scoring/__init__.py`
- Create: `services/worker/src/siembiot_worker/scoring/engine.py`
- Create: `services/worker/src/siembiot_worker/scoring/attribution.py`
- Test: `tests/scoring/test_reproducibility.py`
- Test: `tests/scoring/test_semantics.py`
- Test: `tests/scoring/test_caps.py`
- Test: `tests/scoring/test_monotonicity.py`
- Test: `tests/scoring/test_attribution.py`
- Fixture: `tests/fixtures/evidence/score-snapshots-v1.json`

1. Write failing tests for exact reproducibility, stable ordering, pillar weights, result factors, score bands, rounding rules, minimum coverage, missing data, and separate posture/coverage/evidence-confidence/attribution-confidence outputs.
2. Add fixed-methodology/applicability/coverage/confidence/attribution monotonicity property tests and sensitivity tests. When any fixed condition changes, require explicit evidence/methodology/applicability/coverage/confidence attribution instead of monotonicity.
3. Add failing cap tests: only current, required, high-confidence, directly attributable, authorized, non-fixture evidence under an explicitly capped rule may lower the score. Shared hosting, stale evidence, uncertain fingerprints, provider disagreement, and fixture inputs must not cap.
4. Add tests proving policy/methodology recalculation creates a different immutable snapshot identity and retains the original.
5. Run `python -m uv run pytest tests/scoring -q`; expect missing engine.
6. Implement pure decimal/rational scoring with one documented rounding boundary, deterministic confidence roll-up, cap eligibility, and change attribution.
7. Re-run focused tests, Ruff, and mypy; expect pass.
8. Commit `feat: score evidence reproducibly`.

### Task 6: Stable findings and immutable lifecycle events

**Files:**
- Create: `services/worker/src/siembiot_worker/findings/__init__.py`
- Create: `services/worker/src/siembiot_worker/findings/fingerprint.py`
- Create: `services/worker/src/siembiot_worker/findings/events.py`
- Create: `services/worker/src/siembiot_worker/findings/projection.py`
- Test: `tests/findings/test_fingerprint.py`
- Test: `tests/findings/test_events.py`
- Test: `tests/findings/test_projection.py`

1. Write failing fingerprint-v1 tests proving separation across tenant, asset, check, policy hash, evidence mode, material evidence key, and incompatible attribution; verify secret/raw payload exclusion and safe collision failure.
2. Write failing lifecycle tests for observed, suppressed, accepted-risk, reopened, expired-review, and remediation-verified events. Decisions require authorized actor, reason, scope, correlation/request IDs, timestamp, and expiry/review date.
3. Add tests that current state is a deterministic event projection, expiry is visible without history mutation, and first-seen/occurrence history remains intact.
4. Run focused tests; expect missing findings package.
5. Implement immutable event constructors, transition validation, collision-safe fingerprint registry, and projection reducer.
6. Re-run focused tests, Ruff, and mypy; expect pass.
7. Commit `feat: add immutable finding history`.

### Task 7: Append-only PostgreSQL evidence schema and RLS

**Files:**
- Create: `services/api/migrations/versions/0006_evidence_policy_scoring_findings.py`
- Create: `tests/database/test_evidence_migrations.py`
- Modify: `tests/database/test_migrations.py`
- Modify: `docs/development/setup.md`

1. Write failing migration tests expecting raw artifact metadata, normalized observations, check evaluations, score snapshots, score attributions, findings, finding occurrences, and finding events.
2. Add failing actual-`siembiot_app` tests for missing context, forged tenant IDs, cross-tenant IDs/hashes/joins, indirect references, background-worker context, denied fixture/live mixing, and denied fixture publication/projection.
3. Add failing immutability tests proving the application role lacks update/delete and owner-level update/delete is rejected by triggers for all append-only tables.
4. Add failing constraint tests for mode propagation, composite tenant/scope/asset references, hash lengths and versions, snapshot/evaluation policy hashes, collision identity mismatch, and event decision metadata.
5. Add empty-upgrade, `0005 -> 0006` upgrade, disposable-development downgrade, and re-upgrade tests.
6. Implement the migration with forced RLS, composite foreign keys, tenant-scoped unique constraints, select/insert-only grants, mutation-denial triggers, and database views for current finding state. No global hash index may expose another tenant.
7. Run `python -m uv run pytest tests/database -q`; expect pass with PostgreSQL fixture.
8. Document local-only rollback and forward-fix/PITR rules for shared environments.
9. Commit `feat: persist immutable tenant evidence`.

### Task 8: Authorized evidence and finding services

**Files:**
- Create: `services/api/src/siembiot/evidence/__init__.py`
- Create: `services/api/src/siembiot/evidence/repository.py`
- Create: `services/api/src/siembiot/evidence/service.py`
- Create: `services/api/src/siembiot/evidence/router.py`
- Create: `services/api/src/siembiot/evidence/contracts.py`
- Modify: `services/api/src/siembiot/main.py`
- Modify: `packages/contracts/openapi/private-api.v1.json`
- Test: `tests/api/test_evidence.py`
- Test: `tests/security/test_evidence_tenant_isolation.py`

1. Write failing typed API tests for tenant-scoped snapshot/evaluation/finding/history reads and authorized suppression, accepted-risk, reopening, and remediation-verification event creation.
2. Add negative tests for unauthenticated access, missing/revoked membership, role escalation, forged organization/asset IDs, cross-tenant direct and indirect references, global hash lookup, event actor forgery, missing decision metadata, and fixture publication attempts.
3. Run focused API/security tests; expect missing routes/services.
4. Implement deny-by-default object authorization before repository lookup, append-only writes, audit events, safe error envelopes, pagination, and fixture-visible response classification. Do not expose raw artifacts or global hash search.
5. Regenerate TypeScript contracts and run contract drift checks.
6. Re-run focused tests, Ruff, mypy, and web typecheck; expect pass.
7. Commit `feat: expose authorized evidence history`.

### Task 9: Methodology publication and reproducibility gates

**Files:**
- Create: `docs/methodology/v1/README.md`
- Create: `docs/methodology/v1/scoring.md`
- Create: `docs/methodology/v1/check-catalog.md`
- Create: `docs/methodology/v1/changelog.md`
- Create: `scripts/reproduce_methodology.py`
- Modify: `docs/methodology/methodology-specification.md`
- Modify: `docs/architecture/target-architecture.md`
- Modify: `docs/security/threat-model.md`
- Modify: `docs/development/setup.md`
- Modify: `CHANGELOG.md`
- Modify: `Makefile`
- Modify: `scripts/verify_repo.py`
- Test: `tests/methodology/test_reproduction.py`
- Test: `tests/security/test_fixture_evidence_boundary.py`

1. Write failing reproduction tests that load signed/canonical fixture inputs and policy, produce byte-identical evaluations/findings/snapshots, and verify stored input/policy hashes.
2. Add end-to-end fixture-boundary tests proving mode propagation through normalization, evaluation, finding, snapshot, report/export representation, application rejection, and database rejection.
3. Implement `methodology-reproduce`, `test-normalization`, and `test-scoring` Make targets and include policy/methodology checks in repository verification.
4. Publish methodology limitations, versioning, formulas, cap eligibility, coverage/confidence separation, check catalog, references, fixture-only DEMO classification, and changelog.
5. Update architecture, threat model, setup guide, and changelog with exact ancestry and no-live-assessment status.
6. Run `python -m uv run python scripts/validate_policy.py`, `python -m uv run python scripts/reproduce_methodology.py`, focused suites, Ruff, and mypy; expect pass.
7. Commit `docs: publish reproducible methodology v1`.

### Task 10: Milestone verification and review

**Files:**
- Modify only files required by verified review findings.

1. Run the direct Windows-compatible bodies of `policy-validate`, `test-normalization`, `test-scoring`, and `methodology-reproduce`; record exact counts.
2. Run `python scripts/bootstrap.py`, `python scripts/verify_repo.py`, complete Python/web tests, production web build, empty/upgrade migration tests, `git diff --check`, and `git show --check` with pinned Node 24.18.1.
3. Inspect `git diff --stat 8a50687..HEAD`, migration head, worktree status, ancestry, and ensure `main` and its pre-existing `scripts/generate_openapi.py` modification remain untouched.
4. Request independent review focused on canonical identity, policy validation, score correctness, fixture isolation, append-only controls, RLS, IDOR/BOLA, fingerprint collisions, and historical reproducibility.
5. Address every Critical/Important finding with a failing regression test and rerun all gates.
6. Commit coherent review fixes without rewriting Milestone 3 history.
7. Report implemented functionality, files/migrations, exact verification results, security controls, final commit, ancestry/worktree state, Tyche credential blocker, remote-CI status, and Milestone 5 next step. Do not merge Milestone 4 before explicit Milestone 3 integration and Milestone 4 acceptance.
