# Milestone 3 Fixture-Only Collectors Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build typed provider adapters and deterministic DNS, e-mail DNS, HTTP, TLS, RDAP, and CT collectors that can execute only through a local fixture broker and can never represent fixture output as live findings.

**Architecture:** A versioned collection contract separates execution status from observation outcome. Collectors receive a narrow `CollectorBroker` protocol and immutable run context; the only Milestone 3 implementation is an in-memory deterministic fixture broker backed by integrity-checked scenario packs. Runtime policy rejects reserved live mode, observations are content-addressed and permanently fixture-labeled, and architecture tests ban direct networking from adapters/collectors.

**Tech Stack:** Python 3.13, Pydantic, JSON Schema, FastAPI/OpenAPI, pytest/Hypothesis, existing centralized network policy types, React/TypeScript/Vitest, GNU Make/PowerShell-compatible commands.

---

## Execution rules

- Follow red-green-refactor for every production behavior; observe the expected failure before implementation.
- Use only fictional `.test`, `.invalid`, or RFC-reserved names and local fixture data. No test may query DNS or open a socket.
- Never add a generic URL/method/port API, direct network fallback, environment-controlled live switch, provider credential, finding, score, or production evidence persistence.
- Every result must preserve fixture/live discriminator and complete provenance. Fixture output is always non-publishable and non-real-world.
- Commit each completed task after its focused tests, Ruff, and strict mypy pass.

### Task 1: Versioned collection contracts and fail-closed execution policy

**Files:**
- Create: `packages/contracts/jsonschema/collection/v1/adapter-manifest.json`
- Create: `packages/contracts/jsonschema/collection/v1/observation.json`
- Create: `packages/contracts/jsonschema/collection/v1/run-summary.json`
- Create: `services/worker/src/siembiot_worker/collection/__init__.py`
- Create: `services/worker/src/siembiot_worker/collection/models.py`
- Create: `services/worker/src/siembiot_worker/collection/policy.py`
- Test: `tests/contracts/test_collection_contracts.py`
- Test: `tests/collectors/test_execution_policy.py`

1. Write failing schema/model tests for `fixture`, `unavailable`, `disabled_by_policy`, and reserved `live`; required provenance; non-publishable fixture output; deterministic evidence IDs; and rejection of fixture relabeling.
2. Run `python -m uv run pytest tests/contracts/test_collection_contracts.py tests/collectors/test_execution_policy.py -q`; expect missing schemas/modules.
3. Implement strict Pydantic/JSON Schema contracts, canonical payload hashing, injected clocks, and `FixtureOnlyExecutionPolicy` that always rejects `live` and fails production collector startup without a future restricted-egress attestation type that has no Milestone 3 constructor.
4. Re-run the focused tests, Ruff, mypy, and contract schema validation; expect pass.
5. Commit `feat: define fixture-only collection contracts`.

### Task 2: Deterministic fake-internet scenario pack and broker

**Files:**
- Create: `services/worker/src/siembiot_worker/collection/broker.py`
- Create: `services/worker/src/siembiot_worker/collection/fixtures.py`
- Create: `tests/fixtures/fake_internet/v1/manifest.json`
- Create: `tests/fixtures/fake_internet/v1/scenarios/*.json`
- Create: `tests/fixtures/fake_internet/v1/tls/*.json`
- Test: `tests/fixtures/test_fake_internet.py`
- Test: `tests/collectors/test_fixture_broker.py`

1. Write failing tests for a narrow broker protocol, scenario manifest digest validation, canonical host/record/method inputs, deterministic timestamps, SSRF-denied destinations, redirect revalidation, DNS rebinding simulation, timeouts, cancellation checkpoints, response/header limits, malformed responses, and scenario-not-found failures.
2. Run the two focused files; expect missing broker/loader failures.
3. Implement purpose-specific `resolve_dns`, `fetch_http`, `handshake_tls`, `query_rdap`, and `query_ct` methods. The fixture implementation reads only the validated scenario pack, uses no network libraries, delegates destination/redirect policy to centralized helpers, and records safe reason codes without payloads.
4. Re-run tests plus `tests/network`; expect pass.
5. Commit `feat: add deterministic fake internet broker`.

### Task 3: Adapter metadata, budgets, quotas, and disagreement

**Files:**
- Create: `services/worker/src/siembiot_worker/adapters/__init__.py`
- Create: `services/worker/src/siembiot_worker/adapters/contracts.py`
- Create: `services/worker/src/siembiot_worker/adapters/runtime.py`
- Create: `services/worker/src/siembiot_worker/adapters/registry.py`
- Test: `tests/adapters/test_contract.py`
- Test: `tests/adapters/test_runtime.py`
- Test: `tests/adapters/test_registry.py`

1. Write failing tests requiring capability, terms, classification, secret names, health, timeout, rate, cost, cache, fixture support, and schema metadata; reject secrets in fixture adapters and capability mismatches.
2. Add failing deterministic tests for request/cost quotas, concurrency, cooperative cancellation, retry prohibition unless declared, circuit open/half-open recovery, unavailable providers, and retained provider disagreement/confidence.
3. Implement immutable adapter descriptors, registry validation, deterministic budget ledger/circuit breaker, and structured outcomes. Do not read environment variables or secret values.
4. Run `python -m uv run pytest tests/adapters -q`, Ruff, and mypy; expect pass.
5. Commit `feat: add typed provider adapter runtime`.

### Task 4: DNS and declared-selector e-mail collectors

**Files:**
- Create: `services/worker/src/siembiot_worker/collectors/__init__.py`
- Create: `services/worker/src/siembiot_worker/collectors/dns/__init__.py`
- Create: `services/worker/src/siembiot_worker/collectors/dns/collector.py`
- Create: `services/worker/src/siembiot_worker/collectors/email/__init__.py`
- Create: `services/worker/src/siembiot_worker/collectors/email/collector.py`
- Extend: `tests/fixtures/fake_internet/v1/scenarios/*.json`
- Test: `tests/collectors/test_dns_collector.py`
- Test: `tests/collectors/test_email_collector.py`

1. Write failing golden tests for NS/SOA/DS/DNSKEY/CAA/wildcard/delegation and MX/SPF/DMARC/MTA-STS/TLS-RPT/TLSA/BIMI states including pass/fail/warning/unknown/error and malformed/oversized records.
2. Add a failing test proving DKIM requests accept only selectors explicitly present in the signed run input and never generate/brute-force selectors.
3. Implement pure parsers/collectors that call only broker DNS capabilities and emit provenance-complete observations without scoring.
4. Run focused tests plus deterministic rerun/property cases; expect byte-identical canonical results.
5. Commit `feat: add fixture DNS and email collectors`.

### Task 5: Bounded HTTP and TLS collectors

**Files:**
- Create: `services/worker/src/siembiot_worker/collectors/http/__init__.py`
- Create: `services/worker/src/siembiot_worker/collectors/http/collector.py`
- Create: `services/worker/src/siembiot_worker/collectors/tls/__init__.py`
- Create: `services/worker/src/siembiot_worker/collectors/tls/collector.py`
- Extend: `tests/fixtures/fake_internet/v1/scenarios/*.json`
- Extend: `tests/fixtures/fake_internet/v1/tls/*.json`
- Test: `tests/collectors/test_http_collector.py`
- Test: `tests/collectors/test_tls_collector.py`

1. Write failing tests for HEAD/allowlisted GET, redirect chain, HSTS/CSP/frame/content/referrer/permissions headers, public cookie flags, canonical host, bounded body metadata, TLS version/cipher, hostname, chain, validity, and expiry.
2. Add failing negative cases for credentials/query/fragments, cross-host redirect, downgrade, rebinding, private addresses, malformed framing/certificates, oversized headers/body, timeout, cancellation, and intrusive method/crawl attempts.
3. Implement collectors against only HTTP/TLS broker methods. Parse hostile strings with strict size/type bounds; never execute content or preserve full bodies.
4. Run focused and network adversarial suites; expect pass.
5. Commit `feat: add fixture HTTP and TLS collectors`.

### Task 6: RDAP and local CT fixture adapters

**Files:**
- Create: `services/worker/src/siembiot_worker/collectors/rdap/__init__.py`
- Create: `services/worker/src/siembiot_worker/collectors/rdap/collector.py`
- Create: `services/worker/src/siembiot_worker/collectors/ct/__init__.py`
- Create: `services/worker/src/siembiot_worker/collectors/ct/collector.py`
- Extend: `tests/fixtures/fake_internet/v1/scenarios/*.json`
- Test: `tests/collectors/test_rdap_collector.py`
- Test: `tests/collectors/test_ct_collector.py`

1. Write failing tests for normalized registration status/timestamps, redacted entity roles, CT certificate/name assertions, explicit unavailable results, disagreement, hostile strings, oversized arrays, unrelated names, and wildcard handling.
2. Implement deterministic parsers through broker methods. CT names remain passive fixture assertions for later asset review and never authorize or create assets.
3. Run focused tests, Ruff, and mypy; expect pass.
4. Commit `feat: add fixture RDAP and CT collectors`.

### Task 7: Deterministic suite runner and partial completion

**Files:**
- Create: `services/worker/src/siembiot_worker/collection/runner.py`
- Create: `services/worker/src/siembiot_worker/collection/reporting.py`
- Test: `tests/collectors/test_runner.py`
- Test: `tests/collectors/test_determinism.py`

1. Write failing tests for stable step ordering, independent partial failure, cancellation, aggregate quotas, circuit-open providers, exact rerun identity, evidence-ID stability, safe error redaction, and mandatory fixture report banner.
2. Implement a synchronous deterministic fixture runner with immutable context and per-step structured outcomes. One collector error must not erase successful independent observations; coverage is reported separately and nothing is scored.
3. Run all adapter/collector tests twice and compare canonical output hashes; expect equality.
4. Commit `feat: orchestrate deterministic fixture collection`.

### Task 8: Fixture-only API, UI, and report visibility

**Files:**
- Modify: `services/api/src/siembiot/contracts.py`
- Modify: `services/api/src/siembiot/main.py`
- Modify: `packages/contracts/openapi/private-api.v1.json`
- Modify: `packages/contracts/src/private-api.v1.ts`
- Modify: `apps/web/src/app/layout.tsx`
- Modify: `apps/web/src/app/styles.css`
- Test: `tests/api/test_collection_capability.py`
- Test: `apps/web/src/app/fixture-mode.test.tsx`
- Test: `tests/security/test_fixture_label_invariants.py`

1. Write failing API tests requiring `fixture_only`, `live_execution=false`, non-publishable status, and the restricted-egress dependency; write UI tests for a persistent Romanian fixture banner; write source/schema tests preventing fixture observations from real-world/report publication.
2. Run focused backend/web tests; expect missing endpoint/banner.
3. Implement read-only typed capability status and persistent UI label. Generate OpenAPI/TypeScript contracts. Expose no collector execution endpoint.
4. Run contract drift, API, web test, typecheck, and production build; expect pass.
5. Commit `feat: surface fixture-only collection status`.

### Task 9: Architecture gates, commands, provider matrix, and full verification

**Files:**
- Create: `tests/security/test_collector_network_architecture.py`
- Create: `tests/security/test_no_external_fixture_network.py`
- Create: `docs/providers/matrix.md`
- Create: `docs/collection/fixture-only.md`
- Modify: `docs/adr/0008-provider-adapters.md`
- Modify: `docs/adr/0010-network-and-ssrf-safety.md`
- Modify: `docs/architecture/target-architecture.md`
- Modify: `docs/security/threat-model.md`
- Modify: `docs/development/setup.md`
- Modify: `CHANGELOG.md`
- Modify: `Makefile`
- Modify: `scripts/verify_repo.py`

1. Write failing architecture tests banning direct networking/process/browser imports and calls in adapters/collectors, and a network trap that fails on socket/DNS access during the complete fixture suite.
2. Add `fixture-stack`, `test-adapters`, and `test-collectors` commands; `fixture-stack` validates scenario integrity and starts no external service.
3. Document provider metadata, zero-key core, fixture limitations, unavailable behavior, disagreement, privacy, non-live status, and the later activation dependency. Update ADRs/threat model/architecture/setup/changelog without claiming live support.
4. Run exact pinned-runtime verification:
   - `python scripts/bootstrap.py`
   - `make fixture-stack test-adapters test-collectors`
   - `python scripts/verify_repo.py`
   - `python -m uv run --frozen pytest -q`
   - `corepack pnpm --filter @siembiot/web build`
   - `git diff --check main...HEAD`
   - `git show --check --oneline --stat HEAD`
5. Confirm the worktree is clean and commit `docs: operationalize fixture-only collectors`.

## Milestone boundary

Push `implementation/milestone-3`, open a draft PR, and require configured remote CI. Report the exact commit, tests/gates, scenario coverage, broker-only security proof, fixture-only UI/API/report labeling, worktree status, remaining live-execution dependency, Tyche credential blocker, and Milestone 4 next step. Do not merge without the next explicit acceptance/integration instruction.
