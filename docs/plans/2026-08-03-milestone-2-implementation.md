# Milestone 2 Domain Authorization and Network Safety Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Deliver tenant-isolated domain verification, explicit signed scope authorization, emergency controls, and a purpose-specific SSRF-safe network broker without adding collectors or generic network tools.

**Architecture:** FastAPI owns state transitions and authorization; PostgreSQL is authoritative and applies forced RLS. A separately packaged worker network-safety module accepts structured, manifest-bound verification requests through injected resolver/transport/policy interfaces and reauthorizes at every I/O boundary. Contracts and UI consume only backend-confirmed state.

**Tech Stack:** Python 3.13, FastAPI, Pydantic, PostgreSQL 17/Alembic, Ed25519 through `cryptography`, `idna`, `dnspython`, Hypothesis, Next.js/React/TypeScript/Vitest, vendored commit-pinned Public Suffix List.

---

## Execution rules

- Follow red-green-refactor for every behavior. No production function is added before its failing test is observed.
- Use only deterministic fake DNS/transport fixtures in tests; no assessment target or Tyche connection is permitted.
- Keep challenge plaintext out of logs, audit context, and stored rows.
- Commit after every completed task and run its focused suite before continuing.
- Treat any ability to bypass scope, RLS, manifest, IP policy, redirect policy, or emergency controls as a release blocker.

### Task 1: Domain normalization and pinned Public Suffix List

**Files:**
- Create: `services/api/src/siembiot/domains/__init__.py`
- Create: `services/api/src/siembiot/domains/normalization.py`
- Create: `packages/policy/public_suffix_list/public_suffix_list.dat`
- Create: `packages/policy/public_suffix_list/PROVENANCE.md`
- Create: `THIRD_PARTY_NOTICES.md`
- Modify: `pyproject.toml`, `uv.lock`
- Test: `tests/domain/test_normalization.py`, `tests/repository/test_repository_invariants.py`

1. Add failing table/property tests for ASCII/Unicode normalization, A-label/display output, length/label rules, URLs, IPs, ports, paths, credentials, wildcards, whitespace, trailing dots, malformed IDNs, public suffixes, PSL wildcard/exception cases, registrable domains, and neutral confusable warnings.
2. Run `python -m uv run --frozen pytest tests/domain/test_normalization.py -q`; expect import/behavior failures.
3. Vendor the PSL file from commit `e1b8015c3b2f0f4f8c18659c2480fc1a22c07b20`, record URL/commit/SHA-256/license, pin `idna==3.18` explicitly and `hypothesis==6.165.0` for tests, then refresh the lock.
4. Implement `NormalizedDomain`, a deterministic PSL matcher, UTS #46 non-transitional normalization, exact rejection reason codes, and non-accusatory IDN warnings.
5. Run focused tests, repository secret/license invariants, Ruff, and mypy; expect pass.
6. Commit `feat: normalize domains with pinned public suffix data`.

### Task 2: Versioned domain/scope contracts and persistence

**Files:**
- Create: `packages/contracts/jsonschema/v1/domain.json`
- Create: `packages/contracts/jsonschema/v1/domain-challenge.json`
- Create: `packages/contracts/jsonschema/v1/assessment-authorization.json`
- Create: `packages/contracts/jsonschema/v1/scope-manifest.json`
- Create: `packages/contracts/jsonschema/v1/emergency-control.json`
- Create: `packages/contracts/jsonschema/v1/network-decision.json`
- Create: `services/api/migrations/versions/0004_domain_authorization_network_safety.py`
- Modify: `services/api/src/siembiot/contracts.py`, `services/api/src/siembiot/authorization.py`, `scripts/generate_openapi.py`
- Test: `tests/contracts/test_domain_scope_contracts.py`, `tests/database/test_domain_scope_migrations.py`

1. Add failing schema/API-model tests for strict versioned shapes, state enums, bounded operation classes, safe reason codes, and omission of token/signature-private fields.
2. Add failing database tests for empty upgrade, tenant RLS/IDOR, exact-domain uniqueness, one active challenge per method, state constraints, immutable verification events/manifests, application-role grant limits, and development downgrade/re-upgrade.
3. Run focused suites; expect missing-schema/table failures.
4. Implement typed contracts and migration tables for domains, challenges, verification events, authorizations, authorization targets, immutable manifests, emergency controls, and network operations. Add forced RLS, partial indexes, constraints, security-definer predicates, and immutable triggers.
5. Extend deny-by-default actions for domain read/manage/verify, authorization read/manage, and emergency-control read/manage; owners/security admins manage, analysts read only where explicitly allowed, all other combinations deny.
6. Generate OpenAPI/TypeScript, run contract drift, database tests, Ruff, and mypy; expect pass.
7. Commit `feat: add tenant-isolated domain authorization schema`.

### Task 3: Challenge lifecycle and DNS TXT verification

**Files:**
- Create: `services/api/src/siembiot/domains/challenges.py`
- Create: `services/api/src/siembiot/domains/service.py`
- Create: `services/api/src/siembiot/domains/router.py`
- Create: `services/api/src/siembiot/domains/dns_verification.py`
- Modify: `services/api/src/siembiot/main.py`, `services/api/src/siembiot/config.py`, `.env.example`
- Test: `tests/domain/test_challenge_lifecycle.py`, `tests/api/test_domains.py`, `tests/security/test_domain_tenant_isolation.py`

1. Add failing tests for create/list/get, digest-only storage, one-time plaintext response, `_tyche-verify` query name, exact TXT digest match, expiry, attempts/rate windows, replay, concurrent active challenges, revocation, reverification state, audit redaction, forged organization, cross-tenant object IDs, and role denial.
2. Run the focused tests; expect missing route/service failures.
3. Implement cryptographically random challenge creation, constant-time digest matching, transaction/row-lock state transitions, injected clock/TXT resolver, bounded database-backed rate counters, and immutable safe audit events.
4. Add provider-neutral DNS resolver adapter with lifetime/answer limits and no generic DNS endpoint. Keep administrative email absent.
5. Run domain/API/security suites, Ruff, mypy, and OpenAPI drift; expect pass.
6. Commit `feat: implement bounded domain verification lifecycle`.

### Task 4: Canonical manifests and versioned signing

**Files:**
- Create: `packages/contracts/jsonschema/scope/v1/scope-manifest.json`
- Create: `services/api/src/siembiot/domains/manifests.py`
- Create: `services/api/src/siembiot/domains/signing.py`
- Modify: `services/api/src/siembiot/domains/router.py`, `services/api/src/siembiot/config.py`, `.env.example`
- Test: `tests/domain/test_scope_manifests.py`, `tests/api/test_authorizations.py`, `tests/security/test_manifest_authorization.py`

1. Add failing golden/property tests for canonical UTF-8 JSON, stable hash/signature, actor/org/targets/operation/policy/consent/validity fields, key ID/algorithm, altered bytes, unknown key, rotation, invalid signature, expired/revoked authorization, inactive verification, delegated child mismatch, and production rejection of development keys.
2. Run focused tests; expect missing signer/manifest failures.
3. Implement pure canonical serialization, SHA-256 digest, `ManifestSigner`/`ManifestVerifier` protocols, Ed25519 development adapter, configured active verification-key set, and production fail-closed configuration.
4. Implement authorization draft/accept/revoke endpoints and immutable manifest insertion. Require current exact-domain verification and explicit consent; never infer authorization from verification.
5. Run focused suites, contract drift, Ruff, and mypy; expect pass.
6. Commit `feat: sign immutable assessment scope manifests`.

### Task 5: Network policy and adversarial destination validation

**Files:**
- Create: `services/worker/src/siembiot_worker/__init__.py`
- Create: `services/worker/src/siembiot_worker/network_safety/__init__.py`
- Create: `services/worker/src/siembiot_worker/network_safety/models.py`
- Create: `services/worker/src/siembiot_worker/network_safety/address_policy.py`
- Create: `services/worker/src/siembiot_worker/network_safety/url_policy.py`
- Create: `tests/fixtures/network/destinations.json`
- Modify: `pyproject.toml`, `tests/conftest.py`
- Test: `tests/network/test_address_policy.py`, `tests/network/test_url_policy.py`, `tests/security/test_network_architecture.py`

1. Add failing table/property tests for every IPv4/IPv6 forbidden class, IPv4-mapped IPv6, metadata ranges, CGNAT, documentation/benchmark ranges, mixed answers, integer/hex/octal/short forms, zone IDs, credentials, fragments, schemes, ports, noncanonical hosts, paths, and redirect scope.
2. Add a failing architecture test prohibiting socket/HTTP client imports in future collector code and generic fetch/URL parameters in the broker API.
3. Run focused tests; expect missing policy failures.
4. Implement typed `NetworkBudget`, `NetworkDecision`, safe reason enums, strict address parser/classifier, structured verification destination builder, and redirect normalization/authorization.
5. Run focused property/security tests, Ruff, and mypy; expect pass.
6. Commit `feat: deny unsafe network destinations centrally`.

### Task 6: Address-pinned broker, HTTPS verification, and budgets

**Files:**
- Create: `services/worker/src/siembiot_worker/network_safety/resolver.py`
- Create: `services/worker/src/siembiot_worker/network_safety/transport.py`
- Create: `services/worker/src/siembiot_worker/network_safety/broker.py`
- Create: `tests/fixtures/network/fakes.py`
- Test: `tests/network/test_broker.py`, `tests/network/test_transport.py`, `tests/network/test_rebinding_redirects.py`

1. Add failing tests proving immediate resolution, all-answer validation, address pinning, Host/TLS SNI preservation, no proxy use, DNS rebinding defense, redirect re-resolution, cross-domain denial, redirect cap, header/body/read limits, connect/read/total timeout, concurrency budget, cancellation checkpoints, and safe audit reason codes without bodies/tokens.
2. Run focused tests; expect missing broker failures.
3. Implement injected resolver/transport/control interfaces and a purpose-specific `fetch_https_verification` operation. The concrete transport uses only validated IPs and a bounded HTTP/1.1 exchange; it does not expose arbitrary methods, URLs, or ports.
4. Reauthorize manifest/target/emergency state before DNS, after DNS, before connect, on redirect, and between body chunks. Record network-operation status and reject stale queued/in-flight work cooperatively.
5. Run focused network/security suites, Ruff, mypy, and architecture tests; expect pass.
6. Commit `feat: add address-pinned verification network broker`.

### Task 7: HTTPS state transition and emergency controls

**Files:**
- Create: `services/api/src/siembiot/domains/network_adapter.py`
- Create: `services/api/src/siembiot/domains/emergency.py`
- Modify: `services/api/src/siembiot/domains/service.py`, `services/api/src/siembiot/domains/router.py`, `services/api/src/siembiot/main.py`
- Test: `tests/api/test_https_verification.py`, `tests/api/test_emergency_controls.py`, `tests/security/test_revocation_kill_switches.py`

1. Add failing tests for the fixed well-known path, exact token body, HTTP-to-HTTPS reauthorization, blocked destinations, global/org/domain/operation controls, reason/actor/time/expiry, immediate authorization revocation, support non-bypass, stale policy reads, queued rejection, cooperative in-flight cancellation, and safe recovery.
2. Run focused tests; expect missing integration failures.
3. Wire HTTPS challenge verification to the broker through a narrow adapter and persist only bounded outcome metadata. Implement emergency-control list/activate/deactivate/status routes and authoritative policy checkpoints.
4. Add global-control authorization requiring platform admin plus phishing-resistant MFA; tenant controls require owner/security admin and never inherit support bypass.
5. Run API, database, RLS, network, and security suites; expect pass.
6. Commit `feat: enforce revocation and emergency network controls`.

### Task 8: Romanian-first domain and authorization UI

**Files:**
- Create: `apps/web/src/app/organizations/[organizationId]/domains/page.tsx`
- Create: `apps/web/src/app/organizations/[organizationId]/domains/domain-panel.tsx`
- Create: `apps/web/src/app/organizations/[organizationId]/domains/[domainId]/page.tsx`
- Create: `apps/web/src/app/organizations/[organizationId]/domains/[domainId]/domain-detail.tsx`
- Create: `apps/web/src/lib/domain-state.ts`
- Modify: `apps/web/src/app/styles.css`, `apps/web/src/lib/secure-client.ts`
- Test: `apps/web/src/lib/domain-state.test.ts`, `apps/web/src/app/domain-flow.test.tsx`, `tests/security/test_web_security_invariants.py`

1. Add failing tests for the three distinct states, backend-only success, expiry/attempt display, DNS/HTTPS instructions, authorization scope/consent, revocation, suspension, loading/error/live-region behavior, permission denial, and absence of client-side signing/authorization decisions.
2. Run web tests; expect missing components/functions.
3. Implement accessible Romanian UI and typed client calls. Keep challenge plaintext only in the immediate creation view and never browser storage.
4. Run web tests, typecheck, and production build; expect pass.
5. Commit `feat: add Romanian domain authorization workflow`.

### Task 9: Operations, documentation, and complete verification

**Files:**
- Create: `docs/security/scan-authorization.md`
- Create: `docs/operations/emergency-controls.md`
- Modify: `docs/adr/0010-network-and-ssrf-safety.md`
- Modify: `docs/architecture/target-architecture.md`
- Modify: `docs/security/threat-model.md`
- Modify: `docs/development/setup.md`
- Modify: `CHANGELOG.md`, `Makefile`, `scripts/verify_repo.py`, `.github/workflows/ci.yml`
- Test: `tests/repository/test_foundation_commands.py`, `tests/repository/test_repository_invariants.py`

1. Add failing repository tests requiring `test-domain`, `test-network-safety`, and `e2e-verification` gates and banning direct collector network imports.
2. Implement the focused gates without weakening existing checks.
3. Document authorization language, PSL provenance/update review, key configuration/rotation, verification operations, blocked reason codes, kill-switch activation/recovery, audit/privacy behavior, and remaining deployment controls.
4. Run `python scripts/bootstrap.py`.
5. Run `python scripts/verify_repo.py`, `make test-domain`, `make test-network-safety`, and `make e2e-verification` (or exact Windows equivalents); expect all pass.
6. Run empty migration, downgrade/re-upgrade, full Python tests, web tests/type/build, contract drift, `git diff --check`, and `git show --check`.
7. Commit `chore: complete milestone 2 verification` and report exact counts, security boundaries, commit hash, clean worktree, blockers, and Milestone 3.
