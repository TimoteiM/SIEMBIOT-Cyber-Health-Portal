# SIEMBIOT Cyber Health Portal Design

**Approved direction:** 2026-08-03 user decision
**Status:** Phase 0 design; implementation not started

## Decision summary

Build a separate greenfield monorepo. Treat Microsoft Tyche as read-only provenance and independently reimplement only Semantic Kernel orchestration/plugin concepts. Use deterministic collectors, normalizers, policy evaluation, and scoring as authority; isolate the agent as a bounded planner/analyst with schema-validated grounded output.

Use Next.js/TypeScript for the bilingual accessible web application; FastAPI/Python for APIs; PostgreSQL with application authorization plus RLS; Celery/Redis for bounded workers; S3-compatible private artifacts; Keycloak-compatible OIDC; isolated collector/egress, agent, and report workers; OpenTelemetry observability; Docker Compose locally and signed non-root OCI workloads in production.

## Why this approach

It best fits the supplied fallback architecture while preserving a single Python domain/collector stack and a typed TypeScript web stack. A monolithic Next.js-only implementation would make safe network collectors and Semantic Kernel integration less natural. A microservice-per-check design would add operational complexity before invariants are proven. The selected modular-monolith control plane with isolated high-risk workers creates meaningful security boundaries without premature service fragmentation.

## Authoritative boundaries

- API/policy service: identity, tenant/object authorization, consent, signed scope, state transitions.
- Collectors: bounded evidence collection only through central network policy.
- Evidence/scoring: immutable normalized observations and pure versioned evaluation.
- Agent gateway: no direct I/O or score authority; grounded schemas and deterministic fallback.
- Public projector: allowlisted safe fields only; no private-table public queries.

## Error and degradation model

Known result states distinguish failure, unknown, provider error, non-applicability, suppression, and accepted risk. Partial work is retained; progress is known-step completion. Provider/model failure is visible and lowers coverage or uses deterministic templates. Cancellation/deadlines propagate. Duplicate delivery is safe through database-backed idempotency.

## Security and test posture

Cross-tenant disclosure and out-of-scope connections have zero tolerance. TDD begins with authorization, domain/PSL, network policy, evidence/scoring, and agent-boundary tests. Real third-party scanning is prohibited in automated tests; deterministic fake DNS/HTTP/TLS/provider fixtures cover all states and attacks.

Detailed design: `docs/architecture/target-architecture.md`, `docs/security/threat-model.md`, ADRs, methodology specification, and implementation plan.
