# Milestone 4 Evidence, Policy, Scoring, and Findings Design

**Status:** Approved — 2026-08-03

**Branch:** `implementation/milestone-4`

**Exact base:** `8a50687bb8cd10fe5dc18712d1672aed3dfa147c` (`implementation/milestone-3`)

**Ancestry constraint:** This is a stacked branch that depends on Milestone 3. It must not merge to `main` before Milestone 3. Milestone 3 history must not be silently rebased, squashed, or rewritten. After Milestone 3 reaches `main`, ancestry reconciliation and the complete baseline and Milestone 4 verification suites are required before merge.

## Objective and boundary

Milestone 4 turns immutable, typed collector output into reproducible normalized evidence, deterministic check evaluations, posture snapshots, and finding history. Policy data and pure functions are authoritative. No model, agent, provider, or live target is required or allowed to influence scoring.

Milestone 4 remains fixture-only in executable demonstrations. Fixture provenance is structural and propagates from source evidence through observations, evaluations, findings, snapshots, reports, and exports. Fixture-derived objects are permanently classified `fixture`, `publishable=false`, `real_world=false`, and visibly `DEMO/FIXTURE`. No role may relabel them or publish them. Mixed fixture/live inputs are rejected. Live execution remains blocked by the separately documented activation dependency.

## Versioned contracts and canonical identity

JSON Schemas define `NormalizedObservation`, `CheckEvaluation`, `Finding`, `FindingEvent`, `ScoreSnapshot`, `ScoreAttribution`, raw-artifact metadata, and provenance. Contract schema versions, policy content versions, scoring behavior versions, methodology versions, canonicalization versions, and fingerprint versions evolve independently when their compatibility boundaries differ.

Canonical JSON version 1 uses UTF-8 JSON with lexicographically sorted object keys, no insignificant whitespace, JSON primitives only, and rejection of non-finite numbers, ambiguous timestamps, duplicate keys, and unsupported values. Timestamps are normalized to UTC with an explicit offset. Hash inputs are declared by typed identity projections; volatile database identifiers and insertion timestamps are excluded only when a versioned contract explicitly says so. SHA-256 version 1 is used for content identity. Golden vectors prove that semantically identical inputs hash identically across runs and that meaningful provenance or payload changes alter the hash.

Hashes never include secrets or unnecessary raw provider content, never authorize access, and are never exposed as cross-tenant lookup keys. Tenant and authorized-asset boundaries remain part of evidence and finding identity.

## Policy catalog

Reviewed policy-as-data lives under `packages/policy/checks/v1/`. Every check has a stable ID that is never repurposed, a policy schema/content version, accepted evidence schema, pillar, applicability rule, result mapping, weight, severity, freshness requirement, confidence and attribution requirements, optional critical cap, remediation, references, public-safety classification, and deprecation/replacement metadata.

Repository verification validates the complete catalog and rejects duplicate IDs, unsupported versions, invalid or dangling references, missing remediation, invalid result mappings, and inconsistent pillar or weight definitions. Each evaluation and snapshot pins the exact policy content hash. A newer policy or methodology produces a new immutable projection and never overwrites historical results.

## Deterministic processing pipeline

Versioned normalizers accept immutable collector observations and produce bounded `NormalizedObservation` values without retaining unnecessary hostile or sensitive source content. The first catalog covers the Milestone 3 fixture families: DNS resilience, e-mail trust, HTTP security controls, TLS posture, RDAP registration signals, and CT attribution signals.

Pure evaluation preserves `pass`, `fail`, `warning`, `unknown`, `error`, `not_applicable`, `suppressed`, and `accepted_risk`. Missing, unknown, and error evidence never becomes pass or fail. Not-applicable checks leave the applicability denominator and do not reduce coverage.

The scoring engine produces four separate outputs:

- technical posture score;
- evidence coverage;
- evidence confidence;
- attribution confidence.

Coverage and confidence are never blended into posture. Pillar scores use only score-bearing completed applicable checks. An overall score is omitted when policy-defined minimum coverage is not met. Critical caps may lower a score only when the policy explicitly defines the cap and evidence is current, required, high-confidence, directly attributable to an authorized asset, and non-fixture. Shared hosting, stale evidence, uncertain attribution, fixture evidence, or provider disagreement cannot trigger a cap.

Monotonicity is asserted only with fixed methodology, applicability, coverage, confidence, and attribution. Changes outside those controls require an explicit attribution record rather than artificial monotonic behavior. Recalculation under new methodology creates a separately identified snapshot with methodology-effect attribution.

## Persistence and tenant boundary

PostgreSQL stores append-only raw-artifact metadata, normalized observations, evaluations, score snapshots, findings, finding occurrences, finding events, and score attributions. Tenant-owned rows carry `organization_id`, authorized scope/asset references, evidence mode, schema versions, content hashes, and provenance.

Database `CHECK` and foreign-key constraints prevent mode mixing and indirect cross-tenant references. RLS is enabled and forced for all tenant-owned tables. Restricted application roles receive insert/select only where required and no update/delete privileges on immutable records. Database triggers reject update/delete even if privileges are accidentally broadened. Application repositories expose no mutation methods for immutable records.

Integration tests use the actual restricted application role and cover missing tenant context, forged tenant identifiers, cross-tenant primary and content-hash lookups, cross-tenant joins, indirect references, and explicitly scoped background processing. Publication paths and future public projections reject fixture-derived rows in both application logic and database constraints.

Development rollback may remove the Milestone 4 schema only in disposable local databases. Shared or production-like environments use forward fixes or point-in-time recovery; immutable assessment history is never rewritten by downgrade logic.

## Findings and state projections

Finding fingerprint version 1 includes tenant, authorized asset identity, check ID, policy content hash, material evidence key, evidence mode, and compatible attribution state. It never merges findings across tenants, assets, policy versions, execution modes, or incompatible attribution. A same-fingerprint/different-identity collision fails closed with a diagnosable safe reason code and audit event.

First-seen and occurrence history are immutable. Suppression, accepted risk, reopening, expiry review, and remediation verification append versioned events containing reason, authorized actor, scope, timestamp, expiry or review date, request/correlation ID, and audit reference. A deterministic projection derives current state. Expiry makes a decision visible for review without altering its historical event.

## Security and error handling

All inputs are schema validated, size bounded, canonicalized, and treated as untrusted data. Error outputs contain stable reason codes and correlation IDs, not raw evidence or secrets. Authorization runs before tenant object lookup. Content hashes are scoped by tenant and cannot be used for global enumeration. Fixture classification is validated at contract, service, database, report/export, and publication boundaries.

## Verification

TDD covers schema rejection, canonical hash golden vectors, policy validation, deterministic normalization, every evaluation outcome, score reproducibility, fixed-condition monotonicity, sensitivity, missing data, critical-cap eligibility, coverage/confidence separation, attribution, fingerprint collision handling, immutable finding events, and fixture-mode propagation.

PostgreSQL integration tests prove empty upgrade and previous-head upgrade behavior, RLS with the restricted application role, append-only triggers and privileges, forged and missing tenant context denial, indirect cross-tenant reference denial, and structural fixture/publication separation. Repository verification adds policy validation and methodology reproduction gates. The full existing fixture/network/security suite remains green.
