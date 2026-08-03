# ADR-0007: Deterministic, Versioned Scoring

**Status:** Accepted — 2026-08-03

## Decision

Store checks and methodology as reviewed policy data with stable IDs, applicability, evidence schema, weight, severity, caps, public classification, remediation template, references, and methodology version. A pure engine maps normalized observations to result states, then computes pillar and overall posture scores. Questionnaire scoring is a separate pure engine on a 0–5 scale. Coverage/confidence remains separate.

Unknown/error/suppressed/accepted-risk/not-applicable states are not silently treated as pass/fail. Critical caps are explicit and testable. A published snapshot pins policy and inputs; Tyche cannot change it.

## Consequences

Golden fixtures can reproduce every score and delta. Methodology changes create a new version and may require side-by-side historical recalculation, never silent rewriting.
