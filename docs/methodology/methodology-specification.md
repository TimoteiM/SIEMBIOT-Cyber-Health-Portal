# Methodology Specification v0.1-draft

**Status:** original design for implementation/testing; not yet validated against real assessments
**Review date:** 2026-08-03

## Principles

The methodology is transparent, reproducible, versioned, evidence-driven, conservative about attribution, and safe for public disclosure. It does not reproduce any undisclosed third-party formula. A score is a prioritization aid, not a security guarantee or legal compliance determination.

## Policy-as-data check contract

Each check defines: stable `check_id`; version; localized title/rationale; pillar; collection mode; applicability expression; accepted observation schema/version; weight; severity; critical cap; result rules; remediation template/version; public-safety class; reference IDs; freshness window; and deprecation/replacement metadata.

Policy changes require review, golden fixtures, changelog, and a new methodology version. Completed assessments retain their original policy/input snapshot.

## External posture calculation

Pillars initially use these transparent weights, subject to validation before methodology 1.0:

| Pillar | Draft weight |
| --- | ---: |
| Domain and DNS resilience | 20% |
| E-mail trust | 20% |
| Web and TLS | 25% |
| Public attack surface | 15% |
| Reputation and abuse signals | 10% |
| Exposure hygiene/change resilience | 10% |

For applicable, score-bearing checks, deterministic result factors are: `pass=1.0`, `warning=0.5`, `fail=0.0`. `unknown`, `error`, `not_applicable`, `suppressed`, and `accepted_risk` do not contribute a hidden factor. Unknown/error reduce coverage; not-applicable is removed from the applicable denominator; suppressed/accepted-risk remain visible and follow explicit policy for score snapshot continuity. These semantics must be resolved in policy tests before 1.0 and never changed within a version.

`pillar_score = 100 × Σ(weight × factor) / Σ(weight of score-bearing completed applicable checks)`.

The overall score is the weighted mean of applicable pillars, followed by explicit critical caps. A cap can only lower the result and names the triggering check(s). At least one cap example and justification must be published for each cap class. If minimum coverage is not met, show an insufficient-coverage state rather than a deceptively precise overall score.

Bands are draft: `0–39 critical`, `40–59 weak`, `60–74 developing`, `75–89 good`, `90–100 strong`. Public labels use sober language and show coverage/confidence/date/methodology.

## Coverage and confidence

`coverage = completed_applicable_weight / known_applicable_weight × 100` with explicit reporting of checks whose applicability could not be determined.

Confidence is not one scalar disguised as truth. Each observation records attribution confidence, source confidence, and freshness. A deterministic roll-up yields High/Medium/Low with reasons. Shared hosting, weak asset attribution, stale data, and provider disagreement lower confidence but do not automatically create failures.

## Maturity calculation

Answer values: `implemented=5`, `partially_implemented=3`, `planned=1`, `not_implemented=0`; `not_applicable` leaves the denominator; `unknown` reduces completeness and has no hidden score. Domain scores are weighted means on 0–5. Evidence support is a separate state and never silently boosts the self-attested score. Results show baseline/extended path, completeness, self-attested/evidence-supported coverage, gaps, and versioned NIS2/CIS mappings.

## Finding generation

Only deterministic check evaluations create findings. Stable fingerprinting uses tenant, authorized asset identity, check ID, and material evidence key. Findings retain first/last seen, state/history, severity, confidence, business impact template, evidence references, remediation and validation steps. Tyche may rewrite an approved remediation into audience-appropriate language only when references remain grounded.

## Score-change attribution

Diffs compare like methodology versions directly. When methodology changes, the UI separates observed control change from methodology effect and, where feasible, computes old/new policy against the same evidence snapshot. It never attributes a delta to remediation without evidence.

## Public safety

Checks are classified `public_aggregate`, `public_profile`, or `private_only`. Dangling DNS indicators, hosts/IPs/ports/products, exact header/DNS weaknesses, evidence, reputation-provider detail, and remediation are private-only. Public data uses safe bands/pillars and thresholded aggregates. Publication logic is independent of score logic.

## Validation required before 1.0

- security-expert review of weights, caps, staging guidance, and false-positive behavior;
- fictional/local-fixture golden cases spanning every result state;
- sensitivity and monotonicity analysis;
- stability across provider disagreement and missing data;
- fairness/public-interest/counsel review;
- Romanian/English comprehension and accessibility testing;
- signed methodology artifact, canonical source register, changelog, and reproducibility command.
