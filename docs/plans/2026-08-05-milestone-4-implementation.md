# Milestone 4 — Evidence, policy catalog, scoring, and findings

**Status:** implemented. Verified on 2026-08-05 with Docker available, so the
database-backed suites ran for the first time since Milestone 2.

**Goal:** turn the Milestone 3 collector payloads into deterministic, reproducible,
versioned scores and findings, with no model involved anywhere in the path.

## What was built

### Evidence contracts

`packages/contracts/jsonschema/evidence/v1/` publishes `NormalizedObservation`,
`CheckEvaluation`, `ScoreSnapshot`, `Finding` and a shared `Confidence`. Contract tests
feed **real engine output** through the validators, so the schemas cannot drift from the
code that produces them.

### Policy as data

`packages/policy/methodology/v1.0.0.json` and `packages/policy/checks/v1/` hold the
entire methodology as reviewed configuration: 22 checks across all six pillars, with
weights, severities, ordered rules, applicability, remediation templates, public-safety
classes and bilingual titles. `catalog.py` loads it, validates it strictly, and computes
a SHA-256 digest that every snapshot records.

The loader refuses a catalog that is internally inconsistent — weights that do not sum
to one, non-contiguous bands, a cap referencing an unknown check, a pillar with no
checks, a check missing localized text or a remediation template.

### The four engines

| Module | Responsibility |
| --- | --- |
| `normalization.py` | Collector payload → immutable, content-addressed observation |
| `evaluation.py` | Observation + check → one of the eight result states |
| `scoring.py` | Evaluations → pillar scores, caps, coverage, confidence, snapshot |
| `findings.py` | Evaluations → fingerprinted findings with history and suppression |

All four are pure functions over data. None imports a network client or a model.

### The distinction the whole milestone rests on

A collector that **proved** a record is absent produces `absent`, which is scored. A
collector that **could not tell** produces `inconclusive`, which becomes `unknown` and
is excluded from the numerator while reducing coverage. Missing data never silently
becomes good news or bad news. `test_inconclusive_collection_never_becomes_a_pass_or_a_fail`
asserts this end to end.

### Caps

Three caps ship, all requiring a **failing, high-confidence** check. Because a
shared-hosting observation, a stale provider result or provider disagreement all push
confidence below `high`, none of them can trigger a cap — the brief's explicit
requirement, asserted directly in `test_shared_hosting_style_uncertainty_cannot_cap_a_score`.

### Immutability

Migration `0006` makes observations, evaluations, snapshots and finding history
append-only through triggers, and freezes finding identity columns while allowing state
to change. A database constraint independently rejects a snapshot whose cap raised the
score. Row-level security mirrors the Milestone 1 helpers.

## Verification

| Command | Result |
| --- | --- |
| `make policy-validate` | 27 passed |
| `make test-scoring` | 66 passed |
| `make test-normalization` | 13 passed |
| `make methodology-reproduce` | reproduced exactly |
| `make providers-check` | matrix up to date |
| `uv run pytest` (full, Docker up) | **494 passed** |
| `uv run mypy` (strict) | no issues in 113 files |
| `uv run ruff check` / `format --check` | clean |
| `alembic heads` | `0006_evidence_scoring_findings` |

The 36 database-backed tests that could not run during Milestone 3 were executed and
pass, along with 27 new ones covering the evidence schema constraints.

The reference domain in `docs/methodology/v1/reference-snapshot.json` scores **90.1
(resilient)** at 93.7% coverage from 17 passes, 4 warnings and 1 unknown.

## Notes and limitations

- **The methodology is not review-approved.** Weights, severities and caps are an
  original draft. The security-expert, fairness and counsel reviews the specification
  requires have not happened. Scores from this version must not be published.
- Reputation has a single check that stays `unknown` until an opt-in provider is
  configured, so pillar E contributes nothing to a keyless assessment today.
- Pillar F covers only banner disclosure and evidence freshness. Secrets exposure,
  certificate/DNS change monitoring and remediation verification are not implemented.
- No check covers dangling DNS or subdomain takeover yet; the specification requires it
  before a public release.
- The engines are not yet driven by a workflow and nothing persists them to the new
  tables — orchestration and the repository layer are Milestone 5.
- Romanian check titles and band labels still need native-speaker review.
