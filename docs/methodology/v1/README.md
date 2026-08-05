# Methodology v1.0.0

**Status:** implementation draft. The weights, severities and caps below are an
original design and have **not** yet passed the security-expert, fairness and counsel
review that the [methodology specification](../methodology-specification.md) requires
before any public release. Do not publish scores produced by this version.

**Machine-readable source:** [`packages/policy/methodology/v1.0.0.json`](../../../packages/policy/methodology/v1.0.0.json)
and [`packages/policy/checks/v1/`](../../../packages/policy/checks/v1/).

## What this version computes

Three outputs stay separate and are never blended into one number:

| Output | Range | Source |
| --- | --- | --- |
| External security posture | 0–100 | Normalized technical evidence only |
| Coverage | 0–100% | Completed applicable weight ÷ known applicable weight |
| Confidence | high / medium / low | Weakest of attribution, source and freshness |

The organizational maturity score (0–5) is Milestone 7 and is deliberately absent here.

## Pillars and weights

| Pillar | Weight | Checks |
| --- | ---: | ---: |
| Domain and DNS resilience | 20% | 4 |
| E-mail trust | 20% | 5 |
| Web and TLS | 25% | 8 |
| Public attack surface | 15% | 2 |
| Reputation and abuse signals | 10% | 1 |
| Exposure hygiene and change resilience | 10% | 2 |

## Result states

Every check resolves to exactly one of the eight states, and each is treated distinctly.

| Result | Factor | Effect |
| --- | --- | --- |
| `pass` | 1.0 | Scores |
| `warning` | 0.5 | Scores |
| `fail` | 0.0 | Scores |
| `unknown` | — | Reduces coverage; never a pass or a fail |
| `error` | — | Reduces coverage; never a pass or a fail |
| `not_applicable` | — | Leaves the applicable denominator entirely |
| `suppressed` | — | Leaves the scoring denominator, stays visible and counted as covered |
| `accepted_risk` | — | Leaves the scoring denominator, stays visible and counted as covered |

The distinction that matters most: a collector that **proved** a record is absent
produces `absent`, which is scored. A collector that **could not tell** produces
`inconclusive`, which becomes `unknown` and is never scored. Missing data never
silently becomes either good news or bad news.

## Pillar and overall calculation

```
pillar_score = 100 × Σ(weight × factor) ÷ Σ(weight of score-bearing checks)
overall      = Σ(pillar_weight × pillar_score) ÷ Σ(pillar_weight of scored pillars)
```

A pillar with no score-bearing checks is `null`, not zero, and is excluded from the
overall weighting rather than dragging it down.

## Critical caps

A cap only ever lowers a score, always names the checks that triggered it, and fires
only on a **failing, high-confidence** check.

| Cap | Ceiling | Trigger |
| --- | ---: | --- |
| `expired_certificate` | 54 | `C.certificate_validity` fails |
| `no_https` | 54 | `C.https_available` fails |
| `certificate_hostname_mismatch` | 74 | `C.certificate_hostname` fails |

A shared-hosting observation, an uncertain fingerprint, a stale provider result or
provider disagreement can never trigger a cap: all of them lower confidence below
`high`, and the cap requires `high`.

## Bands

| Band | Range | Română | English |
| --- | --- | --- | --- |
| `resilient` | 90–100 | Rezilient | Resilient |
| `managed` | 75–89 | Gestionat | Managed |
| `developing` | 55–74 | În dezvoltare | Developing |
| `exposed` | 30–54 | Expus | Exposed |
| `critical` | 0–29 | Critic | Critical |

Below 60% coverage the band becomes `insufficient_coverage` regardless of the number,
so a thin assessment cannot be presented as a confident result. The Romanian labels
still need native-speaker review.

## Confidence

Attribution, source and freshness are recorded separately per observation. The roll-up
takes the **minimum**, not the mean — one weak dimension is never averaged away by two
strong ones. Every reduction records a machine-readable reason
(`attribution_uncertain`, `served_from_cache`, `evidence_aged`, `partial_collection`).

## Reproducibility

Every snapshot stores the methodology version, the policy digest (SHA-256 over the
canonical catalog) and the evidence digest (SHA-256 over the observation content
hashes). Identical evidence under an identical catalog always produces an identical
score.

```
make methodology-reproduce
```

regenerates [`reference-snapshot.json`](reference-snapshot.json) from a fixed fictional
evidence set and fails if anything changed. Recomputing historical evidence under a
newer methodology creates a snapshot marked `is_projection: true`; the database refuses
to overwrite the original.

## Public safety classification

Each check declares `public_aggregate`, `public_profile` or `private_only`. Cookie
attributes, asset candidates, wildcard exposure, reputation detail and banner
disclosure are `private_only` and must never reach the public projection. Enforcement
of that boundary is Milestone 9.

## Changelog

### 1.0.0 — 2026-08-05

First implementable catalog: 22 checks across pillars A–F, deterministic result
factors, three high-confidence caps, a 60% coverage floor, and the minimum-based
confidence roll-up.

**Known limitations.** Reputation has a single check that stays `unknown` until an
opt-in provider is configured. Pillar F covers only banner disclosure and evidence
freshness; secrets exposure, certificate/DNS change monitoring and remediation
verification are not implemented. No check yet covers dangling DNS or subdomain
takeover, which the specification requires before a public release.
