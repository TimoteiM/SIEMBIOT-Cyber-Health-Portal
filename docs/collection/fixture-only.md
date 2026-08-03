# Fixture-Only Collection

> **FIXTURE DATA — NOT A LIVE ASSESSMENT**

Milestone 3 validates collector contracts and deterministic behavior using an in-memory fake internet. It does not scan, resolve, connect to, or assess any live target or provider. Fixture observations are permanently marked `fixture`, `publishable=false`, and `real_world=false`; they cannot become findings or scores.

## Modes

| Mode | Meaning in Milestone 3 |
| --- | --- |
| `fixture` | The only executable mode; reads integrity-checked local scenario files. |
| `unavailable` | A structured result state for absent fixture/provider data. |
| `disabled_by_policy` | A structured result state for operations prohibited by policy. |
| `live` | Reserved for a future reviewed contract and always rejected. |

No environment variable, feature flag, tenant role, support grant, URL, method, port, provider token, or fallback can enable live execution. Production collector startup fails closed because the required restricted-egress attestation has no Milestone 3 constructor.

## Fake internet

The versioned pack at `tests/fixtures/fake_internet/v1` contains fictional `.test` and `.invalid` data for deterministic DNS, e-mail DNS, HTTP, TLS, RDAP, CT, private/mixed destinations, DNS rebinding, redirects, cancellation, malformed responses, timeouts, size limits, partial failure, and unavailable data.

The manifest hashes every scenario and synthetic TLS artifact. `make fixture-stack` validates these hashes and starts no service. The broker exposes only `resolve_dns`, `fetch_http`, `handshake_tls`, `query_rdap`, and `query_ct`; it has no generic request method and imports no network transport.

## Provenance and reporting

Every observation includes the scope reference, evidence identifier, collection timestamp, collector and adapter versions, scenario identifier/digest, execution mode, classification, outcome, confidence, freshness, and normalized payload. Evidence identifiers hash canonical provenance and payload data. Reports retain the fixture banner, report `live_assessment=false` and `scoring=not_performed`, and are non-publishable.

## Live dependency

Live execution requires all eight controls in [Live Execution Activation Dependency](../plans/live-execution-activation-dependency.md), production-like security tests, and explicit product/security approval. Partial delivery never enables it.
