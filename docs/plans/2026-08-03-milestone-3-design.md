# Milestone 3 Fixture-Only Collectors Design

**Status:** Approved — 2026-08-03

## Objective

Milestone 3 validates typed provider adapters and deterministic collector behavior without supporting live internet assessment. DNS, e-mail DNS, HTTP, TLS, RDAP, and certificate-transparency collectors run only against a deterministic local fake-internet scenario pack through the centralized broker contract. They need no provider credentials and cannot open sockets or invoke HTTP/DNS libraries directly.

## Execution modes and activation boundary

The versioned execution contract distinguishes four states:

- `fixture`: the collector ran against a named, integrity-checked local scenario;
- `unavailable`: a declared capability/provider is absent or unhealthy;
- `disabled_by_policy`: policy, scope, cancellation, quota, or a kill switch denied execution;
- `live`: reserved for the future restricted-egress implementation and rejected by every Milestone 3 runtime factory.

Ordinary environment variables or application settings cannot enable `live`. Production startup fails closed if collector execution is requested without a future code-level restricted-egress attestation and broker implementation. Milestone 3 ships neither. A local fixture broker is an in-memory protocol simulator, not a network client: it exposes the same purpose-specific broker capabilities future workers will call but never opens a connection.

## Typed adapter framework

Every adapter publishes immutable metadata containing its contract/version, capabilities, terms/licensing note, input and output classification, required secret names, health semantics, timeout, rate unit, cost unit, cache rules, fixture support, and output schema identifier. Core adapters declare no secrets. Adapter startup validation rejects undeclared capabilities, secret-bearing fixture adapters, unsupported schemas, invalid budgets, and a request/metadata mismatch.

Results use structured states rather than exceptions as business outcomes. Provider disagreement is retained as separate source assertions with confidence and provenance; it is never collapsed into a synthetic truth. Missing or unhealthy sources produce explicit `unavailable`, `unknown`, or `error` observations and cannot become a pass.

## Broker and fake internet

Collectors depend only on a `CollectorBroker` protocol with purpose-specific operations:

- bounded DNS record lookup;
- bounded HTTP HEAD/GET for a canonical authorized host;
- bounded TLS handshake/certificate retrieval;
- bounded RDAP lookup;
- bounded local CT query.

There is no generic URL, arbitrary method, port, socket, shell, browser, crawl, or fallback API. The fixture broker loads versioned JSON/binary scenario data for DNS, redirects, headers/cookies, certificates, RDAP, CT, timeouts, rebinding, malformed/oversized responses, cancellation, and partial failures. It applies the same destination, redirect, size, timeout, concurrency, and checkpoint policy concepts as the centralized network safety module. SSRF-denied and rebinding fixtures are decisions, never attempted connections.

An architecture test permits network-library imports only inside the existing centralized network-safety implementation. Collector and adapter packages fail CI if they import `socket`, `ssl`, DNS resolvers, HTTP clients, subprocess/browser libraries, or construct direct network clients.

## Deterministic collectors

Six collectors consume broker responses and emit typed observations:

- DNS: NS, SOA, DNSSEC/DS, CAA, delegation and wildcard observations;
- e-mail DNS: MX, SPF, DMARC, MTA-STS, TLS-RPT, TLSA and only explicitly declared DKIM selectors;
- TLS: negotiated protocol/cipher and parsed certificate chain/hostname/validity metadata;
- HTTP: bounded redirect chain, status, security headers, public cookie attributes, canonical host and safe body metadata;
- RDAP: registration status/timestamps and redacted entity-role metadata;
- CT: fixture-only certificate/name assertions for later asset-candidate review.

No collector scores, creates findings, follows forms, authenticates, crawls, fuzzes, injects payloads, brute-forces selectors, enumerates objects, downloads arbitrary content, or executes scripts.

## Observation and run contracts

Every observation includes a versioned schema, evidence identifier, scope-manifest reference, exact collector/version, source adapter/version, collection timestamp supplied by the run clock, execution mode, scenario identifier/digest when fixture-backed, classification, outcome, confidence, freshness, and normalized typed payload. Evidence IDs are content-addressed from canonical input, provenance, and payload so reruns with the same clock/scenario are identical.

Fixture observations are permanently marked `fixture`, `publishable=false`, and `real_world=false`. Validation rejects attempts to relabel them or persist/present them as real-world findings. Milestone 3 stores no production evidence and creates no findings or scores; Milestone 4 persistence must enforce the same discriminator.

The deterministic suite runner orders steps, freezes budgets, supports cooperative cancellation, records per-step outcomes, and returns partial completion when independent collectors fail. Rate, concurrency, cost, and request quotas plus circuit-breaker state are deterministic and injected per run. Fixture time advances only through the scenario clock; tests never sleep or access the internet.

## Product visibility

The API exposes a typed collection-capability status declaring `fixture_only`, `live_execution=false`, and the missing restricted-egress dependency. The authenticated web shell displays a persistent Romanian fixture-only banner. Any collection summary intended for later report rendering carries a mandatory non-publishable fixture banner. Documentation and handoff language must say “collection behavior validation,” never “live assessment support.”

## Testing and acceptance

Tests cover adapter contracts, prohibited imports, broker-only interaction, each deterministic collector, malformed/hostile/oversized inputs, SSRF denial, redirect revalidation, rebinding, timeouts, cancellation, quotas, circuit breakers, disagreement, unavailable providers, partial completion, stable reruns, fixture-label immutability, and API/UI visibility. Test instrumentation fails if a process attempts external DNS or network access.

`make fixture-stack`, `make test-adapters`, and `make test-collectors` operate exclusively on the local scenario pack. The complete repository verifier remains green.

## Required later live-execution dependency

Live execution remains blocked until a later approved milestone provides all of the following as one reviewed boundary: restricted-egress broker service, isolated workers and outbound network policy, target reauthorization immediately before connection, DNS and redirect revalidation, provider-secret isolation, rate/concurrency/circuit-breaker/kill-switch enforcement, production deployment/security tests, and explicit activation approval. Partial completion of that list cannot enable live mode.
