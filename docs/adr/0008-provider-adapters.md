# ADR-0008: Provider Adapter Framework

**Status:** Accepted — 2026-08-03

## Decision

Define typed adapters for DNS/RDAP, CT, TLS/HTTP, passive assets, reputation, notifications, model, reports, and object storage. Each declares capabilities, terms/licensing note, data classification, required secret names, health, timeout, rate semantics, cost unit, cache rules, fixture support, and output schema.

Core DNS/e-mail-record/TLS/certificate/header collectors require no paid key. Missing paid adapters produce explicit unavailable/unknown results. Provider disagreement is retained with source/confidence rather than collapsed.

## Consequences

Commercial dependencies remain optional and auditable. Adapters cannot bypass network/scope policy and never expose raw secrets or provider payloads to logs/models.

## Milestone 3 realization

The first implementation is deliberately fixture-only. Immutable descriptors and a deny-by-default registry enforce declared capabilities and reject fixture adapters that request secrets. A deterministic runtime enforces request, cost, concurrency, retry, cancellation, and circuit-breaker behavior and retains provider disagreement with source and confidence.

The only adapter is the local `fixture-internet` implementation. Live providers are unavailable or disabled by policy, and no ordinary configuration can change that state. See the [provider matrix](../providers/matrix.md).
