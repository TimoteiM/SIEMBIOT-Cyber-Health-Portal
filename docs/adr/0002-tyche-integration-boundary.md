# ADR-0002: Tyche Integration Boundary

**Status:** Accepted — 2026-08-03

## Decision

Run Semantic Kernel in an isolated internal agent-gateway service. Inputs are tenant-scoped, minimized, redacted evidence views and versioned schemas. Outputs are structured proposals or narrative with evidence IDs. Tool requests go to the workflow/policy service; the gateway has no target, database, queue, object-store, notification, or collector credentials.

Deterministic services own collection, normalization, evaluation, scores, state transitions, and fallback templates. Every run has model/provider pinning, time/token/cost/concurrency/retry budgets, cancellation, trace IDs, and an immutable audit summary without chain-of-thought.

## Rejected

Direct plugin I/O, autonomous side effects, model scoring, raw prompt concatenation, cross-tenant memory, and unrestricted tool discovery.
