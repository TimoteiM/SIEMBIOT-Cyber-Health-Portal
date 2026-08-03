# ADR-0005: Durable Queue and Workers

**Status:** Accepted — 2026-08-03

## Decision

Use Celery with Redis for task delivery/rate buckets, dedicated worker pools, and PostgreSQL as authoritative workflow state. Each step has a deterministic idempotency key, lease, deadline, retry classification, bounded exponential backoff with jitter, cancellation check, and durable attempt record. Dead-letter replay is an audited operator action.

Separate orchestration, collector, agent, and report queues. Prevent duplicate active runs for the same scope/profile using database constraints/advisory locks. Progress is completed known steps, never elapsed-time animation.

## Consequences

Queue loss or duplicate delivery cannot corrupt authoritative state. Celery cancellation is cooperative; every expensive/network boundary must check cancellation and deadline.
