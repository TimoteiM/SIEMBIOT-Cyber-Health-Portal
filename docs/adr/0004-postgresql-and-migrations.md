# ADR-0004: PostgreSQL and Migration Strategy

**Status:** Accepted — 2026-08-03

## Decision

PostgreSQL is the authoritative relational store. Use SQLAlchemy 2 and Alembic with forward-only production migrations and explicit forward-fix/restore procedures. CI creates a database from zero, upgrades from the previous release, checks model/schema drift, and tests RLS.

Tenant rows require `organization_id` foreign keys and constraints. Immutable records prohibit update/delete through permissions/triggers where appropriate. Destructive migrations use expand/backfill/contract across releases; deployment never assumes instant rollback of data changes.

## Consequences

JSONB supports versioned evidence payloads, but indexed/query-critical fields remain typed columns. Backups, PITR, and restore exercises are release-operational requirements.
