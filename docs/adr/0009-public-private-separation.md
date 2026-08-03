# ADR-0009: Public/Private Information Separation

**Status:** Accepted — 2026-08-03

## Decision

Private tenant data and a sanitized public read model are separate authorization/data paths. An allowlisted projector emits only approved identity, score/band/pillar, assessment date, trend, methodology, coverage/confidence, and consent/moderation fields. Exact weaknesses, evidence, assets, infrastructure, people, and remediation never enter the projection.

Publication requires explicit revocable consent for private organizations and moderation policy for public-interest observation. Aggregates require configured minimum cohorts and disclosure controls. Correction, takedown, emergency suppression, and projection rebuild are audited.

## Consequences

Public APIs cannot query private tables directly. Revocation is fast, but private immutable history remains under retention/legal policy.
