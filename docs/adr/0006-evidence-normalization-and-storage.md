# ADR-0006: Evidence Normalization and Storage

**Status:** Accepted — 2026-08-03

## Decision

Collectors emit immutable raw-artifact metadata and typed `NormalizedObservation` records. Raw bytes/provider payloads go to encrypted S3-compatible storage only when necessary; PostgreSQL stores content hashes, provenance, classification, retention, and normalized fields. Normalizers are deterministic and versioned.

Evidence is append-only and references the signed scope manifest, adapter version, collection time, source, freshness, and hash. Untrusted strings are size-limited and escaped. Model-facing views are separately minimized/redacted. Uploads require content-type/signature validation, size limits, malware scanning, quarantine, and object authorization.

## Consequences

Scores are reproducible without mutating evidence. Storage and privacy cost are controlled by data-class retention schedules and cryptographic erasure where lawful.
