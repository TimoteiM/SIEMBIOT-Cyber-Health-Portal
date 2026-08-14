# Scan Authorization and Domain Ownership

## Security boundary

Domain ownership proof, assessment authorization, and network permission are separate gates. A successful DNS or HTTPS challenge proves temporary control of one exact canonical domain. It does not prove organizational identity, authorize a parent or child name, or permit collection. Assessment execution is unavailable until a later milestone and will require a current verified domain plus an active, signed, immutable scope manifest containing the exact target and operation class.

## Ownership lifecycle

The API normalizes user input with UTS 46/STD3 rules, stores the ASCII A-label and Unicode display form, and rejects IP literals, URLs, ports, paths, credentials, wildcards, trailing dots, and public suffixes. The vendored Public Suffix List provenance and checksum are recorded under `packages/policy/public_suffix_list/`.

Challenges are random `siembiot-v1=` values returned once. PostgreSQL stores only SHA-256 digests. DNS verification reads `_siembiot-verify.<canonical-domain>`; HTTPS verification reads only `https://<canonical-domain>/.well-known/siembiot-verification.txt`. A value must match exactly. Challenges expire, allow at most five attempts, permit only one pending challenge per domain/method, and are rate-limited to three creations per domain per hour by default.

## Authorization lifecycle

An authorized organization role creates a draft with exact domain IDs, operation classes, policy/consent versions, accepted consent text, and a validity interval. Acceptance freezes the authorization and produces a canonical Ed25519 manifest carrying a key ID and payload digest. Revocation is immediate and reasoned. Manifest consumers must verify signature, key ID, validity, authorization state, tenant, exact target, and exact operation class at use time.

## Explicit exclusions

Milestone 2 performs no public scans, passive assessments, active assessments, collector execution, provider lookup, scoring, or Tyche/model operation. The HTTPS request exists solely to validate an operator-created ownership challenge through the centralized safety broker.
