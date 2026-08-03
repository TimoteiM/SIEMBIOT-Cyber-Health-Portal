# Contributing

Phase 0 changes must preserve the security invariants in `docs/security/threat-model.md` and update any affected ADR. Application changes will require tests first, generated-contract drift checks, tenant/scope authorization tests, and a clean secret scan.

No real third-party targets or production data may be used in tests. Use reserved domains, fictional organizations, and local fixture services only.

Commits should be narrow and auditable. Do not commit generated reports, credentials, `.env` files, provider payloads, or copied Tyche source.
