# Contributing

Phase 0 changes must preserve the security invariants in `docs/security/threat-model.md` and update any affected ADR. Application changes will require tests first, generated-contract drift checks, tenant/scope authorization tests, and a clean secret scan.

No real third-party targets or production data may be used in tests. Use reserved domains, fictional organizations, and local fixture services only.

Commits should be narrow and auditable. Do not commit generated reports, credentials, `.env` files, provider payloads, or copied Tyche source.

## Closing a milestone

A change that completes a milestone must update `CHANGELOG.md` in the same pull request,
and the entry must carry **verification evidence rather than a narrative claim**: the
commands run and their exact results — gate count, test counts, exit codes — not "tests
pass".

The implementation plan's Definition of Done already required this per milestone. It was
not enforced, and the cost was measurable: on 2026-08-12 the changelog's most recent
verification entry recorded 14 gates and 44 Python tests against a measured 15 and 1129,
and its `Added` section ended six milestones earlier. Anybody reading it to find out what
this repository contained would have been misled for nine days.

A milestone is not closed because the code works. It is closed when somebody else can see
that it works without running it themselves.

State what is *not* done in the same entry. A changelog that lists only what was achieved
reads as a complete product, which is the failure this rule exists to prevent.
