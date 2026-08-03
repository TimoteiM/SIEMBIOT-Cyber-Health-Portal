# Phase 0 Consistency Review

**Reviewed:** 2026-08-03
**Disposition:** internally consistent design baseline; application implementation not started

## Master-brief traceability

| Requirement domain | Primary artifact | Status |
| --- | --- | --- |
| Tyche code-confirmed audit, license, baseline gates | `repository-audit.md` | Covered; prototype limitations explicit |
| Separate product experiences and claims | `product-specification.md`, ADR-0009 | Covered |
| Verification, authorization, scan safety | product specification, ADR-0010, threat model | Covered |
| Architecture/services/data/queue/storage | target architecture, ADR-0004/0005/0006 | Covered |
| Tyche authority/restrictions/contracts | adaptation boundary, ADR-0002, plan M6 | Covered |
| Deterministic methodology/scoring | methodology specification, ADR-0007 | Draft values require pre-1.0 validation |
| Providers/no-key degradation | ADR-0008, plan M3 | Covered |
| Auth/RBAC/tenant isolation | ADR-0003, threat model, plan M1 | Covered |
| Public/private separation/moderation | ADR-0009, plan M9 | Covered |
| UX/localization/accessibility/reports | product specification, plan M8/M9 | Covered |
| Testing/CI/demo/operations/release | implementation plan M0–M11, ADR-0011 | Covered as planned, not implemented |
| Current standards/NIS2/Romanian context | source register | Covered; expiry/review policy defined |
| Threats/privacy/legal constraints | threat model | Covered; counsel/DPIA gates remain open |

## Cross-artifact checks

- PostgreSQL, not Redis or the agent, is authoritative for workflow/evidence state.
- Only the policy/scope service authorizes; the collector and agent cannot self-authorize.
- Only deterministic normalizers/evaluators create evidence, findings, and scores.
- The public projector is the only private-to-public path and uses an allowlist.
- All target network I/O uses the central egress policy and reauthorization.
- Agent and provider outages preserve deterministic workflows and visible coverage.
- No document claims Phase 0 artifacts are a working product or compliance certification.
- Tyche remains read-only and no exposed value is present in SIEMBIOT.

## Decisions intentionally deferred but gated

- production hosting provider/jurisdiction and managed-service selection;
- accountable legal entity, final privacy roles/retention schedule, and subprocessor terms;
- counsel approval of public-interest scoring and active-test authorization;
- final validated methodology weights/caps/cohort threshold;
- production identity-provider choice within the accepted OIDC contract;
- provider contracts and model data-use/transfer terms.

These do not block foundation implementation because interfaces are provider-neutral, but they block live-data staging or production launch where indicated.

## Launch blockers

- upstream Tyche credential rotation/history disposition;
- DPIA/privacy/legal review and responsible-publication approval;
- independent security review and penetration test;
- verified backup restore, production-like smoke, release gates, and zero critical/high defects;
- direct evidence for every Definition of Done journey.
