# Consolidated status — 2026-08-12

Where the product stands against the release invariants in
[the product specification](product-specification.md) and the launch blockers in
[the Phase 0 review](phase0-review.md). Those are the master Definition of Done: the
specification calls the invariants "release blockers, not backlog items".

Written after the work of this session and measured, not asserted. The audit that preceded
it is [status-audit-2026-08-12](status-audit-2026-08-12.md); this is the position after.

**Verification at the time of writing:**

```
python scripts/verify_repo.py            exit 0 — 15/15 gates
python -m uv run --frozen pytest -q      1235 passed, 0 failed, 0 skipped
pnpm --filter @siembiot/web test         60 passed (8 files)
pytest tests/agent_security -q           70 passed
```

---

## Release invariants

### 1. No cross-tenant data disclosure — **verified**

Row-level security with `FORCE` on every tenant table, so it applies to the owner too. The
API refuses to start if it finds itself connected as a role that could bypass it — a
credential is a claim, `current_user` is the fact.

The agent gateway added a second boundary of the same kind: a claim citing evidence
outside its run's scope is dropped, and unknown evidence and another tenant's evidence
return **one** reason code, because "that exists but is not yours" confirms the existence
of another tenant's data.

*Evidence:* `tests/security/test_identity_tenant_authorization.py`,
`tests/agent_security/test_agent_boundary.py` (3 cross-tenant tests),
`tests/api/test_least_privilege.py`.

### 2. No out-of-scope network connection — **verified**

Every outbound request passes one broker that pins the resolved address, refuses private
ranges, bounds redirects and body size, and records what it touched. Collectors cannot
open sockets; an architecture test confines `dns`, `ssl`, `http`, `smtplib` and `asyncio`
imports to the network-safety module.

The passive/authorized split is enforced by operation class, not by convention: a passive
run never asks for an authorized operation rather than asking and being refused.

*Evidence:* `tests/network/`, `tests/security/test_network_architecture.py`,
`tests/security/test_observation_mode.py`.

### 3. No public release of actionable private detail — **verified in code, blocked on review**

The observatory reads through a separate database role that cannot resolve a tenant table
at all. Checks carry a `public_safety_class`; the three port checks are `private_only`,
because a public page listing which institutions have remote desktop open would be a
target list.

**Blocked:** the specification requires counsel and privacy review before live catalogue
data, and no such record exists.

*Evidence:* `tests/api/test_public_observatory.py`, `tests/api/test_publication.py`.

### 4. No agent-authored evidence or score — **verified**

Now testable rather than true by absence. Every gateway tool is read-only; the narrative
schema has nowhere to put a score, a band or a severity; a claim asserting one is dropped
even when correctly cited, in both languages, because the objection is not that it might
be wrong but that it is not the model's to make.

*Evidence:* `tests/agent_security/test_agent_boundary.py`,
`tests/agent_security/test_agent_contracts.py`.

### 5. Authorization and audit history cannot be silently rewritten — **verified**

Audit was append-only and **not** tamper-evident: `previous_hash` and `event_hash` existed
from the first migration and nothing ever wrote them. Events are now chained per
organisation by a database trigger, so the chain covers writes that never went through the
application. Altering a row, deleting one from the middle, and inserting a forged row with
both triggers disabled are each detected and named.

Existing rows were deliberately **not** backfilled: hashing them now would certify
whatever they say today, and a chain reporting a spotless history it cannot vouch for is
worse than no chain.

*Evidence:* `tests/security/test_audit_chain.py` (11 tests, mostly attacks).

### 6. Core demo and deterministic collectors work without paid providers or a model — **verified**

Nine collectors, none requiring a credential — asserted by a test, not by the README,
because the moment one does, a public body's data starts reaching a commercial service.
The full assessment-to-report flow runs with the model disabled, which is the only
configuration this platform has ever run in.

*Evidence:* `tests/api/test_providers.py::test_no_shipped_provider_needs_a_credential`,
`tests/agent_security/test_disabled_gateway_fallback.py` (4 tests).

### 7. Model or provider outage degrades to visible unknown/unavailable states — **verified**

A provider outage is an ordinary outcome with its own audit record, not an incident. An
exhausted budget returns what it has. An inconclusive collection stays inconclusive and is
never flattened into "absent", because absent is a proven negative and gets scored.

The metrics endpoint was itself failing this invariant: a series vanished when its table
was empty, making "nothing happened" indistinguishable from "the exporter is broken". Every
described metric is now always emitted.

*Evidence:* `tests/agent_security/test_agent_boundary.py`,
`tests/operations/test_alert_rules.py`, `tests/policy/`.

### 8. No launch while the upstream credential exposure is undispositioned — **blocked, external**

Outside this repository's authority. Unchanged.

---

## Launch blockers

| Blocker | Status |
| --- | --- |
| Upstream Tyche credential rotation and history disposition | **external, open** |
| DPIA, privacy and legal review; responsible-publication approval | **external, open** — you are moving this |
| Independent security review and penetration test | **external, open** — you are moving this |
| Verified backup restore | **done** — executed against a real database, checking schema, row counts, forced RLS, append-only triggers, roles and the audit chain |
| Production-like smoke, release gates, zero critical/high defects | **partial** — 15 gates pass; no release-check target, no container or IaC scanning, no signed artifacts |
| Direct evidence for every Definition of Done journey | **partial** — see the invariants above |

The third blocker on the specification's separate list — the licensing review of the NIS2
Article 21 and CIS v8.1 mappings before the maturity catalogue is finalised — is also open
and also yours. Eight policy documents remain `review_status: draft` and are labelled as
draft wherever they are displayed.

---

## Milestones

| # | Status | What is missing |
| --- | --- | --- |
| 0–5 | complete | `docs/operations/jobs.md` was never written |
| 6 | built and tested | **no provider adapter ships**; the analyst panel does not distinguish Measured / Inferred / Recommended |
| 7 | built | **licensing and legal review** of the NIS2 and CIS mappings |
| 8 | mostly complete | dedicated e-mail and web/TLS posture pages; visual-regression and accessibility suites |
| 9 | built | **counsel and privacy review** before live catalogue data |
| 10 | mostly complete | backup **destination** not configured; PITR decided but not configured; log aggregation; TLS termination; `infra/deploy/`; container and IaC scanning; signed artifacts |
| 11 | partial | release-check target; release candidate; independent penetration test |

---

## What changed this session

Ordered by how much it changed what the product can honestly claim.

**Milestone 6, from nothing to tested.** The audit found no gateway, no schemas, no test
directory and no model integration. There is now a gateway with versioned contracts, a
claim validator written before anything that could call a model, a closed read-only tool
set, per-run budgets, and 70 adversarial tests. It ships no provider, and that is stated
in the README rather than folded into a summary.

**The audit trail became tamper-evident.** It had looked tamper-evident for five months.

**Retention and erasure.** Evidence accumulated indefinitely because nothing removed it;
an institution could not ask to be forgotten. Both exist, both have named refusals, and
the per-organisation audit chain is what makes erasure possible without breaking everybody
else's trail.

**Quota became a real budget.** Four workers with a limit of a thousand would have made
four thousand calls, each worker correctly believing it complied. Now shared in Redis with
an atomic consume, snapshotted to PostgreSQL, and alertable.

**Alerts reach somebody**, demonstrated end to end — and one rule could never have fired,
because it named a metric the exporter dropped whenever its table was empty.

**Reports leave the platform**, as HTML and as PDF, with injection prevented structurally
rather than by discipline.

---

## What I would do next, and what I would not

**Worth another session:** the M8 posture pages are cosmetic and can wait. The two items
with real weight are the **backup destination** — the schedule and the refusals exist, so
this is a bucket and a credential away from being true rather than a design problem — and
**container and IaC scanning**, which is the last gate-shaped gap before a release
candidate means anything.

**Not worth starting until the reviews land:** the maturity catalogue cannot be finalised
before the licensing review, the observatory cannot carry live data before counsel, and a
release candidate cannot be tagged before the penetration test. Building around any of
those would produce work that has to be redone once the answer arrives.

**A note on this machine.** `.venv` and `.next` sit on a OneDrive-synced path, and file
locks failed the gates six times across this session — `os error 5`, `EPERM`, always
transient, always clearing on retry. None was a code failure, and every 15/15 above is a
clean run. It does mean Milestone 0's "clean clone bootstraps" is true here only with
retries, which is worth knowing before somebody reads a red gate as a defect.
