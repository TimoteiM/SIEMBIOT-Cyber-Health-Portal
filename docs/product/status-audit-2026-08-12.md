# Status audit — 2026-08-12

A ground-truth audit of what this repository contains, against what the implementation
plan specifies and what the README and CHANGELOG claim. Every row is backed by a command
that was run, not by reading a document that asserts it.

Commit audited: `3910fcf`, branch `milestone-3-4-collection-and-scoring` (identical to
`main` and `origin/main`).

---

## 1. Verification actually run

`make` is not installed on this host; the Makefile targets were run as their underlying
commands, which is what the Makefile invokes.

### `python scripts/bootstrap.py`

Exit **0** — on the second attempt. The first attempt failed:

```
[bootstrap] sync-python
Resolved 66 packages in 10ms
error: failed to remove directory `...\.venv\Lib\site-packages\uv-0.12.1.dist-info\sboms`:
Access is denied. (os error 5)
[bootstrap] failed: sync-python
```

This is OneDrive holding files in `.venv` under sync, not a defect in the repository. It
recurred once during this audit and cleared on retry both times. Worth recording because
a clean-clone bootstrap on a OneDrive-synced path is not reliably reproducible, and
Milestone 0's acceptance is "clean clone bootstraps without paid keys".

### `python scripts/verify_repo.py`

Exit **0**. All fifteen gates, in order:

```
[check] phase0        Phase 0 verification passed: 395 files, 11 ADRs, no structural errors
[check] repository    Ran 6 tests in 0.383s — OK
[check] locks
[check] format
[check] lint          All checks passed!
[check] types
[check] unit          1129 passed in 74.76s
                      Test Files 8 passed (8) | Tests 60 passed (60)
[check] contracts     API contract drift check passed.
[check] migrations
[check] secrets
[check] images
[check] i18n
[check] sbom
[check] docs
[check] diff
Repository verification passed: 15/15 gates
```

### Test suites standalone

| command | result |
| --- | --- |
| `uv run --frozen pytest -q` | **1129 passed**, 0 failed, 0 skipped, exit 0 |
| `pnpm --filter @siembiot/web test` | **60 passed** across 8 files, exit 0 |

### Against the CHANGELOG's last verification entry

CHANGELOG records, dated 2026-08-03: *"`python scripts/verify_repo.py` (14/14 gates; 44
Python and 3 web tests) … `pytest -q` (44 passed)"*.

| | CHANGELOG (2026-08-03) | measured now |
| --- | --- | --- |
| gates | 14 | **15** |
| Python tests | 44 | **1129** |
| web tests | 3 | **60** |

**The CHANGELOG is stale, confirmed.** Its `Added` section ends at Milestone 4. Six
subsequent milestones' worth of work — orchestration, maturity, reports, observatory,
retention, erasure, audit chaining, alerting — has no entry at all.

---

## 2. Milestone 6 in detail

The audit's primary question. Answered by inspection, not inference.

| deliverable (from the plan) | present? | evidence |
| --- | --- | --- |
| `services/agent-gateway/` | **No** | `ls: cannot access 'services/agent-gateway': No such file or directory` |
| `packages/contracts/jsonschema/agent/` | **No** | directory does not exist; `jsonschema/` contains only `evidence/`, `scope/`, `v1/` |
| `services/worker/src/siembiot_worker/agent_analysis/` | **No** | does not exist |
| `tests/agent_security/` | **No** | does not exist — **there is nothing to run** |

### The ten named contracts

Searched by name across `packages/contracts/jsonschema/`:

| schema | status |
| --- | --- |
| AssessmentScope | **absent** (`scope/v1/scope-manifest.json` exists but is the Milestone 2 scope manifest, not an agent scope contract) |
| ExecutionPlan | **absent** |
| ToolCallRequest | **absent** |
| ToolCallResult | **absent** |
| RemediationAction | **absent** |
| ReportNarrative | **absent** |
| AgentRunAudit | **absent** |
| NormalizedObservation | present — `evidence/v1/normalized-observation.json` |
| CheckEvaluation | present — `evidence/v1/check-evaluation.json` |
| Finding | present — `evidence/v1/finding.json` |

The three that exist were built for Milestone 4's deterministic engine and predate any
agent work. They are not evidence of Milestone 6.

### Model integration

```
grep -rni "semantic.kernel|semantic_kernel|openai|anthropic|azure.ai|llm\b" \
  services/ packages/ apps/web/src pyproject.toml
```

One match, and it is a comment:

```
services/worker/src/siembiot_worker/workflows/lifecycle.py:71:
  # report generation, which is what keeps the product usable without an LLM.
```

**There is no Semantic Kernel or equivalent integration.** The question "does it hold
direct network/database credentials, a violation, or go through the policy service,
correct?" therefore has no answer either way: there is no integration to assess. No
violation exists, and no correct implementation exists.

### What does exist

`agent_analysis` is a **registered step in the workflow graph and a state in the
lifecycle**, and it is a permanent stub:

```python
def agent_analysis(step: StepContext) -> StepOutcome:
    """Optional by design. ..."""
    del step
    return StepOutcome.ok(agent_analysis="skipped_model_disabled")
```

It is `optional=True, max_attempts=1`, and `AssessmentState.AGENT_ANALYSIS` exists in the
lifecycle and in migration `0006`.

**This is not nothing.** One clause of Milestone 6's acceptance — *"complete workflows
remain usable with model disabled"* — is structurally satisfied and exercised by every
assessment the platform runs, since the model has never been enabled. What is absent is
everything the clause was meant to be a fallback *for*.

### Milestone 6 acceptance, clause by clause

> "agent cannot expand authority, change evidence/scores, or leak another tenant;
> complete workflows remain usable with model disabled."

| clause | status | evidence |
| --- | --- | --- |
| agent cannot expand authority | **not demonstrable** | no agent exists; vacuously true, untested, and no test suite exists to test it |
| agent cannot change evidence/scores | **not demonstrable** | same |
| agent cannot leak another tenant | **not demonstrable** | same |
| workflows usable with model disabled | **met** | 1129 tests pass with the step stubbed; every assessment in this repository has run this way |

**Milestone 6 is not complete.** Three of four acceptance clauses cannot be evidenced
because the subject of them does not exist.

---

## 3. Milestone table

"Claimed (README)" refers to the README as rewritten on 2026-08-12, commit `3910fcf`.

| # | Milestone | Claimed (README) | Claimed (CHANGELOG) | Actual | Evidence |
| --- | --- | --- | --- | --- | --- |
| 0 | Repository and toolchain | implemented | listed under Added | **complete, with a caveat** | all named files exist; 15/15 gates; bootstrap needs a retry on a OneDrive path |
| 1 | Contracts, DB, auth, tenancy, audit | implemented | listed under Added | **complete** | migrations `0001`–`0020`; `tests/security/test_identity_tenant_authorization.py` passes. Plan names `tests/security/test_tenant_isolation.py`; the file is named differently — same coverage, different filename |
| 2 | Domain verification, authorization, network safety | implemented | listed under Added | **complete** | `domains/`, `network_safety/`, `jsonschema/scope/`, `docs/security/scan-authorization.md` all present; suites pass |
| 3 | Provider framework and collectors | implemented | listed under Added | **complete, exceeded** | plan names 6 collectors; 9 exist (added `ports`, `asn`, `mail_tls`) |
| 4 | Evidence, policy, scoring, findings | implemented | listed under Added | **complete, exceeded** | methodology 1.0.0 (22 checks) and 1.1.0 (26); `docs/methodology/v1/` present |
| 5 | Durable orchestration and assets | implemented | **absent** | **complete except one doc** | `workflows/`, `tests/workflows/`, assets API present. **`docs/operations/jobs.md` absent** |
| 6 | **Tyche gateway and grounded analysis** | "partly done" — grouped with 8 and 10 | **absent** | **not started** | see section 2. Only the disabled-model fallback exists |
| 7 | Maturity and remediation | implemented | **absent** | **complete except docs and review** | `packages/policy/maturity/` (plan says `questionnaires/v1/`); `maturity.py`, `remediation.py`, UI present. **`docs/methodology/maturity-v1.md` absent.** 8 policy files still `review_status: draft`; plan requires licensing/legal review before finalising NIS2/CIS mappings — **not done** |
| 8 | Dashboards, findings, history, reports | "partly done" | **absent** | **partly done** | see section 4 |
| 9 | Public Observatory and moderation | implemented | **absent** | **complete except counsel review** | `publication/`, public pages, `docs/publication/safety-policy.md`; 6 review rows, 2 consents, 1 published profile. Acceptance requires "counsel/privacy review recorded before live catalog data" — **no such record** |
| 10 | Operations and hardening | "partly done" | **absent** | **partly done** | see section 5 |
| 11 | Demo and release candidate | not claimed | **absent** | **partly done** | `docs/demo.md` and `scripts/seed_demo.py` exist. No `release-check`, no RC tag, no independent penetration test |

---

## 4. Milestone 8 in detail — which pages are real

Every page under `apps/web/src/app` was checked for whether it fetches data. The codebase
uses thin server `page.tsx` wrappers that render client `-panel.tsx` components, so a
zero on a wrapper is the pattern rather than a placeholder.

| plan's page | route | data source | verdict |
| --- | --- | --- | --- |
| overview | `/onboarding` | 3 API calls | real |
| findings explorer | `…/domains/[id]/findings` | 5 API calls | real |
| domain / technical posture | `…/domains/[id]` | 11 API calls | real |
| assets | `…/domains/[id]/assets` | 3 API calls | real |
| history / diff | `…/domains/[id]/history` | 2 API calls | real |
| team | `…/team` | 2 API calls | real |
| audit | `…/audit` | 2 API calls | real |
| assessments | `…/assessments` | 7 API calls | real |
| maturity | `…/maturity` | 3 API calls | real |
| observatory | `/observatory` | `fetchPublic` server-side | real |
| **e-mail posture** | — | — | **no dedicated page**; e-mail checks appear within the domain and findings pages |
| **web/TLS posture** | — | — | **no dedicated page**; same |
| **providers** | — | — | **absent** |
| **settings** | — | — | **absent** |

No page was found with hard-coded data or a fake success state. Reports exist
(`siembiot_worker/reports/`, HTML, bilingual, single-use download) and are reachable from
the findings page.

**Unmet in Milestone 8:** dedicated e-mail and web/TLS posture pages, providers page,
settings page, `docs/reports/`, PDF output, and the visual-regression and axe
accessibility tests the plan lists at step 5.

---

## 5. Milestone 10 in detail

| item | status | evidence |
| --- | --- | --- |
| non-root read-only images, health/readiness | done | `infra/images/`, `images` gate passes |
| production-like compose | done | `infra/compose/production-like.compose.yml` |
| structured redacted telemetry | done | `telemetry.py`, `tests/operations/test_telemetry.py` |
| metrics endpoint | done | `/metrics`, 8 metrics, all emitted even when empty |
| alerts defined **and evaluated and routed** | done | Prometheus + Alertmanager + receiver in compose; fire-to-delivery demonstrated |
| backup/restore tooling | done | `scripts/backup.py`; restore executed and verified 2026-08-11 |
| retention | done | `siembiot_worker/retention/`, migration `0018` |
| tenant erasure | done | `scripts/erase_organization.py`, migration `0020`; executed against a real org |
| audit tamper-evidence | done | migration `0019`; `audit_chain_breaks()` returns empty |
| measured load targets | done | `scripts/load_test.py`; baselines in `deployment.md` |
| **scheduled off-host backups** | **not done** | tooling exists, no timer, artifacts on the same host as the database |
| **point-in-time recovery** | **not done** | no ADR, no implementation |
| **dashboards** | **not done** | no Grafana or equivalent definitions |
| **log aggregation** | **not done** | logs structured and redacted, stay on the host |
| **provider budget/cost monitoring** | **not done** | adapters track cost; not exposed as a metric |
| **TLS termination** | **not done** | assumed in front of the stack |
| **`infra/deploy/`** | **absent** | named in the plan |
| **container/IaC/SAST/SCA scanning** | **not done** | no scanner in the gates |
| **signed release artifacts / provenance** | **not done** | SBOM gate exists; no signing |
| **independent penetration test** | **not done** | outside my authority to perform or substitute |

---

## 6. Findings

1. **Milestone 6 has not been started.** Only its fallback path exists. Three of its four
   acceptance clauses cannot be evidenced.

2. **The CHANGELOG is six milestones stale** and its last verification entry understates
   the suite by 1085 Python tests and one gate. The plan's own Definition of Done requires
   a per-milestone changelog entry with verification evidence; that was not enforced.

3. **The README's status line groups 8 and 10 as "partly done" and omits 6 entirely** —
   the milestone with the largest gap is the one it does not mention. I wrote that line
   yesterday and it is imprecise.

4. **Four documents named in the plan do not exist:** `docs/operations/jobs.md` (M5),
   `docs/methodology/maturity-v1.md` (M7), `docs/reports/` (M8), `infra/deploy/` (M10).

5. **Two acceptance criteria depend on decisions outside my authority** and are recorded
   here rather than worked around: Milestone 7's licensing/legal review of the NIS2 and
   CIS v8.1 mappings, and Milestone 9's counsel/privacy review before live catalogue data.
   Eight policy files remain `review_status: draft` and are labelled as draft wherever
   they are displayed.

6. **`tests/security/test_tenant_isolation.py` does not exist under that name.** The
   coverage is in `test_identity_tenant_authorization.py`. A plan-to-file check would
   report a false gap; a file-to-coverage check reports it correctly. Recorded so the
   next audit does not chase it.

7. **Bootstrap is not reliably reproducible on a OneDrive-synced path.** It failed twice
   during this audit with `os error 5` on `.venv`, and succeeded on retry both times.
   Milestone 0's acceptance says a clean clone bootstraps; on this host that is true only
   with retries.

---

## 7. What I did not do

No implementation code was written during this audit, as instructed. No milestone status
in any other document has been changed yet; Phase 2 reconciles the README and CHANGELOG
against this table.
