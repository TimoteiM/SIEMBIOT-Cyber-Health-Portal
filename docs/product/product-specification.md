# Phase 0 Product Specification

## Product promise

SIEMBIOT helps Romanian organizations understand external digital hygiene and organizational cybersecurity maturity. It provides evidence-backed improvement guidance; it is not a penetration-testing service, security guarantee, certification, or legal determination of NIS2 compliance.

Romanian is the default complete locale; English is fully supported. Exact findings, assets, evidence, remediation, people, and reports remain private. Public output is limited to approved high-level fields and privacy-safe aggregates.

## First-class outputs

1. **External Security Posture Score (0–100):** deterministic result from applicable normalized technical evidence and a versioned methodology.
2. **Organizational Maturity Score (0–5):** deterministic result from questionnaire responses, with self-attested and evidence-supported states visible.
3. **Coverage & Confidence:** completion percentage plus attribution, freshness, and provider confidence; never folded into success/failure.

Result states are `pass`, `fail`, `warning`, `unknown`, `error`, `not_applicable`, `suppressed`, and `accepted_risk`. Missing data is never silently scored as success or failure.

## Experiences and boundary

### Public Observatory

Passive/non-intrusive collection only. It supports a moderated Romanian institution catalog, safe profiles, correction/claim workflows, methodology history, and aggregates released only above configured cohort/privacy thresholds. It never publishes attacker-useful detail.

### Verified Organization Workspace

Enrollment, verified e-mail, organization and membership, terms/authorization acceptance, domain-control state machine, scope review, and authorization precede any private/active assessment. Workspaces support multiple domains and strict tenant isolation.

## Safe assessment lifecycle

`draft → awaiting_authorization → queued → planning → collecting → normalizing → evaluating → agent_analysis → report_generation → completed`

Exception states: `cancelled`, `partially_completed`, `failed`, `expired`, `blocked_by_policy`.

Every run freezes a signed scope manifest containing tenant, verified domains/hosts, profile, policy versions, consent, requester, validity window, and authorization facts. Destination resolution and policy are rechecked immediately before each connection and redirect.

## Initial deterministic check families

- DNS health, DNSSEC, name-server posture, CAA, RDAP, changes, delegation/wildcard observations;
- MX, SPF, user/provider-declared DKIM selectors, DMARC, MTA-STS, TLS-RPT, DANE/TLSA, optional BIMI;
- HTTPS/redirect, certificate/chain/expiry, safe TLS handshakes, HTTP security headers, public cookies, mixed-content signals, banners, canonical host;
- CT/DNS/user-declared passive asset candidates and attribution review;
- provider-backed passive service and reputation signals with disagreement and provenance;
- change/freshness/blind-spot and remediation-verification events.

No form submission, authenticated crawl, fuzzing, payload injection, exploitation, brute force, selector brute force, object enumeration/download, stealth, or denial-of-service behavior is permitted.

## Domain verification

Challenges are stateful: `pending`, `verified`, `expired`, `failed`, `revoked`, `reverification_required`.

- DNS TXT at `_tyche-verify.<domain>` is preferred; random tokens are expiring, single-use, purpose-bound, and stored only as digests.
- HTTPS well-known verification has centralized SSRF/redirect/rebinding defenses.
- Administrative e-mail is restricted to documented role aliases and is fallback-only.
- eTLD+1 uses a pinned, regularly refreshed Public Suffix List; public/shared suffixes never confer authorization.
- Parent verification does not automatically authorize separately delegated child zones.

## Maturity assessment

Baseline completion target is 10–15 minutes; an extended path covers governance, assets, risk, IAM, configuration, backup/recovery, logging, incident response, supply chain, vulnerability management, awareness, continuity, and reporting. Mappings to NIS2 Article 21 themes and optional CIS Controls v8.1 IG1 are versioned and informational.

## Tyche role

Tyche selects among permitted capabilities, proposes bounded plans, interprets normalized evidence, explains risk, compares authorized runs, and drafts grounded remediation/report narrative. Every statement is labeled Measured, Inferred, or Recommended and references evidence IDs.

Tyche cannot connect to targets, choose unrestricted tools, execute side effects, access cross-tenant data, mutate raw evidence, suppress findings, or calculate/override authoritative scores. Failed grounding causes omission, and model outage falls back to deterministic templates and leaves assessment status available.

## Roles

`platform_admin`, `public_catalog_moderator`, `organization_owner`, `security_admin`, `analyst`, `viewer_auditor`, and `maturity_contributor`. Authorization is deny-by-default and object-scoped. Platform private-tenant access requires explicit, time-bounded, audited support access. Platform administrators require phishing-resistant MFA/passkeys.

## Release invariants

- no cross-tenant data disclosure;
- no out-of-scope network connection;
- no public release of actionable private detail;
- no agent-authored evidence or score;
- authorization/audit history cannot be silently rewritten;
- core demo and deterministic collectors work without paid providers or a model;
- model/provider outage degrades to visible `unknown`/unavailable states;
- no launch while upstream credential exposure remains undispositioned.

These are release blockers, not backlog items.

## Explicit Phase 0 out of scope

Application code, database migrations, runnable collectors, real institution seed data, provider contracts, legal approval, production deployment, and claims that any user journey works. Typosquat monitoring, intrusive testing, authenticated scanning, mobile-native apps, billing, and a light theme are post-launch or explicitly separate modules.
