# Threat Model

**Version:** 0.3

**Review date:** 2026-08-03

**Method:** data-flow trust boundaries plus STRIDE/LINDDUN-informed abuse cases

## Scope and assets

In scope: public web/API, authenticated workspace, identity/session, tenants/RBAC, domain verification, authorization/scope manifests, queues/workers, collectors/egress, providers, normalized/raw evidence, scoring, Tyche/model gateway, uploads/reports, public projection, moderation, CI/deployment, logs/backups.

Highest-value assets:

- tenant identity, membership, sessions, personal data, and invitations;
- proof of domain control, consent, authorization, signed scope manifests, and suspension/kill-switch state;
- private assets, evidence, findings, maturity answers/uploads, reports, and remediation;
- provider/model/storage credentials and signing keys;
- immutable audit history and methodology versions;
- public catalog integrity and publication consent;
- worker egress authority and platform availability.

## Actors and assumptions

Actors include anonymous users, legitimate members in every role, malicious/compromised tenant users, platform operators, providers, model providers, target-domain operators, attackers controlling DNS/redirects/content, supply-chain attackers, and accidental insiders.

Assume every target response, DNS record, certificate field, HTTP header/body, RDAP/CT/provider payload, upload, questionnaire note, and model response is hostile data. Domain control proves only control of the challenge location, not organizational authority or perpetual ownership.

## Security invariants

1. A principal can access only explicitly authorized objects in the active tenant and role context.
2. No connection occurs unless the exact destination is currently permitted by a valid signed scope and network policy.
3. Agent/model output cannot create evidence, alter scores, expand scope, or execute side effects.
4. Public projection never contains actionable private detail.
5. Authorization, publication, support access, assessment actions, evidence, and report access are attributable and tamper-evident.
6. A failed provider/model/step reduces coverage or returns unavailable; it never becomes a pass.
7. Secrets/private findings do not enter logs, analytics, prompts beyond approved minimization, URLs, or caches.
8. Out-of-scope network access is denied and audited regardless of caller or workflow state.

## Threat register

| ID | Threat / abuse case | Primary controls | Verification | Residual risk |
| --- | --- | --- | --- | --- |
| TM-01 | Credential stuffing, enumeration, reset abuse | OIDC, generic errors, rate/abuse limits, MFA/passkeys, session/device revoke | auth abuse E2E/load tests | IdP compromise |
| TM-02 | CSRF/session fixation/token theft | BFF opaque session, rotation, Secure/HttpOnly/SameSite, CSRF token, origin checks, CSP | browser security tests | compromised endpoint/browser |
| TM-03 | IDOR/BOLA/cross-tenant access | deny-by-default object auth, tenant context, DB constraints/RLS, no user-supplied tenant trust | role matrix + cross-tenant API/SQL tests | policy defect; zero tolerance |
| TM-04 | Abusive support/admin access | phishing-resistant MFA, just-in-time support grant, reason/expiry, dual-control option, audit/alerts | admin journey and audit tests | privileged infrastructure admin |
| TM-05 | Invitation/membership race | expiring single-use invites, membership/session revocation, transaction/locking | concurrency tests | e-mail compromise |
| TM-06 | False domain claim/shared suffix | PSL eTLD+1, digest token, expiry, delegated-zone policy, org moderation | PSL/IDN/delegation fixtures | registrar/DNS account compromise |
| TM-07 | DNS rebinding/SSRF/metadata access | central structured network client, immediate A/AAAA recheck, address pinning, deny non-global, redirect revalidation, egress policy | adversarial IPv4/6, redirect, resolver, metadata suite | resolver/kernel defect; zero tolerance |
| TM-08 | Scope expansion/target churn | signed immutable scope, verified authorization, per-step policy, reauthorization, suspension/kill switch | manifest tamper and race tests | stolen signer key |
| TM-09 | Scan DoS or harm | passive default, safe profiles, port/method allowlist, low concurrency, deadlines/bytes, org/global quotas | load and policy tests | fragile third-party target |
| TM-10 | Queue replay/duplicate/out-of-order jobs | idempotency keys, DB transition constraints, leases, known-step graph, dead letter audit | retry/replay/chaos tests | prolonged partition |
| TM-11 | Cancellation ignored | propagated cancellation tokens, short network deadlines, pre-step checks | cancellation at every lifecycle stage | non-cooperative dependency |
| TM-12 | Malicious provider/target output | typed/size-limited normalization, encoding, quarantine, source confidence, no instruction interpretation | malformed/golden/fuzz fixtures | parser zero-day |
| TM-13 | Indirect prompt injection | separated instructions/data, minimal evidence views, tool denylist, output schemas, reference validation, no direct I/O | injection corpus and cross-tenant prompts | persuasive unsupported narrative, omitted on validation failure |
| TM-14 | Model leaks private data | per-tenant minimized prompt, provider contract/config, no training where required, redaction, egress policy, audit metadata | prompt snapshot/redaction tests | provider/operator compromise |
| TM-15 | Model budget exhaustion/loop | step/tool/token/time/cost/retry/concurrency budgets, cancellation, no recursive delegation | budget and outage tests | intentional tenant quota use |
| TM-16 | Score manipulation | pure pinned policy engine, signed inputs/snapshots, no model influence, golden fixtures | reproducibility/property tests | flawed methodology, disclosed/versioned |
| TM-17 | Evidence/audit tampering | append-only records, content hashes, DB permissions, object versioning/retention, chained audit exports | mutation/restore/integrity tests | database superuser |
| TM-18 | Raw evidence or report exposure | object auth, random keys, private cache headers, short single-use download, encryption, access audit | URL guessing/cache/cross-tenant tests | recipient redistribution |
| TM-19 | Upload malware/polyglot/zip bomb | allowlisted purpose/type, signature inspection, size/decompression limits, quarantine, ClamAV, sandbox, no execution | upload abuse corpus | scanner evasion |
| TM-20 | Public projection leakage/reidentification | explicit field allowlist, separate read model, consent/moderation, cohort threshold, suppression | schema snapshots/privacy tests | linkage with external data |
| TM-21 | Correction/moderation abuse | authenticated claim proof, workflow separation, evidence/reason, rate limits, audit | moderation E2E tests | social engineering |
| TM-22 | Log/telemetry leakage | structured allowlist logging, redaction, private metrics prohibition, access/retention | automated canary-secret/private-data tests | operator screenshots/export |
| TM-23 | Secret/supply-chain compromise | secret manager, rotation, push protection, lockfiles, SAST/SCA/container/secret scan, SBOM, signed provenance, protected CI | release pipeline and tamper tests | malicious upstream update |
| TM-24 | Backup/closure privacy failure | encrypted backups, PITR, restore test, retention schedule, deletion/anonymization workflow, legal holds | restore and deletion drills | immutable backup window |
| TM-25 | Provider quota/circuit failure | quotas, cache terms, circuit breakers, cost budgets, explicit unknown, health dashboard | adapter fault/contract tests | prolonged provider outage |
| TM-26 | Report HTML/PDF injection | escaped templates, CSP/no network, sandboxed renderer, bounded assets/fonts, schema-only narrative | malicious evidence/report snapshots | renderer vulnerability |
| TM-27 | Methodology/reference drift | versioned source register, review/expiry dates, policy review, changelog | expired-source CI gate | law/standard ambiguity |
| TM-28 | Mass signup/verification/scan churn | layered IP/account/org quotas, device/e-mail reputation where lawful, anomaly signals, manual suspension | abuse load tests | distributed botnet |

## Privacy analysis

Potential harms include unauthorized disclosure of weaknesses, employee data, organizational profiling, inaccurate public attribution, persistent historical stigma, and small-cohort reidentification. Controls are minimization, purpose/classification metadata, private-by-default storage, correction/appeal, consent revocation, retention limits, cohort thresholds, visible confidence/limitations, and no exact findings in analytics/public output.

A formal DPIA, records of processing, controller/processor analysis, subprocessor register, transfer assessment, and counsel review are launch prerequisites, not satisfied by this model.

## Abuse-resistant network policy

The target design recognizes `passive_public`, `verified_safe_active`, and `local_fixture`, but Milestone 3 implements only `local_fixture`. Public and verified-active modes are not executable and cannot be enabled by configuration. Each future tool must declare one mode. Public observatory jobs cannot transition to an active tool. Verified active mode will require tenant authorization, current verification, allowed target/port/protocol, valid time window, and no suspension. The future egress gate must record decision inputs/outcome but never secret tokens or full sensitive payloads.

Emergency controls: global active-check kill switch, provider kill switch, organization suspension, domain revocation, per-run cancellation, and public-profile suppression. Their activation is strongly authorized, audited, alerting, and exercised in staging.

## Agent security design

The system prompt is immutable/versioned. Retrieved content is delimited and typed as untrusted. Tool descriptions come only from the signed registry. The model sees opaque evidence IDs and minimized values; tool results are schema-validated and stored before further reasoning. A claim validator permits measured claims only when referenced evidence supports the predicate; unsupported sentences are removed. Recommendations may be generated only from approved templates/references and retain the `Recommended` label.

No chain-of-thought is stored. Audit retains run ID, tenant, model/provider/version, prompt/template hash, allowed tools, budget, requested/denied calls, evidence IDs, validation result, timing, token/cost totals, cancellation/error state, and final grounded output hash.

## Release security gates

- threat-model review on every new collector/tool/trust boundary;
- unit/property/fuzz tests for normalization, domain/PSL, scoring, authz, and network policy;
- multi-tenant/RLS, SSRF/rebinding/redirect, CSRF, upload, report, and agent security suites;
- secret/SAST/SCA/container/IaC scans and SBOM/provenance;
- production-like smoke, backup restore, kill-switch, cancellation, provider/model outage, and public-suppression drills;
- independent penetration test and privacy/legal review before public production.

## Milestone 1 validation status

TM-01 through TM-05 and the audit-integrity portion of TM-17 now have executable foundations. Tests cover one-time OIDC state, nonce and PKCE, secure cookie flags, session expiry/revocation, exact-origin CSRF, unauthenticated access, cross-tenant/IDOR attempts, forged tenant headers, role escalation, revoked membership, duplicate invitations, tenant RLS, explicit support grants with phishing-resistant MFA, and database denial of audit update/delete. Remaining abuse-rate limits, independent identity-provider conformance, penetration testing, production key management, and operational alerting remain later hardening work and launch gates.

## Milestone 2 validation status

TM-06, the ownership-verification portion of TM-08, and the application-level controls for TM-07/TM-09/TM-11 now have executable foundations. Tests cover UTS 46/STD3 normalization, the complete pinned PSL including wildcard/exception rules, public-suffix rejection, exact parent/child separation, digest-only challenges, expiry/replay/attempt budgets, canonical signed manifests, key rotation and tamper rejection, tenant RLS, all emergency-control scopes, phishing-resistant global administration, and immediate safe recovery.

Adversarial network tests cover alternate numeric IP encodings, IPv4-mapped IPv6, private/loopback/link-local/multicast/reserved/metadata ranges, mixed DNS answers, DNS rebinding, exact redirect authorization, TLS downgrade, forbidden paths/ports/query/credentials/fragments, address pinning with Host/SNI preservation, malformed framing, response size, time, redirect, concurrency, and cooperative policy cancellation. The architecture test rejects direct network imports outside the centralized module. Residual launch work includes restricted-egress deployment, OS/network-policy enforcement, production signing-key custody, alert delivery, staging kill-switch drills, penetration testing, and collectors requiring valid manifests.

## Milestone 3 validation status

TM-08, TM-10 through TM-12, and TM-25 gain fixture-level executable controls, not live-network assurance. Tests cover broker-only collector access, private/mixed-address denial, redirect reauthorization, simulated DNS rebinding, timeouts, cooperative cancellation, response limits, malformed/hostile data, provider unavailability/disagreement, circuit breaking, partial completion, exact reruns, and a network trap around the full suite.

Fixture observations carry complete provenance and cannot be relabeled, published, treated as real-world evidence, converted to findings, or scored. CT names never authorize or create assets; RDAP entity details are reduced to roles. Residual risk remains unchanged for actual deployment egress, worker isolation, pre-connection scope reauthorization, provider-secret custody, operational kill switches, and production security testing. All are conjunctive prerequisites for explicit live activation.

## Open risks requiring accountable acceptance before launch

- legal basis and fairness of public-interest scoring of Romanian institutions;
- active-testing authorization language and the effect of Romanian Law 123/2026;
- GDPR roles, international provider/model transfers, retention, and data-subject handling;
- final identity provider and production hosting jurisdiction;
- objective cohort threshold and public score challenge process;
- upstream Tyche credential rotation/history disposition.
