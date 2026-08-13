# Changelog

All notable changes are documented here. The project has no supported release yet.

## Unreleased

### Added

- **An accessibility suite**, closing one of the two gaps `release-check` reported. axe
  over the rendered interface — the sign-in page in both builds, the application shell,
  the language switcher — asserting labels, roles, accessible names, landmark structure
  and valid ARIA. The audience is Romanian public institutions, which carry accessibility
  obligations their suppliers are often the reason they miss; "built to be accessible"
  and "measured" were different claims, and only the first was true.
  **What it does not cover is stated rather than implied.** These run in jsdom, which has
  no layout, so colour contrast, focus visibility and target size cannot be evaluated by
  any test here. Those rules are disabled by name rather than left to report as
  *incomplete*, and `release-check` now names the outstanding manual keyboard and
  screen-reader pass on both its output paths — beside the legal and security approvals,
  because it is the same kind of thing: work no script can do for itself.
  The audit refuses to run on markup that is not there. axe over an empty container
  reports zero violations, which reads exactly like a clean page, so a component that
  threw during render would otherwise have been certified accessible.

- **`make release-check`**, the Milestone 11 step 3 readiness report. It runs every gate
  the plan names and **names the ones nothing implements** rather than reporting on the
  subset that exists — 13 of 15 pass today, with `accessibility` and `provenance` reported
  as not built, each carrying what closing it would take.
  It exits non-zero, which is the correct answer: an unbuilt gate and a passing gate are
  not the same thing, and the report refuses to print them the same colour. This is not a
  per-commit gate — `make check` is that — so an accurate red costs nothing where a green
  would have to be a lie.
  **It tags nothing.** Milestone 11 step 5 puts a release candidate behind security,
  privacy and legal sign-off and the upstream credential disposition, so the script
  measures readiness and stops. A test parses its own source and fails if it ever grows a
  `git tag`, `git push` or `docker push`.

### Fixed

- **`make e2e-auth` has been unrunnable since 2026-08-03.** It named
  `tests/security/test_auth_tenant_authorization.py`, which does not exist — the file is
  `test_identity_tenant_authorization.py`. Ten days of a target that exited 4 as a pytest
  *usage* error, never noticed because it is not part of `make check`. Found by
  `release-check` running it.

- **`docs/operations/jobs.md`**, named in the plan since Milestone 0 and never written.
  The five scheduled jobs, their intervals with reasons, the credential each runs as and
  why it is not the worker's, every backup refusal code with its fix, and the queries that
  answer "did it run" from the database alone.
  It leads with the failure that prompted it: the platform started with an API, an
  interface and a worker, reported healthy everywhere, and did no work, because the API
  never publishes to the broker and nothing was scheduling the sweep. Tests pin every beat
  entry, task name and refusal code to the page, so a job added or renamed breaks the build
  until the runbook catches up — and the first run of those tests found `siembiot.run_assessment`
  missing, which is most of what a worker log contains.

- Independent Phase 0 architecture, ADRs, threat model, methodology draft, and implementation plan.
- Milestone 0 reproducible toolchain pins for Node.js 24.18.1, pnpm 10.34.5, Python 3.13, and uv 0.12.1.
- Frozen JavaScript and Python dependency locks.
- Cross-platform bootstrap and 14-gate repository verification commands.
- Repository invariant, toolchain, secret-scanner, Windows command-shim, runtime, and CI pinning tests.
- Commit-pinned CI foundation workflow with least-privilege permissions.
- Milestone 1 versioned JSON Schema/OpenAPI contracts and generated TypeScript API definitions with drift checks.
- Digest-pinned PostgreSQL startup and Alembic migrations for identities, organizations, memberships, invitations, OIDC transactions, server sessions, explicit support grants, and audit events.
- Actor-isolated global audit-event reads in addition to tenant-scoped audit RLS.
- Provider-neutral OIDC discovery, state/nonce/PKCE callback, opaque session, CSRF, logout, organization, membership, invitation, RBAC, and audit APIs.
- Romanian-first accessible login, onboarding, team, and audit web shells with HTTPS local development.
- Milestone 2 canonical IDN/domain registration backed by a pinned, provenance-recorded Public Suffix List.
- Digest-only DNS TXT and fixed-path HTTPS ownership challenges with expiry, attempt, replay, and rate budgets.
- Explicit consent capture, exact domain targets, canonical immutable Ed25519 scope manifests, and key rotation support.
- Purpose-specific address-pinned network broker with DNS rebinding, redirect, SSRF, framing, concurrency, time, and size defenses.
- Global, organization, domain, and operation-class emergency controls with audited activation/deactivation.
- Romanian-first domain verification and authorization workflow with one-time in-memory challenge display.
- Milestone 3 operation-class collection boundary generalizing the network broker to DNS queries, TLS handshakes, and multi-path HTTP fetches under the same authorization, pinning, and redirect revalidation rules.
- Record-type allowlisted, budget-bounded DNS client and handshake-only TLS inspector with bounded protocol probing.
- Declarative provider adapter contract covering capabilities, terms, data classification, secrets, timeout, rate limit, cost unit, cache policy, and mandatory fixture support.
- Adapter registry plus token-bucket rate limiting, circuit breaking, quota accounting, TTL caching, and provider-disagreement summaries.
- Keyless DNS resilience, e-mail trust, TLS/certificate, HTTP surface, RDAP, and Certificate Transparency collectors with golden pass/fail/warning/unknown/error and hostile-input fixtures.
- Generated provider matrix with a CI drift check, and `test-collectors`, `test-adapters`, `providers-check`, `test-domain`, `test-network-safety`, and `fixture-stack` targets.
- Milestone 4 versioned evidence contracts for normalized observations, check evaluations, score snapshots, findings, and multi-dimensional confidence.
- Policy-as-data methodology v1.0.0 with 22 checks across all six pillars, declared weights, severities, public-safety classes, remediation templates, and bilingual titles.
- Deterministic normalizers turning collector payloads into content-addressed observations that keep proven absence and inconclusive collection distinct.
- Pure evaluation engine producing all eight result states, with ordered rules, applicability gating, and expiring authorized overrides.
- Reproducible scoring engine with pillar weighting, high-confidence-only critical caps, coverage floor, and minimum-based confidence roll-up.
- Stable finding fingerprints with resolve/regress reconciliation, expiring suppression, accepted risk, and methodology-aware score-change attribution.
- Append-only migration for assessments, observations, evaluations, score snapshots, findings, suppressions, and finding history under row-level security.
- Published methodology v1 documentation, reference snapshot, and `policy-validate`, `test-normalization`, `test-scoring`, and `methodology-reproduce` targets.

- Milestone 5 durable assessment orchestration: a step graph with per-step retry, idempotency keys, cancellation, and recovery of evidence lost to an in-memory context on resume.
- Milestone 5 asset discovery from Certificate Transparency, with human review before any discovered host enters scope.
- Milestone 7 maturity questionnaire, deterministic 0-5 scoring, and a 30/60/90 remediation roadmap.
- Milestone 8 self-contained bilingual HTML assessment reports, marked CONFIDENTIAL, rendered from the stored snapshot and delivered through a hashed, single-use, five-minute grant bound to the person who asked.
- Milestone 9 Public Observatory: a separate database role and schema, a moderated projection, consent capture, corrections and takedowns.
- Nightly backups that actually take one: `pg_dump` in custom format, placed at the configured destination, with every attempt -- success or failure -- recorded in `backup_runs`. Partial and empty dumps are deleted rather than kept, because a truncated dump restores into half a database without complaining.
- `siembiot_last_successful_backup_seconds` and `siembiot_failed_backups_recent`, with `BackupStale` (pages at thirty-six hours) and `BackupFailing` alerts and dashboard panels. An age rather than a count: a count cannot distinguish a healthy platform from one whose backups stopped a fortnight ago.
- `postgresql-client-17` in the worker image, matching the server's major version. Without it the task reports `pg_dump_not_available` by name rather than crashing nightly.
- An `infrastructure` gate (16 now, from 15) enforcing the production-like stack's hardening -- read-only root filesystems, dropped capabilities, `no-new-privileges`, no published datastore ports, no docker socket, no host networking, digest-pinned images. It runs with no scanner and no network, and fails rather than passes when it cannot find the services it expects to check.
- A scheduled `container-scan` workflow running digest-pinned Trivy against all four images and the Dockerfiles. Scheduled as well as on push, because a vulnerability is disclosed rather than committed.
- Milestone 10 data retention: every table classified, evidence expiring at ninety days, and a dedicated role that is the only one able to delete it.
- Milestone 10 erasure of an organization on request, deriving the tables from the catalogue rather than a list, with a tombstone recording that it happened.
- Milestone 10 a tamper-evident audit trail: events chained per organization by a database trigger, with `audit_chain_breaks()` to verify one.
- Milestone 10 Prometheus, Alertmanager and a receiver, demonstrated firing and resolving end to end.
- Milestone 10 measured performance baselines and a deliberately configured connection pool.
- Collectors for exposed ports (authorized only), announcing-network attribution, and mail transport security, taking the total from six to nine.
- Methodology 1.1.0, adding four checks by naming an additional check directory so 1.0.0 keeps loading exactly what it was published with.

- Milestone 6 Tyche gateway: versioned agent contracts, a claim validator that drops any sentence not citing immutable evidence or an approved reference, a closed read-only tool set, per-run budgets, and an adversarial suite covering scope escalation, prompt injection, hostile tool output, cross-tenant citation, budget exhaustion, cancellation and provider outage.
- Milestone 8 PDF reports rendered by a engine that executes no JavaScript and opens no sockets, offered only where the renderer is present and refused by name where it is not.
- Milestone 8 provider disclosure page, generated from the adapter descriptors the collectors actually run under.
- Milestone 8 organisation settings page carrying the emergency stop at the level it applies to.
- Milestone 10 scheduled backups that refuse a destination inside the repository or sharing a filesystem with the database.
- Milestone 10 shared provider quota in Redis with an atomic consume, snapshotted to PostgreSQL so a budget is visible to the metrics endpoint and alertable.
- Milestone 10 Grafana dashboard whose panels plot the series the alert rules read, at the thresholds those rules fire at.
- ADR-0012 deciding point-in-time recovery is required for the audit trail and why evidence does not need it.

### Changed

- **The application opens on the sign-in page in every build.** It already did in
  development; production showed a landing hero whose only purpose was to be clicked
  through. Root now redirects to `/sign-in` everywhere, and what differs is the page that
  arrives: a deployment terminates identity at a gateway upstream, so `/sign-in` there
  states that authentication happened before the request reached the portal and offers
  the way into the workspace.

### Fixed

- **An origin refusal now says why, in the log.** `SIEMBIOT_PUBLIC_BASE_URL` is compared
  to the `Origin` header as a whole string, so a wrong scheme, host or port refuses every
  state change while every read keeps working -- which reads as a broken application
  rather than a wrong setting, and the API knew exactly why and said nothing anywhere.
  It now logs what it expected, what it received, and which setting fixes it. The
  response stays deliberately uninformative: naming the accepted origin tells an attacker
  what to forge.
  The scheme is the part that actually catches people, and it caught the author within an
  hour of writing the port check: `make web-serve` runs `next dev --experimental-https`,
  so development is `https://`, while the production-like stack has no TLS termination
  and serves plain `http://`. A value correct for one is wrong for the other, and the
  earlier test compared only the port. It now also requires a scheme to be present.

- **A production build served a login form that could not log anybody in.** `/sign-in`
  is a development identity picker, and it was a client component with no build-time
  gate, so it rendered in production complete with username and password fields. Its own
  text said it does not work outside development -- and it still collected credentials,
  set a cookie the middleware never reads, and sent the person to a page that answers
  401. A dead end shaped like a login, on a portal for public institutions, where a form
  asking for a password is a phishing lesson taught by the real thing.
  It now renders no form at all outside development. The tests assert on the input type
  rather than the copy, because a password field is what a person recognises as a login
  whatever the surrounding words say.

- **Host ports no longer assume they are free.** The compose file already parameterised
  them; `scripts/smoke_test.py` did not, so a stack published on another port was checked
  at 3000 and 8000 -- reporting whatever else happened to be listening there, or nothing.
  `make web-serve` now honours `SIEMBIOT_WEB_PORT` too: left to itself Next.js picks 3001
  silently when 3000 is taken, which is worse than failing, because the interface then
  comes up on a port the API's origin check does not expect.
  `SIEMBIOT_PUBLIC_BASE_URL` is the exact `Origin` required on every state change, so it
  has to move with the port. A test pins the two together across `.env.example` and the
  compose default, since the failure mode -- reads fine, every write refused as
  `origin_rejected` -- reads as an application bug rather than as one line of config.

- **The retention role could have started with a blank password.** Every other credential
  in the production-like stack is written `${VAR:?set in local .env}`, which stops the
  stack when it is unset; `SIEMBIOT_POSTGRES_RETENTION_PASSWORD` was interpolated bare, so
  compose would substitute the empty string and print a warning nobody reads. It was also
  in neither `.env` nor `.env.example`, so nothing told an operator it existed. Found by
  running the stack rather than by reading it.
  The `infrastructure` gate now enforces both: every variable must be required or
  defaulted somewhere in the file, and anything required must appear in `.env.example`.
  The rule is per *variable* rather than per occurrence -- one `:?` anywhere protects the
  bare uses that follow, and flagging each of those would have reported six problems
  where there was one, which is how a checker earns being deleted.

### Security

- **PyJWT removed entirely.** The new container scan found CVE-2026-48526 in it on its
  first real run -- an authentication bypass via forged JSON Web Tokens -- along with
  CVE-2026-32597. Neither was reachable: authentication terminates upstream at the
  identity gateway, which compares a shared secret with `hmac.compare_digest` and reads
  identity headers, and the provider-neutral OIDC flow that would have verified an
  `id_token` was replaced before it shipped. Nothing constructs or verifies a JWT
  anywhere -- checked for direct imports, dynamic imports, re-exports, test fixtures, and
  for token handling under another name.
  Removed rather than upgraded. An unused cryptographic library is attack surface with no
  offsetting benefit, and reachability analysis is an argument that has to be re-made by
  every future auditor; absence is a fact that does not. `cryptography==50.0.0` is
  unaffected -- it became a direct dependency during Milestone 3 for X.509 parsing rather
  than arriving through `pyjwt[crypto]`, which is what made this removal a one-line
  change.
- **Three Starlette findings are accepted rather than fixed**, recorded in
  `.trivyignore.yaml` with reasons and an expiry of 2026-11-12: CVE-2025-62727,
  CVE-2026-48818 and CVE-2026-54283. None is reachable -- no `StaticFiles`, no form
  parsing, no ranged responses, each checked rather than assumed -- and all three are
  capped by FastAPI 0.116.1, so clearing them means moving FastAPI to 0.141 and Starlette
  across a major version. Every entry in that file expires on purpose: a suppression with
  no end date is indistinguishable from not scanning.
  The dates are enforced rather than noted. `tests/operations/test_accepted_findings_expire.py`
  fails **thirty days before** a suppression lapses -- 2026-10-13 for these three -- so
  the upgrade arrives with runway instead of as an emergency, and the scope of that work
  is recorded in the header of `.trivyignore.yaml` rather than left to be rediscovered.
  An expiry date nothing trips over is a note, not a deadline.
- **Backups must not be taken with the worker's credentials.** `SIEMBIOT_BACKUP_DATABASE_URL`
  is deliberately separate from `SIEMBIOT_WORKER_DATABASE_URL`. Every tenant-scoped table
  carries row-level security with `FORCE`, so a dump taken by a role subject to those
  policies would contain only the rows that role can see -- and would restore without
  complaint. PostgreSQL does refuse rather than silently filter, but that is a safeguard,
  not a plan.

- **The audit trail was not tamper-evident before 2026-08-12.** `previous_hash` and
  `event_hash` were added to `audit_events` in migration `0001` with a CHECK constraint
  fixing them at 32 bytes, and nothing ever wrote either column: every row in every
  deployment carried two nulls. The trail was append-only, which stops the application
  rewriting history, and it was not chained, which is what would have stopped anybody
  holding the database credentials. Those are different guarantees and the schema read as
  though it provided both. Migration `0019` chains events per organisation in a database
  trigger. Rows written before it are deliberately not backfilled -- hashing them now
  would certify whatever they say today, so an already-altered row would be laundered as
  genuine -- and are reported as predating tamper-evidence rather than as breaks.
- **Denied authorization attempts were recorded and discarded, from `0001` until
  2026-08-12.** `authorize` appended an `authorization.denied` event and then raised,
  both inside the request's transaction; `engine.begin()` rolls back on an exception, so
  the write never survived. A database holding fifteen `assessment.queued` rows held zero
  `authorization.denied` rows. The refusal is now written on its own connection, so it
  outlives the request that was refused.

- DKIM selectors are collected only from organization declarations; selector wordlists are never tried.
- RDAP entity and contact objects are discarded at parse time; only registration facts are retained.
- Certificate Transparency names are recorded as confidence-labelled candidates, never as confirmed organizational assets.
- Architecture test extended to confine `dns`, `ssl`, `http`, `smtplib`, and `asyncio` imports to the network-safety boundary.
- Observations, evaluations, score snapshots, and finding history are append-only at the database level, so a completed assessment cannot be rewritten.
- A critical cap can only lower a score, is rejected by a database constraint otherwise, and never fires on a low-confidence or shared-hosting observation.
- Suppression requires a reason, an actor, and an expiry; an indefinite suppression is not representable in the schema.

- Safe environment template with the model disabled by default.
- Tracked secret/key/generated-file rejection and assignment-shaped secret scanning.
- No Tyche configuration, credentials, dependencies, source, or ticket functionality imported.
- Forced PostgreSQL RLS plus application-layer tenant/action/object authorization, with no implicit platform-admin tenant access.
- Append-only structured audit events protected by application-role grants, RLS, and an immutability trigger.
- Negative tests for unauthenticated, cross-tenant, IDOR/BOLA, forged tenant, role escalation, revoked membership, expired session, OIDC replay/nonce, CSRF origin, and support-access assurance cases.
- Browser security invariant prohibits access/refresh token storage and keeps CSRF state in memory.
- Network imports are confined to the centralized safety module; every resolution and redirect fails closed on any unsafe answer.
- Ownership and assessment authority are distinct: challenges never grant assessment scope and parent domains never grant child domains.
- Emergency controls are checked authoritatively during in-flight reads; global controls require phishing-resistant platform administration.

### Verification

- On 2026-08-12, after the Milestone 6 gateway, backups, quota, settings, dashboards and PDF work:
  - `python scripts/verify_repo.py` — exit 0, **15/15 gates**.
  - `python -m uv run --frozen pytest -q` — **1235 passed**, 0 failed, 0 skipped.
  - `corepack pnpm --filter @siembiot/web test` — **60 passed** across 8 files.
  - `pytest tests/agent_security -q` — **70 passed**; `tests/agent_security/test_disabled_gateway_fallback.py` — **4 passed**.
  - PDF verified inside the Linux image rather than on the development host, which cannot import the renderer: a real report rendered to `%PDF-`, first page converted to an image and inspected, Romanian diacritics intact.
- Earlier the same day, the audit recorded in `docs/product/status-audit-2026-08-12.md`: 15/15 gates, 1129 Python tests, 60 web tests, against a changelog claiming 14 gates and 44 tests.

- On 2026-08-12, audited the repository against the implementation plan and recorded the result in `docs/product/status-audit-2026-08-12.md`. Commands and exact results:
  - `python scripts/bootstrap.py` — exit 0, on the second attempt. The first failed with `error: failed to remove directory ...\.venv\...: Access is denied. (os error 5)`, which is OneDrive holding files under sync on this path, not a repository defect. It recurred once and cleared on retry both times.
  - `python scripts/verify_repo.py` — exit 0, **15/15 gates**: phase0 (395 files, 11 ADRs), repository (6 tests), locks, format, lint, types, unit, contracts, migrations, secrets, images, i18n, sbom, docs, diff.
  - `python -m uv run --frozen pytest -q` — **1129 passed**, 0 failed, 0 skipped, exit 0.
  - `corepack pnpm --filter @siembiot/web test` — **60 passed** across 8 files, exit 0.
- The entry below this one, dated 2026-08-03, recorded 14 gates and 44 Python tests. That understated the suite by one gate and 1085 tests for nine days, because milestones 5 and 7 through 10 were merged without a changelog entry. `CONTRIBUTING.md` now requires one.

- On 2026-08-03, fast-forwarded `main` from `0647393` to the unchanged Milestone 0 commit `40d639f` from `implementation/milestone-0`.
- Verified the merged `main` state with `python scripts/bootstrap.py` (exit 0), `python scripts/verify_repo.py` (14/14 gates), `python -m uv run --frozen pytest -q` (13 passed), and `git show --check --oneline --stat HEAD` (exit 0).
- On 2026-08-03, GitHub PR #1 passed remote `phase0` run `30804463289` and `ci` run `30804461427`, then merged Milestone 1 into `main` as merge commit `683fcfe03dbc97e89e5eda77ec2dcacc5098dcb1` without squashing its verified checkpoints.
- Verified the merged Milestone 1 `main` state with `python scripts/bootstrap.py` (exit 0), `python scripts/verify_repo.py` (14/14 gates; 44 Python and 3 web tests), an independent empty-database migration test (1 passed), `python -m uv run --frozen pytest -q` (44 passed), `corepack pnpm --filter @siembiot/web build` (exit 0), and `git show --check --stat --oneline 683fcfe03dbc97e89e5eda77ec2dcacc5098dcb1` (exit 0).

### Known limitations

- **Milestone 6 ships no model.** The gateway, its contracts, its budgets and its adversarial suite exist and pass, and `DisabledProvider` is the only implementation: no Semantic Kernel or vendor adapter is included, and the analyst panel does not yet distinguish Measured from Inferred from Recommended. Every assessment, finding, score and report this platform produces is deterministic and none has ever depended on a model.
- Milestone 8 has no dedicated e-mail or web/TLS posture page — those checks render on the domain and findings pages — and no visual-regression or accessibility test suite.
- Milestone 10 has no configured backup destination, no point-in-time recovery configured, no log aggregation, no TLS termination in the stack, no `infra/deploy/`, no container or IaC scanning, and no signed release artifacts.
- Eight policy documents remain `review_status: draft` and are labelled as draft wherever they are displayed. Milestone 7's acceptance requires a licensing and legal review of the NIS2 Article 21 and CIS v8.1 mappings before they are finalised; that review has not happened.
- Milestone 9's acceptance requires a recorded counsel and privacy review before live catalogue data. No such record exists.
- No independent penetration test has been carried out.
- The upstream Tyche credential exposure remains a production launch blocker outside this repository's authority.
