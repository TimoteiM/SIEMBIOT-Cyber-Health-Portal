# SIEMBIOT Cyber Health Portal

A free platform that tells a Romanian public institution what its security posture looks
like from the outside, in language it can act on, with the evidence attached.

An institution enrols a domain, proves it controls it, and gets a score, a list of what is
actually wrong, and step-by-step guidance for fixing each item — in Romanian or English,
downloadable as a document it can take to a board or a supplier.

**What it is not.** Not an audit, not a certification, not a NIS2 conformity
determination, and not a penetration test. Every report says so on its face. It observes
what a domain publishes to the world and, where it has signed authorization, checks a
short list of ports. It never attempts to exploit anything.

---

## The two modes, and why the distinction runs through everything

**Passive observation** reads what a domain already publishes to everyone: DNS records,
its RDAP registration, certificate transparency logs, one HTTPS GET of the site root, a
TLS handshake, and an SMTP `STARTTLS` negotiation with its published mail servers. Every
one of those is something a browser or a mail server does routinely. No permission is
required, which is what lets the Public Observatory assess a public body that has never
heard of this platform.

**Authorized assessment** additionally opens TCP connections to a short list of ports the
domain did not advertise. That asks a host a question rather than reading an answer it
published, so it requires proof of domain control plus a signed authorization naming the
scope and an expiry.

The boundary is enforced in the code, not in a policy document: each operation has a
class, each class belongs to exactly one of two sets, and the broker refuses anything
outside the current mode. A passive run does not attempt an authorized operation and get
refused — it never asks.

| | passive | authorized |
| --- | --- | --- |
| DNS, RDAP, certificate transparency | ✓ | ✓ |
| HTTPS GET of the site root, TLS handshake | ✓ | ✓ |
| `STARTTLS` on a published MX host | ✓ | ✓ |
| TCP connect to unadvertised ports | — | ✓ |
| domain control proof required | — | ✓ |

---

## End to end

### 1. Enrol a domain

The organisation adds a domain. It is canonicalised and checked against the public suffix
list, so nobody can enrol `co.uk`.

### 2. Prove control

The platform issues a token; the organisation publishes it as a TXT record at
`_tyche-verify.<domain>`. Until that resolves, the domain is `pending` and only passive
observation is available. Proofs lapse and must be renewed — a domain that changed hands
last year is not still verified.

### 3. Authorize (only for an authorized assessment)

A signed authorization names the scope and an expiry. It is kept forever, because the
question later is not "may we probe this?" but "were we allowed to, then?".

### 4. Collect

The worker runs a durable step graph. Each step is retried, idempotent and recorded, so a
lost message or a dead worker resumes rather than restarting:

```
plan
  → collect.dns  collect.email  collect.tls  collect.http  collect.rdap  collect.ct
  → collect.ports        (authorized only; skipped, not refused, in a passive run)
  → collect.asn          (reads the DNS collector's addresses)
  → collect.mail_tls     (reads the e-mail collector's MX hosts)
  → normalize → evaluate → score → assess.assets → findings → report
```

Every outbound request goes through one broker that pins the resolved address, refuses
private ranges, bounds redirects and body size, applies rate limits, and records what it
touched. Collectors cannot open sockets themselves.

### 5. Normalize

Raw payloads become typed observations. The rule that matters: **an inconclusive
collection stays inconclusive.** It is never flattened into "absent", because absent is a
proven negative and gets scored.

### 6. Evaluate and score

A versioned catalogue of checks — data, not code — turns observations into results.
Scoring is deterministic: the same evidence and the same methodology version always
produce the same number.

Six pillars, weighted: DNS 20%, e-mail 20%, web/TLS 25%, attack surface 15%, reputation
10%, exposure hygiene 10%.

| band | score |
| --- | --- |
| Rezilient / Resilient | 90–100 |
| Gestionat / Managed | 75–89 |
| În dezvoltare / Developing | 55–74 |
| Expus / Exposed | 30–54 |
| Critic / Critical | 0–29 |

**Coverage governs the band, not the number.** If too little could be determined, the
score still stands and the band is withheld — a band is a conclusion, and a reader who
sees one assumes somebody was entitled to draw it. `not_applicable` leaves the
denominator; `unknown` reduces coverage.

### 7. Findings and guidance

Each failed check becomes a finding with a lifecycle across runs — first seen, last seen,
resolved when it stops being observed. Each carries bilingual guidance: why it matters,
what to do, how to verify, and **a caveat where following the advice can break
something**. Guidance nobody has reviewed is labelled as draft on the page carrying it.

### 8. Report

A self-contained HTML document: bilingual, CONFIDENTIAL-marked, fetching nothing over the
network so it renders from a downloads folder years later. The download link is a
credential — stored hashed, bound to the person who asked, single use, five minutes.

### Alongside: self-assessment and the observatory

A **maturity questionnaire** covers what no external observation can see — governance,
backups, incident response — and produces a 30/60/90 day roadmap.

The **Public Observatory** publishes passive results about public bodies, through a
separate database role that cannot reach tenant tables at all, behind a moderation and
consent boundary.

---

## Running it

Requirements: Docker, Python 3.13 (via `uv`), Node 22 (via `pnpm`). See
[local setup](docs/development/setup.md).

```sh
make bootstrap        # toolchains, dependencies, database
make check            # 15 gates: format, types, tests, contracts, migrations, secrets, SBOM…
```

Then, in separate terminals — the full walkthrough is in [docs/demo.md](docs/demo.md):

```sh
make stack-up         # PostgreSQL and Redis
make migrate          # schema to head
make api-serve        # the API on :8000
make web-serve        # the web application
make worker-serve     # runs assessments
make beat-serve       # the scheduler; exactly one
```

Skipping either of the last two is the quietest failure available: everything looks fine
until an assessment is started and it never moves.

Open the web application and sign in. In development there are two personas:
`admin`/`admin` sees other organisations through recorded, time-bounded support grants,
and `expert`/`expert` sees exactly what a client sees.

To assess a domain with no enrolment at all, passively:

```sh
python scripts/observe_domain.py example.ro
```

---

## How it is built

| | |
| --- | --- |
| `apps/web` | Next.js 16, TypeScript, Romanian and English |
| `services/api` | FastAPI, Python 3.13 |
| `services/worker` | Celery, the collectors, the policy engine |
| `packages/policy` | the methodology, checks and guidance — versioned data |
| `packages/contracts` | OpenAPI, generated; drift fails a gate |
| `infra` | images, compose stacks, Prometheus and Alertmanager |

**Tenancy is enforced by the database.** Every tenant table has row-level security with
`FORCE`, so it applies to the table owner too. The API connects as a role that cannot
bypass it, and refuses to start if it finds itself connected as one that can — a
credential is a claim, `current_user` is the fact.

Five roles, each able to do one job: `siembiot_owner` migrates, `siembiot_app` serves,
`siembiot_worker` runs assessments, `siembiot_public` serves the observatory and cannot
resolve a tenant table, `siembiot_retention` is the only role that may delete evidence.

**Evidence is append-only**, enforced by triggers. There are exactly two sanctioned
exceptions and each must be declared in the transaction that uses it: retention, and
erasure of an organisation on request.

**The audit trail is chained.** Each event is hashed with its predecessor, per
organisation, by a database trigger — so it covers writes that never went through the
application. `SELECT * FROM audit_chain_breaks();` returns nothing for an intact history.

---

## Operations

Retention, erasure, backup and restore, alerting and measured baselines are documented in
[docs/operations/deployment.md](docs/operations/deployment.md), including what is **not**
there yet. A runbook that omits its gaps reads as complete.

---

## Status

Milestones 0–5, 7 and 9 are implemented; 8 and 10 are partly done. The
[implementation plan](docs/plans/2026-08-03-production-implementation-plan.md) is the
authority, and [deployment.md](docs/operations/deployment.md) lists the operational gaps
plainly.

Not production-ready. No independent penetration test has been carried out, no
point-in-time recovery exists, and the questionnaire and remediation catalogues are
substantially in draft — labelled as such wherever they are shown.

## Documents

- [Product specification](docs/product/product-specification.md)
- [Target architecture](docs/architecture/target-architecture.md)
- [Threat model](docs/security/threat-model.md)
- [Architecture decisions](docs/adr/README.md)
- [Methodology](docs/methodology/)
- [Implementation plan](docs/plans/2026-08-03-production-implementation-plan.md)
- [Demo walkthrough](docs/demo.md)
- [Changelog](CHANGELOG.md)

## Upstream relationship

Microsoft Tyche is a read-only architectural reference pinned in the audit. Its Git
history, configuration, credentials, generated files, dependencies and ticket-management
functionality are not part of this repository. No Microsoft endorsement is implied.

## License

MIT. See [LICENSE](LICENSE).
