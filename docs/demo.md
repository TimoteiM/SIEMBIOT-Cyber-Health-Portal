# Walking the product end to end

Fifteen minutes, one fictional institution, every screen. This is the path to follow to
see what the platform does, and it is the path that was actually run to check the
screens work rather than a description written from the code.

Everything you will see about **Primăria Orașului Exemplu** is invented. Its domains are
under `.test`, which RFC 2606 reserves so that no real institution is ever named by an
example, and its scores were hand-written rather than measured.

## 1. Start the infrastructure

```bash
docker compose -p siembiot-local -f infra/compose/local-stack.compose.yml --env-file .env up -d --wait
```

PostgreSQL and Redis in containers; the API and web application run on the host, which
is the fastest loop to work in. (`infra/compose/production-like.compose.yml` runs the
real images instead and answers a different question — "does it deploy". It binds the
same ports, so stop one before starting the other.)

Then apply the schema and register the methodology:

```bash
export SIEMBIOT_DATABASE_URL="postgresql+psycopg://siembiot_owner:$SIEMBIOT_POSTGRES_OWNER_PASSWORD@127.0.0.1:$SIEMBIOT_POSTGRES_PORT/siembiot"
python -m alembic -c services/api/alembic.ini upgrade head
python scripts/publish_methodology.py
```

## 2. Seed the demonstration

```bash
python scripts/seed_demo.py --approve-publication
```

It prints the identifiers it created and is safe to run twice. It refuses to run unless
`SIEMBIOT_ENV` is `development` and the domains are reserved names, because seeded rows
are indistinguishable from measured ones once written — which is what makes them useful
here and unacceptable anywhere else.

`--approve-publication` also records a publication review under an obviously fictional
reviewer and projects the primary domain into the public observatory. It is opt-in
because publishing requires a named person to have approved it, and forging that
signature is exactly what the interlock exists to prevent. Without the flag everything
else still works and the observatory stays empty.

## 3. Run the API, the web application, the worker and the scheduler

Four processes. The API answers requests, the web application serves the interface,
the worker runs assessments, and the scheduler turns cadences into runs. Skipping
either of the last two is the quietest failure in this list: everything looks fine
until you start an assessment and it never moves.

```bash
# The API. Note the empty gateway secret -- see below.
SIEMBIOT_IDENTITY_GATEWAY_SECRET="" \
SIEMBIOT_ENV=development \
SIEMBIOT_APP_DATABASE_URL="postgresql+psycopg://siembiot_app:$SIEMBIOT_POSTGRES_APP_PASSWORD@127.0.0.1:$SIEMBIOT_POSTGRES_PORT/siembiot" \
SIEMBIOT_PUBLIC_DATABASE_URL="postgresql+psycopg://siembiot_public:$SIEMBIOT_POSTGRES_PUBLIC_PASSWORD@127.0.0.1:$SIEMBIOT_POSTGRES_PORT/siembiot" \
python -m uvicorn --app-dir services/api/src --factory siembiot.main:create_app --host 127.0.0.1 --port 8000
```

```bash
# The web application, signed in as the fictional mayor.
cd apps/web
SIEMBIOT_API_BASE_URL=http://127.0.0.1:8000 \
SIEMBIOT_DEV_IDENTITY_SUBJECT=demo-primar \
SIEMBIOT_DEV_IDENTITY_EMAIL=primar@primaria-exemplu.test \
SIEMBIOT_DEV_IDENTITY_NAME="Elena Marinescu" \
corepack pnpm dev --port 3100
```

> **`SIEMBIOT_IDENTITY_GATEWAY_SECRET=""` is not a typo, and leaving it out is the one
> thing most likely to cost you twenty minutes.** The root `.env` sets that secret for
> the production-like stack. The API reads `.env` directly, so if the secret is present
> it builds the *trusted gateway* resolver and ignores the development identity headers
> the web application injects — and every authenticated page answers 401 with nothing in
> the logs to explain why. Local development has no gateway, so the secret must be empty.

```bash
# The worker, which is what actually runs assessments.
make worker-serve

# The scheduler, in a fourth terminal. Celery refuses --beat on Windows, and one
# scheduler is what you want in production regardless.
make beat-serve
```

> **Without the worker, pressing "Observă public" appears to do nothing.** The run is
> created and queued, the page shows `0 din 13 etape (0%)`, and it stays there — which
> looks like a broken button and is actually an empty queue. Nothing errors, because
> nothing went wrong: the API's job ends at enqueuing. Beat re-sweeps every thirty
> seconds, so starting the worker later picks up a run that has been sitting there.
>
> The seeded institution's screens do not need the worker — its assessments are already
> written. You need it the moment you assess a real domain.

Sign in as `demo-it` (Andrei Dobre) instead to see the same workspace as a security
admin rather than an owner.

## 4. The walkthrough

Open `https://localhost:3100` and accept the self-signed certificate. The organisation
identifier is printed by the seed; substitute it for `{org}` below.

| # | Where | What it shows |
| --- | --- | --- |
| 1 | `/organizations/{org}/domains` | Two verified domains. Enrolment, and the proof-of-control state that gates everything else. |
| 2 | `/organizations/{org}/domains/{domain}` | Verification, the explicit authorization consent text, and — at the bottom — **publication consent**. |
| 3 | `/organizations/{org}/assessments` | Passive observation versus authorized assessment, and the reassessment cadence. |
| 4 | `.../domains/{domain}/findings` | Score **63.6 / 100 · Developing**, coverage 100%, and per-finding remediation guidance with the plan control. |
| 5 | `.../domains/{domain}/history` | Two runs, and the change between them stated only because both cleared the coverage floor. |
| 6 | `/organizations/{org}/maturity` | The self-assessment: **declared 36%**, completeness 100%, and one declaration the assessment disagrees with. |
| 7 | `/observatory` | The public list — no session required. |
| 8 | `/observatory/primaria-exemplu.test` | The published profile: band, coverage, and 17 of 22 checks. |

### The four things worth stopping on

**Findings (4) — a score that refuses to flatter.** 63.6 is not a grade curve; it is the
weighted result of what was observed, and the page shows coverage next to it because a
score from a fraction of the surface is not the same claim as a score from all of it.

**Maturity (6) — one answer the evidence contradicts.** The questionnaire says email
authentication is *"documented, applied, and tested in the last 12 months"*. The
assessment sees DMARC failing. The page says so in a paragraph rather than a badge:
*"Ați declarat că această măsură este aplicată, dar evaluarea observă contrariul."* That
disagreement is the most useful sentence on the screen, and it is the reason a
self-assessment score is never combined with a measured one.

**Publication (2 and 7) — consent that can be withdrawn.** Press **Retrage publicarea**
on the domain page and reload `/observatory`. The profile is gone on the very next read:
the row is deleted in the same transaction, not flagged, and nothing is cached. Press
**Acceptă publicarea** again and re-run the seed to bring it back.

**The observatory (8) — what is absent.** No numeric score, no evidence, no identifier,
and none of the five checks the catalogue classes private. A public page that cannot be
assembled into something the institution did not agree to publish.

## Switching language

The header switches between Romanian and English. Romanian is the source language: the
English is a translation of it, not the other way round.

## What this demonstration cannot show

- **A real assessment of a real domain.** Passive observation works against any live
  domain — enrol one on the domains page and press **Observă public** — but the seeded
  institution's `.test` domains resolve to nothing, so their evidence is invented.
- **Real proof of control.** The seed asserts `verified` because there is no zone to
  publish a token into. On any real domain, verification is a DNS TXT record or an HTTPS
  file, and publication is refused until it succeeds.
- **A real publication review.** The reviewer recorded by `--approve-publication` is
  fictional. Publishing actual institutions needs a privacy and legal decision that no
  script can stand in for; `docs/publication/safety-policy.md` says what is still open.
