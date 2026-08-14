# Next block: identity, deployment, abuse controls

Scoped 2026-08-14, after the rescope in [scope-2026-08-14.md](scope-2026-08-14.md). This
is what stands between a working assessment engine and a free tool the public can use.

**None of it is product design.** The engine works on real domains today. What follows is
the service around it, and it is the reason this is a month rather than a fortnight.

## 1. Identity — the long pole

**This is the biggest gap, not the reputation collector.** There is currently no
authentication at all:

* `/sign-in` is a development identity picker gated on `NODE_ENV === "development"`, and
  it says on its own face that it does not authenticate;
* the middleware that injects identity headers is gated three ways and never runs in a
  production build;
* the API's production resolver requires a gateway shared secret, and expects a gateway
  in front of it that does not exist.

That arrangement is correct for a deployment behind an institutional SSO. It is not a
login, and a public tool needs one.

### Recommendation: hosted OIDC, no password storage

The resolver was built for exactly this — `build_identity_resolver` already chooses
between a trusted-gateway resolver and a development one, and `provision_user` already
maps `(issuer, subject)` to a local user on first sight. What is missing is the third
implementation: one that completes an OIDC code flow itself rather than trusting a
gateway's headers.

**The provider choice is yours** and depends on what Romanian institutional users already
have accounts with. Two observations that may help:

* Public administration in Romania is heavily Microsoft-tenanted, so Entra ID accounts are
  common — but many smaller *primării* use whatever the mayor's office set up, frequently
  a Gmail address on a custom domain.
* Supporting both is roughly 20% more work than one, not double: the flow is identical and
  only discovery metadata and client credentials differ. If you cannot decide, that is the
  answer.

**What the platform must not do**, and would be the tempting shortcut: accept the OIDC
`email` claim as proof of anything beyond identity. Domain ownership is proven by the
challenge flow, which already works. An `@primaria-x.ro` address must not confer control
of `primaria-x.ro` — that would make a compromised mailbox a route into somebody else's
assessment data.

**Estimate: 1–2 weeks.** Session handling, sign-out, the callback route, and the sign-in
page becoming real. The `__Host-` cookie work is already there from the earlier session
model.

## 2. Deployment — the boring one

| Piece | Note |
| --- | --- |
| One host, `production-like.compose.yml` | Runs today. It is a rehearsal that happens to be a deployment. |
| TLS termination | Caddy or nginx in front. `SIEMBIOT_PUBLIC_BASE_URL` must match the scheme exactly or every write is refused — the API logs what it expected. |
| `SIEMBIOT_BACKUP_DESTINATION` | Off the database's disk. The task refuses to run otherwise and says which of seven reasons applied. |
| Secrets | Five passwords and the gateway secret. All fail closed; `.env.example` documents each. |
| `docs/operations/jobs.md` | Already written. **Start `beat`** — without it nothing runs at all. |

**Estimate: 3–5 days**, most of it DNS, certificates and waiting.

## 3. Abuse controls — the part a public tool needs and a private one did not

Today an authenticated user may enrol any domain and run unlimited passive assessments
against it. Verification gates *authorized* assessment; it does not gate passive
observation, and passive observation of arbitrary domains at scale is the abuse vector.

That was a defensible design when every user was a known customer. It is not defensible
when anyone can sign in with a Google account.

| Control | Why | Effort |
| --- | --- | --- |
| Assessments per organization per day | Nothing limits this. One account can enumerate every `.ro` domain it can think of. | 1 day |
| Domains enrolled per organization | Enrollment is free and unbounded. | half day |
| A published position on assessing domains you do not own | Passive observation of public records is lawful and is the product's premise. Doing it thousands of times an hour from one IP is a different thing, and the difference should be written down before somebody asks. | half day |
| Per-IP limit on sign-up | Otherwise the per-organization limits are one registration away from meaningless. | 1 day |

Challenge creation is already limited to three per domain per hour, which is the pattern
to copy — same table, same shape of query.

**Estimate: 2–3 days.**

## Sequence

1. **Abuse controls first.** They are the cheapest, and shipping a public tool without
   them is the one mistake here that affects other people's infrastructure rather than
   ours.
2. **Identity.** Longest, and everything user-facing waits on it.
3. **Deployment.** Last, because deploying something nobody can log into proves little.

**Roughly a month for a small team**, and nothing in it is blocked on an external answer
— unlike the reputation providers, which wait on Spamhaus.

## Explicitly not in this block

The maturity methodology document, `infra/deploy/`, posture pages, visual-regression
tests, and Measured/Inferred/Recommended labelling in the analyst panel. All deferrable,
none blocking, per the rescope.
