# Publication safety policy

What this platform may say about a named organisation in public, and the controls that
keep it to that.

This document describes the system as built. It is **not** the privacy and legal review
it refers to: see [What is not decided here](#what-is-not-decided-here) at the end.

## The one-sentence version

A public profile exists only for a domain whose control was proved, whose organisation
opted in, that is not under a takedown, that has a completed non-projected assessment,
and only after a named person recorded approval for the exact methodology and catalogue
that assessment ran with. Any one of those missing means no profile.

## What may be published

| Published | Not published |
| --- | --- |
| The registrable domain | Any organisation, domain, user or assessment identifier |
| The band (`resilient` … `critical`), or nothing | The numeric score |
| Coverage percentage | Raw evidence, observations, or artefacts |
| Per-check outcome for checks the catalogue classes `public_profile` | Any check classed `private_only` |
| Only `pass`, `fail`, `warning` | `unknown`, `error`, `not_applicable`, `suppressed`, `accepted_risk` |
| The methodology version and policy digest | Findings, remediation plans, self-assessment answers, audit events |

Three of these are worth their reasons:

**No numeric score.** A band is coarse enough to be useful and too coarse to rank
institutions against each other. A score invites a league table of Romanian public
bodies, which is the specific reputational harm that makes this milestone need legal
review in the first place.

**No `unknown` or `error`.** Those describe *our* collection — a resolver that timed out,
a host that refused a connection. Publishing them beside real outcomes would attribute
our failures to somebody else's infrastructure.

**Which checks are publishable is not decided here.** The policy catalogue classifies
every check with `public_safety_class`, versioned and reviewed with the methodology.
Reclassifying a check to `private_only` removes it from public pages with no code change.
Currently 17 of 22 checks are publishable; the 5 that are not are those whose result
either hints at something exploitable or carries reputational weight beyond hygiene.

## How the boundary is enforced

Not by review discipline. By the database.

- The published read model lives in its own schema, `observatory`.
- `siembiot_public` is granted `USAGE` on `observatory` and **not** on `public`, which
  holds every tenant table. `USAGE` on `public` is revoked from `PUBLIC` and granted back
  only to the owner, app and worker roles. A public route cannot read a tenant table,
  cannot join to one, and cannot name one — the schema does not resolve.
- A table added by a later migration is therefore unreachable by default. This is the
  property that has to survive people who are not thinking about publication.
- `observatory` contains no organisation, domain, user, assessment or finding identifier.
  A copy of it cannot be joined back to anything, by us or by anyone who obtains it.
- The projection is built by **allowlist**: every published field is constructed by name
  in `publication/projection.py`. There is no dict passthrough, so a column added to a
  private table is not published by whoever adds it.

`tests/api/test_publication.py` asserts each of these against a real connection as the
real role. The last time this project trusted a grant it had read rather than one it had
tested, the API was running as a superuser and every row-level security policy had
silently stopped applying.

## Consent

Per **domain**, not per organisation: an institution may be willing to publish one site
and not another, and an all-or-nothing switch is one they would answer with "no".

- Granting consent **publishes nothing**. It is a precondition, not a trigger. Nobody
  puts their own institution on a public page by clicking once.
- Consent requires verified control. Passive observation deliberately needs no proof of
  control — it reads only what a domain already publishes — but attaching a security
  posture to an institution's *name* is a different act, and doing it for a domain nobody
  proved they hold is publishing about a third party.
- Withdrawing consent **deletes** the published profile, in the same transaction that
  records the withdrawal. Not a flag: a flag survives in caches, replicas and queries
  written later by somebody who did not know to check it. If the call returns, the
  profile is gone.
- The consent record itself is kept after withdrawal, so "did they ever agree, and when
  did they withdraw" stays answerable.
- Withdrawal requires no explanation. Friction on that action is friction in exactly the
  wrong place.

The API is granted `DELETE` on published profiles and no `INSERT`. **It can always take
something down and can never put something up.** Removal is safe; publication is the
dangerous direction and has exactly one caller, running as the owner.

## Moderation

A takedown outranks consent. Somebody outside the tenant saying a profile should come
down must beat the tenant's own switch, or the control is advisory. Takedowns are keyed
on the registrable domain and carry a reason and a recorder.

## Aggregates

Cohort statistics are suppressed below **5 contributing profiles**. "One of the two
published county hospitals fails DMARC" names a hospital, and nobody had to be careless
for it to happen — it is what a small denominator does on its own.

A thin cohort is **absent entirely**: not rounded, not a range, not "fewer than five".
A suppression that appears only where the count is small is itself a signal, and an
observer who can see which cohorts are missing learns most of what was being hidden.

The threshold is also a `CHECK` constraint on `observatory.aggregates`, so a bug in the
code that computes cohorts fails at the insert rather than quietly on a public page.

## The review interlock

`publication_reviews` records a privacy and legal decision against a specific
methodology version **and policy digest**. The projector refuses to run without an
approving row.

It is a table rather than a configuration flag because a flag has no author, no date and
nothing to point at afterwards. Matching on the digest means a catalogue edited after
sign-off — even one keeping the same version string — needs approving again: the digest
is what the reviewer actually read. A later `refused` row stops publication without
anybody deleting the record that approval was once given.

## What is not decided here

These are open, and they are not engineering decisions:

- **No review has been recorded.** No approving row exists, so nothing can be published
  today. That is the intended state until somebody with the authority to decide records
  one. The interlock is the mechanism; it is not the decision.
- **Whether Romanian public institutions may be published at all**, on what legal basis,
  and whether consent from an organisation's administrator is sufficient — or whether
  something further is required for public bodies.
- **Whether a band is a personal-data or reputational risk** requiring notice beyond the
  consent flow as built.
- **Correction and dispute handling.** An institution that believes a published result is
  wrong currently has takedown and withdrawal, both blunt. A correction workflow with an
  audit trail is specified in the plan and is not built.
- **Public pages.** There is no public-facing site over `observatory` yet. The read model,
  the boundary and the controls exist; the pages do not.
- **Contested claims.** One published profile per registrable domain, and only a verified
  domain may be published, so two organisations cannot both publish the same host. What
  happens when control legitimately transfers is unhandled.

Until the first item is resolved, the observatory is empty by construction rather than by
convention, and that is the safest state for it to be in.
