# The queue boundary

The broker schedules; PostgreSQL decides. Every guarantee this platform makes about a
run — that it happened once, that it can be cancelled, that its evidence is intact —
is enforced in the database, not in Celery. This document explains why, and what
follows from it.

## Why not trust the queue

Redis gives at-most-once or at-least-once delivery depending on how it is configured,
and never exactly-once. A design that treated a message as the record of intent would
have to answer, for every failure, "did the work happen?" — and it could not, because
the message is gone either way.

So the message carries no authority. It says only *look at this assessment*. What
happens next is decided by reading state, and the state lives in one place.

## What follows

**Creating an assessment does not touch the broker.** The API writes a row with state
`queued` inside the same transaction as its audit event, and returns. There is no
second write that can fail after the first commits, and no way to create an assessment
that nothing will ever pick up. It also means the API stays available when Redis is
not — a user can still enrol a domain, read a past report, or request a run.

**The worker finds work by asking the database.** `siembiot.sweep` runs every 30
seconds and enqueues every assessment that is unsettled and not waiting out a backoff
window. That single query is what makes the system self-healing: a lost message, a
worker killed mid-run, a step that has finished waiting — all are picked up without
anyone re-triggering them.

**Redelivery is safe, so acknowledgement is late.** `task_acks_late` and
`task_reject_on_worker_lost` mean a worker that dies has its message redelivered rather
than dropped. That is only sound because the engine deduplicates on idempotency keys
and reclaims expired leases, so a redelivered task resumes where the last one stopped
instead of repeating side effects.

**Celery retries nothing.** `max_retries=0`. The engine owns the attempt budget and the
backoff schedule. Two retry mechanisms would silently multiply the real budget and make
it impossible to reason about how many times a check can hit somebody's server.

**A worker does not hoard messages.** `worker_prefetch_multiplier=1`. Assessments take
minutes; prefetching would leave work idle in one worker's buffer that another could
have started.

## What is on the wire

Identifiers only: assessment, organization, domain, hostname. No observations, no
findings, no scores. A broker with read access learns *that* an organization is being
assessed, which is already more than nothing — but it does not learn what was found.

`accept_content` is restricted to JSON. Celery's pickle serializer would turn write
access to the broker into remote code execution on every worker.

Redis runs without persistence (`--save "" --appendonly no`). A lost queue costs one
sweep interval, so durability there would buy nothing and would put a copy of the
schedule on disk for no reason.

## The worker's identity

Every row-level security policy written before this asked the same question: does the
current *person* have an active membership here? That is right for a request made on
someone's behalf and unanswerable for the worker, which acts on nobody's behalf. So
migration 0009 adds two things, both deliberately narrow.

**`siembiot_worker` is a separate login role.** Its policies let it write inside an
organization without a membership — but only the organization named in
`app.organization_id`, so a worker connection is confined to exactly one tenant, just
like a user's. `tests/database/test_scheduling_seam.py` asserts that a scoped worker
cannot read or write another tenant's rows.

It is a *role* and not a session flag for one reason: whoever can talk to the database
as the API's role can already set any session variable they like. If the worker's write
permission were a flag, that would be enough to write into any tenant. A role requires
credentials the API does not have.

**`app_due_assessments` is the only cross-tenant read.** It is `SECURITY DEFINER`, it
returns four columns — assessment, organization, domain, hostname — and it must never be
widened to evidence. `EXECUTE` is revoked from `PUBLIC` (PostgreSQL grants it by
default) and given only to the worker, so a SQL injection in the API cannot use it to
enumerate every organization's domains.

Reviewing this boundary means reading one function body and one predicate, not a
service.

## Running it

```
make worker-serve   # the workers; scale these out
make beat-serve     # the scheduler; exactly one
```

They are separate processes because Celery refuses `--beat` on Windows, and because it
is what you want in production regardless: workers scale horizontally, the scheduler
must not. A second scheduler would enqueue every due run twice — harmless, since the
engine deduplicates, but twice the load for nothing.

Before any assessment can be created at all, the policy catalog must be registered:

```
python scripts/publish_methodology.py
```

Every assessment, evaluation, finding and score snapshot carries a foreign key to the
methodology version that produced it, so a report can always be traced back to exactly
the policy it was scored against.

## Testing without a broker

`tests/workflows/test_tasks.py` runs with no Redis anywhere. That is the load-bearing
property, not a convenience: `build_celery_app()` is a function rather than a
module-level object precisely so nothing that determines what a run *does* sits behind
an import of Celery. If that file ever needed a broker to run, the inversion described
here would have been lost.
