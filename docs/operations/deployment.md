# Deployment

Four images, four processes, two databases roles, one scheduler. What follows is what
an operator needs to run it and what to do when it misbehaves.

## The processes

| Image | What it does | Scale | Reaches the internet |
| --- | --- | --- | --- |
| `api` | Serves requests | horizontally | no |
| `worker` | Carries out assessments | horizontally | **yes** |
| `beat` | Decides what is due | **exactly one** | no |
| `web` | Serves the interface | horizontally | no |

`beat` is a separate image rather than a flag on the worker precisely so that "exactly
one" is something you state in a deployment rather than remember. Two schedulers would
enqueue every due assessment twice — harmless, because the engine deduplicates, but
twice the load against other people's infrastructure for nothing.

`worker` is the only process that makes outbound connections to targets. Egress policy
belongs on that one.

## Credentials

Three database roles, three passwords, and they must not be shared.

| Variable | Role | Used by |
| --- | --- | --- |
| `SIEMBIOT_DATABASE_URL` | `siembiot_owner` | **migrations only** |
| `SIEMBIOT_APP_DATABASE_URL` | `siembiot_app` | the API |
| `SIEMBIOT_WORKER_DATABASE_URL` | `siembiot_worker` | the worker and the scheduler |

The owner is a superuser, and **superusers bypass row-level security even where it is
declared `FORCE`**. Serving from the owner switches off tenant isolation completely and
silently: every query still succeeds and every organization can read every other one's
rows. The API refuses to start as a privileged role rather than trusting configuration
— see [database-roles.md](../security/database-roles.md).

`SIEMBIOT_IDENTITY_GATEWAY_SECRET` is required outside development. Without it the API
would trust identity headers from anyone who could reach the port, so it refuses to
start rather than falling back.

## Running it

```
# Once, and whenever migrations change. Never from the API's startup.
docker compose -f infra/compose/production-like.compose.yml --profile migrate \
  --env-file .env run --rm migrate

docker compose -f infra/compose/production-like.compose.yml --env-file .env up -d
python scripts/smoke_test.py
```

Migrations are a one-shot job because an API that migrates on boot races itself the
moment there is more than one replica, and because it would need the owner credential
in the environment of the process that serves requests.

Before anything can be assessed, the policy catalog must be registered:

```
python scripts/publish_methodology.py
```

Every assessment, finding and score carries a foreign key to the methodology version
that produced it, so a report can always be traced to the exact policy it was scored
against.

## Probes

**`/api/v1/health` is liveness.** It touches nothing. A liveness probe that checks the
database makes an orchestrator restart every replica during a database outage, which
does not fix the database and delays recovery once it returns.

**`/api/v1/ready` is readiness.** It answers 503 when the database is unreachable, and
names which dependency failed. Not ready removes a replica from rotation; not alive
restarts it. Confusing the two turns a recoverable dependency outage into a restart
loop.

Neither worker nor scheduler has a healthcheck. A Celery worker has no socket to probe,
and `celery inspect ping` would declare the container unhealthy whenever the broker was
briefly away — restarting a worker mid-run to no purpose. The engine already treats an
interrupted run as resumable.

## When it misbehaves

**The API will not start.** Read the message; it fails closed on purpose. Either the
gateway secret is missing, or it is connected as a role that bypasses row-level
security. Both are refusals, not crashes.

**Assessments are queued but never run.** The worker is not consuming, or the scheduler
is not enqueueing. Check `docker compose logs worker beat`. A queued assessment is not
lost: the sweep re-enqueues anything unsettled every 30 seconds, so a worker that comes
back picks up the backlog without intervention.

**A domain stopped being assessed.** Its cadence may be `off`, its quiet hours may
cover the current time, its verification may have lapsed (authorized runs stop; passive
observation continues), or a previous run may still be in flight. `app_due_schedules`
holds the whole decision in one function and is the fastest place to check.

**Scores dropped across the board.** Look at coverage before posture. A collection
failure lowers coverage and can move scores without anything changing at the targets;
the history endpoint marks such comparisons as incomparable for exactly this reason.

**Redis is gone.** The API is unaffected: creating an assessment writes a row and never
touches the broker. Work resumes when Redis returns, because the sweep reads due work
from PostgreSQL rather than from the queue.

## What is not here yet

Stated rather than implied, because a runbook that omits its gaps reads as complete:

- **No backup or restore procedure.** The database holds append-only evidence and audit
  events that cannot be reconstructed. This is the largest remaining operational gap.
- **No metrics, dashboards or alerting.** Logs are structured and redacted, but nothing
  aggregates them and nothing pages anybody.
- **No TLS termination or identity gateway** in this stack. Both are assumed to be in
  front of it; the API's identity resolver is built for exactly that arrangement.
- **No retention or deletion policy.** Evidence accumulates indefinitely.
- **No provider budget or cost monitoring.**
