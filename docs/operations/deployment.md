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

## Backup and restore

The database holds the only two things in the product that cannot be rebuilt:
append-only evidence, and the audit trail of who did what. The schema, the policy
catalog and the images all live in the repository.

```
python scripts/backup.py create
python scripts/backup.py verify artifacts/backups/<name>
```

**Run `verify`.** A backup nobody has restored is a file, not a backup. `verify`
restores into a throwaway database, checks it, and drops it — it is the only way to
know the archive is worth keeping. Wire it into whatever runs the backup, so a broken
one is discovered on an ordinary Tuesday rather than during an incident.

What the manifest records, and why each would otherwise pass unnoticed:

| Recorded | What its loss would look like |
| --- | --- |
| Row counts per irreplaceable table | A restore that "succeeded" with evidence missing |
| Tables with **forced** row-level security | Isolation still enabled, but the owner reading every tenant |
| Append-only triggers | Evidence that can be edited afterwards |
| Schema version | A restore into a cluster the application cannot migrate |
| Roles | A database nobody can connect to |

The expectations are captured when the backup is taken, not computed at restore time: a
check that derives its own expectation from the restored database agrees with itself
whatever was lost.

**Backups contain no credentials.** Roles are dumped with `--no-role-passwords`, so the
archive holds no secret and does not need to be guarded like one. Set the three
passwords from your secret store after restoring, exactly as at first install.

To restore for real:

```
python scripts/backup.py restore artifacts/backups/<name> --into siembiot
```

Then set the role passwords, run `prod-migrate` if the schema has moved on since, and
`make smoke`.

## Monitoring

`GET /metrics` on the API, in Prometheus exposition format. Rules with a stated reason
for every threshold are in [`infra/observability/alerts.yml`](../../infra/observability/alerts.yml).

**Nothing in a scrape identifies a tenant or a target.** That is the design constraint,
not a consequence: a metrics endpoint is scraped on a timer and stored in a system with
its own, usually looser, access rules. A label carrying an organization id would quietly
export the customer list; one carrying a hostname would export the list of domains under
assessment. Every label comes from a set the schema already constrains.

Ingress should still not expose the path — but the endpoint is built so that exposure
would be an embarrassment rather than a breach, because relying on a proxy rule alone
leaves the customer list one misconfiguration away from being published.

The counts come from `app_operational_metrics`, a `SECURITY DEFINER` function, for a
reason worth knowing before changing it. The API runs as a role row-level security
applies to, so querying the tables directly returned **zero for everything** — not an
error, because row-level security hides rows rather than refusing. A monitoring system
would have recorded a healthy, idle platform indefinitely. Silent zeros are worse than a
failed scrape: a failed scrape is visible.

The signal to watch first is `siembiot_oldest_unsettled_assessment_seconds`. A count of
queued runs cannot tell a busy platform from a stuck one; the age of the oldest can.

A failed scrape reports `siembiot_metrics_scrape_ok 0` rather than returning an error,
because a monitoring system that receives nothing looks exactly like one watching a
quiet, healthy platform.

## What is not here yet

Stated rather than implied, because a runbook that omits its gaps reads as complete:

- **Backups are not scheduled and not stored off-host.** The tooling works and is
  verified; nothing runs it on a timer, and `artifacts/` is on the same machine as the
  database, which is not a backup of anything that fails together.
- **No point-in-time recovery.** A dump loses everything since it was taken. For
  evidence that is tolerable; for the audit trail it may not be, and that is a decision
  somebody should make deliberately.
- **Nothing scrapes the metrics and nothing routes the alerts.** The endpoint and the
  rules exist and are tested; no Prometheus is deployed, and no alert reaches a person.
- **No log aggregation.** Logs are structured and redacted but stay on each host.
- **No dashboards.** The metrics support them; none are defined.
- **No TLS termination or identity gateway** in this stack. Both are assumed to be in
  front of it; the API's identity resolver is built for exactly that arrangement.
- **No retention or deletion policy.** Evidence accumulates indefinitely.
- **No provider budget or cost monitoring.**
