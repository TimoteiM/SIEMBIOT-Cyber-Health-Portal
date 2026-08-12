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

## Data retention

Every table is classified in `siembiot_worker/retention/policy.py`, and a test fails when
one is not: "nobody listed it" must never be how a table's retention gets decided.

| Class | Period | What |
| --- | --- | --- |
| evidence | 90 days | observations, network operations, scope manifests |
| operational | 30 days | step attempts, idempotency keys |
| ephemeral | 1 day past expiry | report grants, domain challenges |
| record | kept | scores, findings, answers, decisions |
| accountability | never removed | audit, authorizations, support grants, retention runs |
| reference | follows its subject | users, organizations, domains, catalogues |

The sweep runs daily from the scheduler and writes a row to `retention_runs` every time,
including when it removes nothing -- "the job ran and found nothing" and "the job did not
run" are different facts.

**Only `siembiot_retention` may delete evidence.** It is a separate role with a separate
credential, held by the scheduler alone: the workers can add evidence and cannot remove
it, which is what makes a completed assessment trustworthy. It holds `SELECT`/`DELETE` on
the swept tables, a column-level `UPDATE` on one column of `score_snapshots`, and nothing
else -- it cannot alter a score, a band or a digest.

**Removal must also be declared.** The evidence tables are append-only by trigger, and the
single exception is a transaction that sets `app.retention_sweep`. The grant is the
boundary; the flag is what stops a stray `DELETE` elsewhere from succeeding if a grant is
ever widened.

**A score outlives its evidence, and says so.** Once observations are removed, every
snapshot computed from them is stamped `evidence_erased_at`, and reports drawn from it
tell the reader the score can no longer be recomputed. Deleting the workings while still
printing a policy digest would invite exactly the wrong conclusion.

## Erasing an institution on request

Retention ages data out on a timer. This is the other obligation, and its danger is the
opposite one: retention risks deleting too much, erasure risks deleting too little --
because the institution is told it is gone.

```bash
python scripts/erase_organization.py --organization <uuid>            # prints the plan
python scripts/erase_organization.py --organization <uuid> --confirm  # performs it
```

Irreversible, and deliberately manual: no scheduled job runs it, no API exposes it, and it
connects as the owner rather than under a login of its own. A long-lived credential that
can delete any institution's entire history is a worse thing to have in a deployment than
an operator typing a command.

Every table carrying an `organization_id` is found in the catalogue and included, and the
deletion order comes from the foreign keys. Afterwards the script checks that nothing
still names the organization and rolls back if anything does -- an erasure that silently
missed a table is worse than one that failed.

The audit trail goes with it. Audit is chained **per organization**, so removing one
institution's events removes one whole chain and every other chain still verifies; a
single global chain would have made erasure and tamper-evidence mutually exclusive. What
survives is a tombstone in the platform's own chain recording that the organization
existed and was erased, with counts but never content.

## The audit trail is tamper-evident

`previous_hash` and `event_hash` existed from the first migration and nothing ever wrote
them, so the trail was append-only and *not* tamper-evident. Those are different
guarantees: append-only stops the application rewriting history, and a chain is what
stops whoever holds the database credentials -- which is the case an audit trail exists
for.

Each event is now chained to the one before it, per organization, by a `BEFORE INSERT`
trigger rather than by application code: a hash written in `append_audit_event` would
only cover rows that went through it, and the writes worth detecting are the ones that
did not.

To check a trail:

```sql
SELECT * FROM audit_chain_breaks();
```

An empty result is an intact history. Otherwise it names the first break in each
organization's chain and what kind it is -- a row altered, or one removed, reordered, or
inserted with the trigger disabled.

Rows written before this feature carry no hash and are reported as predating it rather
than as breaks. They were deliberately **not** backfilled: hashing them now would digest
whatever they say today, so an already-altered row would be certified as genuine and the
chain would report a spotless history. That is worse than no chain, because it looks like
assurance.

A restore is verified against the chain as well as against row counts -- a substituted
trail can have exactly the right number of rows.

## Alerting

Prometheus scrapes the API, evaluates the rules in `alerts.yml`, and hands what fires to
Alertmanager, which routes on severity: `page` notifies quickly and repeats hourly,
`warning` waits and repeats every four hours.

```bash
docker compose -f infra/compose/production-like.compose.yml up -d prometheus alertmanager alert-sink
```

`alert-sink` stands in for whatever pages a person. Deployments replace the two webhook
URLs in `alertmanager.yml`; this repository does not choose a paging provider, because
that decision is about who is on call and every alternative wants a credential in a file
like this one.

**Demonstrated end to end**, which is the only way to know a chain like this works:

| | |
| --- | --- |
| API stopped | t+0 |
| target marked down | t+30s |
| `ApiDown` pending | t+40s |
| fires (`for: 2m`) | t+150s |
| delivered to the **page** receiver | immediately after |
| API restarted, alert clears | |
| resolved notification delivered | after `group_interval` |

The resolved notification waits a full `group_interval` behind the firing one. That is
the configuration working, not a fault, but it is worth knowing before somebody watches
for one and concludes the chain is broken.

## Measured behaviour

Numbers, rather than the reasoned guesses that stood in for them. Taken with
`scripts/load_test.py` against one API process and one PostgreSQL container on a
developer laptop, so treat them as shape and ratio rather than as capacity for a
deployment -- and re-measure there.

**Tenant reads** (a domain's findings, through row-level security):

| concurrent clients | throughput | p50 | p99 |
| --- | --- | --- | --- |
| 1 | 24/s | 44ms | 88ms |
| 8 | ~101/s | 66ms | ~300ms |
| 24 | ~112/s | 197ms | ~460ms |

Throughput flattens around a hundred reads a second; past that, more clients buy latency
rather than work. That ceiling is the API process itself, not the pool.

**Audit writes**, which are chained and therefore serialized per organization:

| | throughput | p50 | p99 |
| --- | --- | --- | --- |
| 16 writers, one organization | 452/s | 27ms | 72ms |
| 16 writers, eight organizations | 982/s | 5ms | 11ms |

Spreading the same work across eight organizations gives 2.2x the throughput, which is
the per-organization lock behaving as designed: it serializes an institution's own
history and nothing else. Four hundred and fifty events a second within one institution
is far beyond what one generates, so the chain's cost is real and not a constraint.

**The connection pool is set deliberately** in `db.py`, and the reason is in the comment
there. It was at SQLAlchemy's defaults, which nobody had chosen: at 24 concurrent clients
that cost about a third of the throughput and doubled the tail. Below saturation it makes
no difference at all -- the pool was never the limit there.

The ceiling that matters for a deployment is the other one: PostgreSQL accepts
`max_connections` in total, and every API replica multiplies its pool. Raise one without
the other and the failure moves from "slow" to "the database refuses connections".

## Backups

A backup runs daily from the scheduler and **refuses to run without a destination**.
`SIEMBIOT_BACKUP_DESTINATION` must be set, and is rejected when it is inside the
repository or shares a filesystem with the PostgreSQL data directory. A copy on the same
machine as the database survives a dropped table and nothing else, and a deployment
writing there looks identical to one backing up correctly until somebody needs a restore.

Remote schemes (`s3://`, `gs://`, `azure://`, `sftp://`, `nfs://`) are accepted as
off-host by construction; the uploader is the deployment's own tooling.

The refusal is named rather than a boolean, so "no backup last night" says which of four
reasons it was — three of them a minute's configuration.

Point-in-time recovery is decided in
[ADR-0012](../adr/0012-point-in-time-recovery.md): required, and required specifically for
the audit trail, because the event most likely to cause a restore is the event whose audit
record matters most. Evidence tolerates a dump-only restore since it is reproducible and
expires at ninety days anyway. Configuring WAL archiving is the deployment's step.

## Dashboards

`infra/observability/dashboard.json` is a Grafana dashboard whose panels plot the same
series the alert rules read, with the same thresholds. Import it, or provision it from
that path.

Each panel carries a `siembiot-alert` field naming the rule it belongs to, and tests
assert the pairing **both ways**: every rule has a panel, and every panel citing a rule
names one that exists. A dashboard whose lines are green while an alert is firing teaches
people to distrust one of the two, and the one they stop trusting is the alert.

## What is not here yet

Stated rather than implied, because a runbook that omits its gaps reads as complete:

- **No backup destination is configured here.** The schedule exists and refuses to run
  without one; see "Backups" above. Choosing an S3 bucket, an NFS mount or a second host
  is infrastructure with credentials attached and is the deployment's decision.
- **Point-in-time recovery is decided but not configured.** ADR-0012 requires WAL
  archiving for the audit trail and states why evidence does not need it. The
  `archive_command` and its destination are deployment infrastructure; no recovery to a
  chosen time has been demonstrated the way the base restore has.
- **No log aggregation.** Logs are structured and redacted but stay on each host.
- **No TLS termination or identity gateway** in this stack. Both are assumed to be in
  front of it; the API's identity resolver is built for exactly that arrangement.
- **No load testing beyond a laptop.** The numbers above are shape, not capacity.
- **No provider budget or cost monitoring.**
