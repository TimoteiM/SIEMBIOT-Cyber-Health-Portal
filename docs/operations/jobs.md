# Scheduled jobs

Five periodic jobs. One scheduler decides when they run, and the workers carry them out.

This document exists because of a specific failure: the platform was started with the
API, the interface and a worker, everything reported healthy, and **nothing ever ran**.
Assessments sat at `queued`, the worker sat connected and idle, and the queue was empty.
Nothing was broken. The scheduler simply was not running, and no page said it had to be.

## The one thing to know first

**The API never publishes to the broker.** Creating an assessment writes a row with state
`queued` and commits. That write *is* the enqueue.

From `services/api/src/siembiot/assessments.py`:

> The API does not talk to the broker. Writing 'queued' inside this transaction *is* the
> enqueue: the worker's sweep claims anything unsettled and not waiting out a backoff
> window. Publishing a message here instead would be a second write that can fail after
> this one commits, leaving a run nobody ever picks up — and it would make creating an
> assessment depend on Redis being reachable, which it need not be.

That design is why creating an assessment works while Redis is down, and why a lost
message costs nothing. It is also why **no scheduler means no work at all**, however
healthy everything else looks.

### What stops without the scheduler

| Symptom | Looks like |
| --- | --- |
| Assessments stay `queued` forever | a broken worker |
| Cadences never produce runs | a customer who "stopped being monitored" |
| Expired evidence is never removed | a retention policy that is documented and not applied |
| No backup is ever taken | nothing, until somebody needs a restore |
| Provider quota is never recorded | dashboards flat at zero |

None of those raises an error. Every one of them is silence.

The alert that catches it is `AssessmentsNotProgressing` — it fires when the oldest
unsettled assessment passes an hour, which is an age rather than a count precisely
because a count cannot tell a busy platform from a stopped one. `BackupStale` catches the
backup half a day and a half later. Neither exists on a laptop, which is why this page
starts where it does.

## Exactly one scheduler

Two schedulers enqueue every due assessment twice. The engine deduplicates, so nothing
breaks — it is simply twice the load against other people's infrastructure for nothing.

That is why `beat` is a separate image from `worker` rather than a `--beat` flag: "exactly
one" is then something a deployment states rather than something an operator remembers.
Scale the workers freely; never scale beat.

The schedule file lives at `/tmp/celerybeat-schedule` because the root filesystem is
read-only. Losing it on restart is harmless: every entry is a fixed interval rather than a
crontab, so beat reschedules immediately from configuration.

## The five jobs

| Beat entry | Task | Every | Credential |
| --- | --- | --- | --- |
| `sweep-due-assessments` | `siembiot.sweep` | 30s | `SIEMBIOT_WORKER_DATABASE_URL` |
| `start-scheduled-assessments` | `siembiot.start_scheduled` | 10min | `SIEMBIOT_WORKER_DATABASE_URL` |
| `snapshot-provider-quota` | `siembiot.snapshot_quota` | 5min | `SIEMBIOT_WORKER_DATABASE_URL` + Redis |
| `apply-retention` | `siembiot.apply_retention` | 24h | **`SIEMBIOT_RETENTION_DATABASE_URL`** |
| `take-backup` | `siembiot.take_backup` | 24h | **`SIEMBIOT_BACKUP_DATABASE_URL`** |

All five are routed to the `assessments` queue, which is the only queue the worker
consumes.

### sweep — 30 seconds

Enqueues every run that is due, and it is what makes the platform self-healing. A lost
message, a worker that died mid-run, and a step that has finished waiting out a backoff
window are all picked up here without anyone re-triggering anything by hand.

Returns how many runs it dispatched. `succeeded ... : 0` is the healthy steady state;
`: 2` means it found two runs nobody had started.

Thirty seconds because a run parked behind a backoff window is not lost — it waits for
the next sweep — so the interval is an ordinary number rather than something urgent.

**The task that does the actual work is `siembiot.run_assessment`**, one per due run,
dispatched by the sweep. It is not on the schedule and never appears in beat's log, but it
is most of what a worker log contains — so an operator grepping for it should know it is
sweep-dispatched rather than wondering what enqueued it.

Celery retries it zero times, deliberately. The engine owns retry policy and backoff;
letting both retry would double the attempt budget and hide the real one.

### start_scheduled — 10 minutes

Turns cadences into runs, and expires stale domain verifications. Expiry runs first, so a
domain whose proof lapsed today is not granted an authorized run in the same pass.

Ten minutes rather than thirty seconds because the shortest cadence offered is daily:
checking more often asks the same question and gets "not yet".

Watched by `SchedulerNotDispatching`, which fires when anything is still due after thirty
minutes — three missed passes. Silence here is the dangerous failure: a domain that
quietly stops being monitored looks exactly like a domain with nothing wrong.

### snapshot_quota — 5 minutes

Copies today's shared quota counters from Redis into `provider_quota_snapshots`. Redis is
the live truth; this is the record the metrics endpoint reads. Without it the counters
exist and nothing can see them.

A failure is logged and swallowed rather than raised: the counters are still correct in
Redis and the next pass records them, whereas a raising task would turn a monitoring gap
into a worker that looks broken.

### apply_retention — daily

Removes data past its retention period, across every organization.

**Runs as `siembiot_retention`, deliberately not as the worker.** The worker can insert
evidence and cannot remove it, which is what makes a completed assessment trustworthy;
retention holds the opposite pair. Keeping them apart means neither job can quietly
acquire the other's authority because somebody widened a grant.

It also runs outside any tenant scope, because binding it to one tenant would silently
sweep only that tenant's data while reporting success for all of it.

Every run is recorded in `retention_runs`, including runs that removed nothing —
otherwise "nothing was deleted" and "the sweep never ran" are the same row.

Daily because the shortest retention period is a day. Deliberately not aligned to
midnight: a sweep is a burst of deletes, and every deployment starting one at the same
instant is how a shared database gets a nightly stall.

### take_backup — daily

Runs `pg_dump` in custom format, places the archive at the configured destination, and
records the attempt in `backup_runs` — **failures included**, because a table of only
successes cannot distinguish a broken backup from a scheduler that never fired.

**Runs as `SIEMBIOT_BACKUP_DATABASE_URL`, deliberately not as the worker.** Every
tenant-scoped table carries row-level security with `FORCE`, so a dump taken by a role
subject to those policies would contain only the rows that role can see — and would
restore without complaint. It must name `siembiot_owner` or another role that can bypass
row security.

It refuses rather than guesses, and every refusal is a named reason:

| Reason | Fix |
| --- | --- |
| `backup_destination_not_configured` | set `SIEMBIOT_BACKUP_DESTINATION` |
| `backup_credentials_not_configured` | set `SIEMBIOT_BACKUP_DATABASE_URL` |
| `backup_destination_shares_filesystem_with_database` | choose a destination off the database's disk |
| `backup_destination_inside_repository` | choose a destination outside the working tree |
| `backup_destination_unwritable` | fix permissions, or create the directory |
| `pg_dump_not_available` | the image lacks `postgresql-client-17` |
| `no_uploader_for_remote_destination` | the upload is the deployment's own tooling |
| `pg_dump_failed` / `pg_dump_produced_no_output` | read the dump's stderr; nothing was kept |

A dump that fails mid-table leaves a real header and half the rows, and that file restores
into half a database without complaining — so a partial dump is deleted rather than kept.

Watched by `BackupStale` (pages after 36 hours) and `BackupFailing` (warns on any failed
attempt in a day). Two metrics rather than one, because "tried and failed" and "never ran"
are different problems with different fixes.

See [deployment.md](deployment.md#backups) for destination rules and restore verification.

## Running them

Production — one scheduler, workers scaled freely:

```
docker compose -f infra/compose/production-like.compose.yml --env-file .env up -d
```

`beat` is its own service in that file. Nothing else needs doing.

Locally, four processes in four terminals — and the fourth is the one people forget:

```
make api-serve        # 127.0.0.1:8000
make web-serve        # SIEMBIOT_WEB_PORT, default 3000
make worker-serve     # consumes the assessments queue
make beat-serve       # THE SCHEDULER. Without it nothing runs.
```

## Telling whether they are working

Beat says what it sent:

```
Scheduler: Sending due task sweep-due-assessments (siembiot.sweep)
```

The worker says what it did, and what the job returned:

```
Task siembiot.sweep[...] succeeded in 0.48s: 2
```

That trailing number is the job's return value — runs dispatched, runs created, rows
removed, adapters snapshotted. It is the fastest way to tell "ran and found nothing" from
"did not run".

From the database, without any log access:

```sql
-- did retention run, and did it remove anything. `removed` is a jsonb count per
-- table rather than a single number, so "which table" is answerable a year later
SELECT started_at, finished_at, removed, error
FROM retention_runs ORDER BY started_at DESC LIMIT 5;

-- did last night's backup happen, and if not, why
SELECT started_at, size_bytes, error FROM backup_runs ORDER BY started_at DESC LIMIT 5;

-- is anything stuck
SELECT metric, value FROM app_operational_metrics()
WHERE metric IN ('oldest_unsettled_assessment_seconds', 'schedules_due',
                 'last_successful_backup_seconds', 'failed_backups_recent');
```

`last_successful_backup_seconds` reads about `315360000` — ten years — when no backup has
ever succeeded. That is a sentinel, not a scale artefact, and it is also what the exporter
reports when it cannot read the database, so an unreachable database cannot be mistaken
for a fresh backup.

## Why a redelivered task is harmless

Celery's delivery guarantee is at-least-once at best, and the engine does not depend on
it. A redelivered task finds the steps already settled and does nothing; a task that dies
mid-step leaves a lease that expires, so the next delivery reclaims it rather than the
step being stranded; and the dispatcher never blocks on a backoff window — it returns and
lets the next delivery, or the next sweep, pick the run up.

This is why the sweep can run every thirty seconds without coordination, and why losing
the broker entirely costs nothing but time.
