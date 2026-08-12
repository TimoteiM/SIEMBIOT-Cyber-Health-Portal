"""The Celery binding.

Deliberately thin. The queue's only job is to say *when* to look at an assessment;
PostgreSQL decides what actually happens. That inversion is what lets this module be
almost trivial — and it is why the engine's correctness does not depend on Celery's
delivery guarantees, which are at-least-once at best.

Concretely:

* a task carries only identifiers, never evidence, so a message in a broker's queue is
  not a copy of somebody's private findings;
* a redelivered task finds the steps already settled and does nothing;
* a task that dies mid-step leaves a lease that expires, so the next delivery reclaims
  it rather than the step being stranded;
* the dispatcher never blocks on a backoff window: it returns and lets the next
  delivery, or the periodic sweep, pick the run up.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from siembiot_worker.backups import resolve_destination
from siembiot_worker.collectors.ct_source import BrokeredCTSource
from siembiot_worker.observation.mode import AssessmentMode
from siembiot_worker.observation.runtime import build_observation_runtime
from siembiot_worker.policy.catalog import load_catalog
from siembiot_worker.retention import SweepResult, record_run, sweep_retention
from siembiot_worker.scheduling import (
    advance_from,
    due_schedules,
    expire_stale_verifications,
)
from siembiot_worker.telemetry import log_event
from siembiot_worker.workflows.assets import CandidateState
from siembiot_worker.workflows.engine import WorkflowEngine
from siembiot_worker.workflows.evidence_repository import EvidenceRepository, persist_assessment
from siembiot_worker.workflows.handlers import AssessmentContext, build_handlers
from siembiot_worker.workflows.lifecycle import AssessmentState, is_terminal
from siembiot_worker.workflows.postgres_repository import PostgresWorkflowRepository

DEFAULT_BROKER_URL = "redis://localhost:6379/0"
ASSESSMENT_QUEUE = "assessments"

#: How often the sweep looks for runs that are due. A run parked behind a backoff
#: window is not lost -- it simply waits for the next sweep, which is why the interval
#: is a normal number of seconds rather than something urgent.
SWEEP_INTERVAL_SECONDS = 30.0

#: How often schedules are turned into runs, and stale verifications expired. Ten
#: minutes rather than thirty seconds because the shortest cadence offered is daily:
#: checking more often would only ask the same question repeatedly and get "not yet".
SCHEDULE_INTERVAL_SECONDS = 600.0

#: How often expired data is removed. Daily, because the shortest retention period is a
#: day and running more often would ask the same question and delete nothing. Deliberately
#: not aligned to midnight: a sweep is a burst of deletes, and every deployment starting
#: one at the same instant is how a shared database gets a nightly stall.
RETENTION_INTERVAL_SECONDS = 86_400.0

#: How often a backup is taken. Daily, matching the retention sweep: a deployment losing
#: at most a day of evidence is the trade this schedule makes, and it is the trade the
#: point-in-time recovery decision in ADR-0012 exists to revisit for the audit trail.
BACKUP_INTERVAL_SECONDS = 86_400.0

#: How often the shared quota counters are copied into the database. Five minutes: often
#: enough that an alert on a spent budget fires while it still matters, rare enough that
#: the upsert is not itself a load.
QUOTA_SNAPSHOT_INTERVAL_SECONDS = 300.0

log = logging.getLogger("siembiot.worker")


def broker_url() -> str:
    return os.environ.get("SIEMBIOT_REDIS_URL", DEFAULT_BROKER_URL)


def database_url() -> str:
    """The worker's own credentials.

    Not the API's. Migration 0009 lets this role write within one tenant without a
    human membership -- a permission the API must not be able to reach, which is what
    makes it a separate role rather than a session flag.
    """
    url = os.environ.get("SIEMBIOT_WORKER_DATABASE_URL")
    if not url:
        raise RuntimeError(
            "SIEMBIOT_WORKER_DATABASE_URL is required for the worker. It must name the "
            "siembiot_worker role; the API's role cannot carry out a run."
        )
    return url.replace("postgresql://", "postgresql+psycopg://")


#: How long to wait for a row lock before giving up. A worker that finds a step locked
#: has met another worker already doing it, so the useful answer is "not mine" arriving
#: promptly -- not a thread parked for the length of somebody else's run.
LOCK_TIMEOUT_MS = 2000


def _tenant_engine() -> Any:
    from sqlalchemy import create_engine

    return create_engine(database_url(), pool_pre_ping=True)


def _scope_to_tenant(connection: Any, organization_id: UUID) -> None:
    """Bind a connection to one tenant, so row-level security applies to it.

    The worker is not exempt from tenant isolation. `app_is_worker_for` grants it
    nothing beyond the organization named here, so a bug that reached for another
    tenant's rows would find none -- rather than the isolation guarantee resting on
    this file being correct.

    `false` rather than `true` for the local flag: under autocommit there is no
    surrounding transaction for a local setting to belong to, so it has to persist for
    the session.
    """
    from sqlalchemy import text

    connection.execute(
        text("SELECT set_config('app.organization_id', :value, false)"),
        {"value": str(organization_id)},
    )
    connection.execute(text(f"SET lock_timeout = {LOCK_TIMEOUT_MS}"))


@contextmanager
def _workflow_connection(engine: Any, organization_id: UUID) -> Iterator[Any]:
    """A connection that commits each step as it settles.

    Deliberately *not* one transaction around the whole run. The engine's leases and
    idempotency keys exist precisely because work is handed between processes, and
    neither means anything to another worker until it is committed: an uncommitted
    lease is invisible, so a second worker would block on the row rather than see that
    the step is taken.

    It is also what makes progress durable. A run wrapped in a single transaction loses
    everything it did if the process dies at minute nine -- which is the exact failure
    the durable engine was built to survive.
    """
    connection = engine.connect().execution_options(isolation_level="AUTOCOMMIT")
    try:
        _scope_to_tenant(connection, organization_id)
        yield connection
    finally:
        connection.close()


@contextmanager
def _evidence_transaction(engine: Any, organization_id: UUID) -> Iterator[Any]:
    """Evidence is written atomically: a report is a set of rows or it is nothing.

    The opposite call to the one above, and for the opposite reason. Observations,
    evaluations, the score snapshot and the findings describe one another; half of them
    is not a partial report, it is an incoherent one.
    """
    with engine.begin() as connection:
        _scope_to_tenant(connection, organization_id)
        yield connection


def run_assessment(
    assessment_id: UUID,
    organization_id: UUID,
    domain_id: UUID,
    host: str,
    *,
    mode: AssessmentMode = AssessmentMode.PASSIVE_OBSERVATION,
    declared_dkim_selectors: tuple[str, ...] = (),
) -> str:
    """Drive one assessment as far as it can go right now.

    Returns the state it reached. A run parked behind a backoff window returns a
    non-terminal state, which is not a failure: the next delivery continues it.
    """
    catalog = load_catalog()
    accepted = _accepted_assets(organization_id, domain_id)
    runtime = build_observation_runtime(mode=mode)
    context = AssessmentContext(
        organization_id=organization_id,
        assessment_id=assessment_id,
        host=host,
        catalog=catalog,
        # The mode comes from the row, which the API wrote under a check constraint
        # requiring an authorization for the wider mode. Defaulting here instead would
        # let a scheduling bug decide what the platform is allowed to do to a domain.
        runtime=runtime,
        # A real Certificate Transparency index, rather than the empty source that was
        # the default in every deployed run since asset discovery was written. With the
        # empty one, `collect.ct` reported "no entries" for every domain on earth.
        ct_source=BrokeredCTSource(runtime.broker, organization_id, domain_id, assessment_id),
        clock=lambda: datetime.now(UTC),
        declared_dkim_selectors=declared_dkim_selectors,
        accepted_assets=accepted,
    )

    database = _tenant_engine()
    try:
        with _workflow_connection(database, organization_id) as connection:
            workflow = PostgresWorkflowRepository(connection, organization_id)
            engine = WorkflowEngine(workflow, build_handlers(context))
            state = engine.run(assessment_id, organization_id)

        # Evidence is written whenever there is any, not only on a clean finish, so a
        # partially completed run keeps what it managed to collect.
        if context.observations:
            with _evidence_transaction(database, organization_id) as connection:
                evidence = EvidenceRepository(connection, organization_id, domain_id)
                persist_assessment(
                    evidence,
                    assessment_id=assessment_id,
                    domain_id=domain_id,
                    catalog=catalog,
                    # The domain's own evidence and every accepted host's, written
                    # together. They are separate in the context so the score cannot pick
                    # up a subdomain's result; once scored, they are the same evidence.
                    observations=(*context.observations, *context.asset_observations),
                    evaluations=(*context.evaluations, *context.asset_evaluations),
                    snapshot=context.snapshot,
                    findings=context.findings,
                    asset_candidates=context.asset_candidates,
                    observed_at=datetime.now(UTC),
                )
    finally:
        # In a finally block because the run above can raise: an engine left behind on
        # the error path holds its pooled connections open, and a worker that fails
        # repeatedly would exhaust the server's connection slots rather than just
        # failing repeatedly.
        database.dispose()
    return str(state)


def _accepted_assets(organization_id: UUID, domain_id: UUID) -> tuple[str, ...]:
    """Hosts somebody reviewed and accepted into scope.

    Read at the start of the run rather than carried on the queue message: acceptance is
    a decision that can change between a run being enqueued and it starting, and the
    decision at the moment of assessment is the one that authorized the traffic.
    """
    engine = _tenant_engine()
    try:
        with _evidence_transaction(engine, organization_id) as connection:
            repository = EvidenceRepository(connection, organization_id, domain_id)
            return tuple(
                candidate.name
                for candidate in repository.load_asset_candidates(domain_id)
                if candidate.state is CandidateState.ACCEPTED
            )
    finally:
        engine.dispose()


#: How many runs one sweep will enqueue. A bound, not a policy: anything left over is
#: picked up by the next sweep, so a backlog drains instead of arriving all at once.
SWEEP_BATCH_SIZE = 50


def due_assessments() -> tuple[dict[str, Any], ...]:
    """Runs that are not settled and are not waiting out a backoff window.

    This is the one place the worker reads across tenants, and it does so through
    `app_due_assessments` -- a `SECURITY DEFINER` function that returns identifiers and
    a hostname and nothing else. The worker connects as the ordinary application role
    with no tenant context, so row-level security still hides every other table from it;
    the function is the whole of the exemption. See migration 0009.
    """
    from sqlalchemy import create_engine, text

    engine = create_engine(database_url(), pool_pre_ping=True)
    try:
        with engine.begin() as connection:
            rows = connection.execute(
                text("SELECT * FROM app_due_assessments(:limit)"),
                {"limit": SWEEP_BATCH_SIZE},
            ).mappings()
            return tuple(dict(row) for row in rows)
    finally:
        engine.dispose()


def snapshot_provider_quota() -> int:
    """Read every adapter's counters from Redis and upsert them. Returns how many.

    A failure here is logged and swallowed: the counters are still correct in Redis and
    the next pass will record them, whereas a raising task would turn a monitoring gap
    into a worker that looks broken.
    """
    import redis as redis_client
    from sqlalchemy import text

    from siembiot_worker.adapters.shared_quota import read_all

    readings = read_all(redis_client.Redis.from_url(broker_url()))
    if not readings:
        return 0

    engine = _tenant_engine()
    try:
        with engine.begin() as connection:
            for reading in readings:
                connection.execute(
                    text(
                        """
                        INSERT INTO provider_quota_snapshots
                            (adapter_id, quota_window, used, denied, captured_at)
                        VALUES (:adapter_id, :quota_window, :used, :denied, now())
                        ON CONFLICT (adapter_id, quota_window) DO UPDATE
                        SET used = EXCLUDED.used,
                            denied = EXCLUDED.denied,
                            captured_at = EXCLUDED.captured_at
                        """
                    ),
                    {
                        "adapter_id": reading.adapter_id,
                        "quota_window": reading.window,
                        "used": reading.used,
                        "denied": reading.denied,
                    },
                )
    finally:
        engine.dispose()
    return len(readings)


def retention_database_url() -> str:
    """The role that may forget things, and nothing else.

    Deliberately not the worker's. The worker can insert evidence and cannot remove it,
    which is what makes a completed assessment trustworthy; retention holds the opposite
    pair. Keeping them apart means neither job can quietly acquire the other's authority
    because somebody widened a grant.
    """
    url = os.environ.get("SIEMBIOT_RETENTION_DATABASE_URL")
    if not url:
        raise RuntimeError(
            "SIEMBIOT_RETENTION_DATABASE_URL is required to apply retention. It must "
            "name the siembiot_retention role; no other role may delete evidence."
        )
    return url.replace("postgresql://", "postgresql+psycopg://")


def _retention_engine() -> Any:
    from sqlalchemy import create_engine

    return create_engine(retention_database_url(), pool_pre_ping=True)


def run_retention() -> int:
    """Apply the retention schedule once, and record what it did.

    The sweep and the record of it are separate transactions on purpose. If the sweep
    fails part way, its deletions roll back and the failure is still written down --
    whereas one transaction would roll the record back too and leave a failed sweep
    indistinguishable from a night when nothing ran.
    """
    engine = _retention_engine()
    try:
        try:
            with engine.begin() as connection:
                result = sweep_retention(connection)
        except Exception as error:  # noqa: BLE001 - recorded, then re-raised
            with engine.begin() as connection:
                record_run(connection, SweepResult(), error=str(error)[:500])
            raise
        with engine.begin() as connection:
            record_run(connection, result)
        if result.total or result.snapshots_marked:
            log.info(
                "retention removed %d rows and marked %d snapshots",
                result.total,
                result.snapshots_marked,
            )
        return result.total
    finally:
        engine.dispose()


def start_due_schedules() -> int:
    """Create an assessment for every schedule that is due, and advance each schedule.

    Written as one transaction per schedule rather than one for the batch: a failure on
    the fourth domain must not roll back the three runs already created, because those
    runs are real work the queue may already have picked up.
    """
    from sqlalchemy import text

    engine = _tenant_engine()
    created = 0
    try:
        # Expiry first: a domain whose proof lapsed today should not be handed an
        # authorized run in the same pass that notices it lapsed.
        with engine.begin() as connection:
            expired = expire_stale_verifications(connection)
        if expired:
            log_event(log, "verification expired", domains=expired)

        with engine.begin() as connection:
            pending = due_schedules(connection)

        for schedule in pending:
            with _evidence_transaction(engine, schedule.organization_id) as connection:
                methodology = connection.execute(
                    text("SELECT version FROM methodology_versions ORDER BY version DESC LIMIT 1")
                ).scalar_one_or_none()
                if methodology is None:
                    # Nothing is published to score against, so there is no honest run
                    # to create. Leaving next_run_at alone means the next pass tries
                    # again rather than silently skipping this cadence forever.
                    continue

                assessment_id = uuid4()
                connection.execute(
                    text(
                        """
                        INSERT INTO assessments (
                            id, organization_id, domain_id, methodology_version, state, mode
                        ) VALUES (
                            :id, :organization_id, :domain_id, :methodology_version,
                            'queued', :mode
                        )
                        """
                    ),
                    {
                        "id": assessment_id,
                        "organization_id": schedule.organization_id,
                        "domain_id": schedule.domain_id,
                        "methodology_version": methodology,
                        "mode": schedule.mode,
                    },
                )

                # Advanced only after the run exists. The other order would lose a run
                # whenever the insert failed, and lose it silently.
                connection.execute(
                    text(
                        """
                        UPDATE assessment_schedules
                        SET next_run_at = CASE
                                WHEN cadence = 'off' THEN NULL
                                ELSE :next_run_at
                            END,
                            last_run_at = now(),
                            updated_at = now()
                        WHERE id = :schedule_id
                        """
                    ),
                    {
                        "schedule_id": schedule.schedule_id,
                        "next_run_at": _next_run_for(connection, schedule.schedule_id),
                    },
                )
                created += 1
    finally:
        engine.dispose()
    return created


def _next_run_for(connection: Any, schedule_id: UUID) -> datetime | None:
    """Compute the following firing time from the schedule's own cadence."""
    from sqlalchemy import text

    row = (
        connection.execute(
            text("SELECT cadence, next_run_at FROM assessment_schedules WHERE id = :id"),
            {"id": schedule_id},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    previous = row["next_run_at"] or datetime.now(UTC)
    return advance_from(str(row["cadence"]), previous, datetime.now(UTC))


def build_celery_app() -> Any:
    """Construct the Celery application.

    Imported lazily so the rest of the worker package stays usable — and testable —
    without Celery installed. Nothing above this line depends on the broker.
    """
    from celery import Celery  # noqa: PLC0415

    app = Celery("siembiot", broker=broker_url(), backend=None)
    app.conf.update(
        task_default_queue=ASSESSMENT_QUEUE,
        task_acks_late=True,  # redelivery is safe; the engine deduplicates
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,  # long tasks, so do not hoard messages
        task_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        beat_schedule={
            "sweep-due-assessments": {
                "task": "siembiot.sweep",
                "schedule": SWEEP_INTERVAL_SECONDS,
            },
            "start-scheduled-assessments": {
                "task": "siembiot.start_scheduled",
                "schedule": SCHEDULE_INTERVAL_SECONDS,
            },
            "apply-retention": {
                "task": "siembiot.apply_retention",
                "schedule": RETENTION_INTERVAL_SECONDS,
            },
            "take-backup": {
                "task": "siembiot.take_backup",
                "schedule": BACKUP_INTERVAL_SECONDS,
            },
            "snapshot-provider-quota": {
                "task": "siembiot.snapshot_quota",
                "schedule": QUOTA_SNAPSHOT_INTERVAL_SECONDS,
            },
        },
    )

    @app.task(name="siembiot.run_assessment", bind=True, max_retries=0)
    def run_assessment_task(
        self: Any,
        assessment_id: str,
        organization_id: str,
        domain_id: str,
        host: str,
        mode: str = AssessmentMode.PASSIVE_OBSERVATION.value,
        declared_dkim_selectors: list[str] | None = None,
    ) -> str:
        """Celery retries nothing: the engine owns retry policy and backoff.

        Letting both retry would double the attempt budget and hide the real one.

        An unrecognised mode is refused rather than coerced: the alternative is a
        typo silently widening what the platform may do to somebody's domain.
        """
        del self
        return run_assessment(
            UUID(assessment_id),
            UUID(organization_id),
            UUID(domain_id),
            host,
            mode=AssessmentMode(mode),
            declared_dkim_selectors=tuple(declared_dkim_selectors or ()),
        )

    @app.task(name="siembiot.start_scheduled")
    def start_scheduled() -> int:
        """Create the runs that cadences are due for, and expire stale verifications.

        Returns how many runs were created. The two jobs share a task because both are
        periodic maintenance over the same tenants, and running expiry first means a
        domain whose proof lapsed today is not given an authorized run this pass.
        """
        return start_due_schedules()

    @app.task(name="siembiot.snapshot_quota")
    def snapshot_quota() -> int:
        """Copy today's shared quota counters into the database.

        Redis is the live truth and this is the record. The metrics endpoint reads the
        database, so without this the counters exist and nothing can see them -- which
        was the state the adapters were in since Milestone 3.
        """
        return snapshot_provider_quota()

    @app.task(name="siembiot.take_backup")
    def take_backup() -> str:
        """Take a backup, if there is somewhere safe to put it.

        Returns the refusal reason rather than raising when there is not. A deployment
        with no destination configured has a configuration problem, and a task that
        crashed nightly would be reported as a broken worker rather than as the missing
        setting it is -- while a task that silently succeeded would be worse still.
        """
        verdict = resolve_destination()
        if not verdict.usable:
            log.error("backup not taken: %s", verdict.refusal)
            return str(verdict.refusal)
        # The dump and the upload are the deployment's own tooling: `scripts/backup.py`
        # for a container-local database, or a managed provider's snapshot. What this
        # task owns is the schedule and the refusal.
        log.info("backup destination accepted: %s", verdict.destination)
        return "destination_ready"

    @app.task(name="siembiot.apply_retention")
    def apply_retention() -> int:
        """Remove data past its retention period.

        Returns how many rows were removed. Runs as the worker role and outside any
        tenant scope: retention is platform housekeeping across every organization, and
        binding it to one tenant would silently sweep only that tenant's data while
        reporting success for all of it.
        """
        return run_retention()

    @app.task(name="siembiot.sweep")
    def sweep() -> int:
        """Enqueue every run that is due.

        The sweep is what makes the system self-healing: a lost message, a worker that
        died mid-run, or a step that has finished waiting all get picked up here
        without anyone re-triggering them by hand.
        """
        due = due_assessments()
        for row in due:
            run_assessment_task.delay(
                str(row["assessment_id"]),
                str(row["organization_id"]),
                str(row["domain_id"]),
                row["host"],
                row["mode"],
            )
        return len(due)

    return app


def assessment_is_settled(state: str) -> bool:
    return is_terminal(AssessmentState(state))
