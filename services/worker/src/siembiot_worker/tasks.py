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

import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from siembiot_worker.observation.mode import AssessmentMode
from siembiot_worker.observation.runtime import build_observation_runtime
from siembiot_worker.policy.catalog import load_catalog
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
    context = AssessmentContext(
        organization_id=organization_id,
        assessment_id=assessment_id,
        host=host,
        catalog=catalog,
        # The mode comes from the row, which the API wrote under a check constraint
        # requiring an authorization for the wider mode. Defaulting here instead would
        # let a scheduling bug decide what the platform is allowed to do to a domain.
        runtime=build_observation_runtime(mode=mode),
        clock=lambda: datetime.now(UTC),
        declared_dkim_selectors=declared_dkim_selectors,
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
                    observations=context.observations,
                    evaluations=context.evaluations,
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
            }
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
