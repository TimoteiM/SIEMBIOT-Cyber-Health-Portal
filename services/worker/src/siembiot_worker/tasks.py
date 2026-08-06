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


@contextmanager
def _tenant_connection(organization_id: UUID) -> Iterator[Any]:
    """A connection scoped to one tenant, so row-level security applies.

    The worker is not exempt from tenant isolation. `app_is_worker_for` grants it
    nothing beyond the organization named here, so a bug that reached for another
    tenant's rows would find none -- rather than the isolation guarantee resting on
    this file being correct.
    """
    from sqlalchemy import create_engine, text

    engine = create_engine(database_url(), pool_pre_ping=True)
    with engine.begin() as connection:
        connection.execute(
            text("SELECT set_config('app.organization_id', :value, true)"),
            {"value": str(organization_id)},
        )
        yield connection
    engine.dispose()


def run_assessment(
    assessment_id: UUID,
    organization_id: UUID,
    domain_id: UUID,
    host: str,
    *,
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
        runtime=build_observation_runtime(),
        clock=lambda: datetime.now(UTC),
        declared_dkim_selectors=declared_dkim_selectors,
    )

    with _tenant_connection(organization_id) as connection:
        workflow = PostgresWorkflowRepository(connection, organization_id)
        engine = WorkflowEngine(workflow, build_handlers(context))
        state = engine.run(assessment_id, organization_id)

        # Evidence is written whenever there is any, not only on a clean finish, so a
        # partially completed run keeps what it managed to collect.
        if context.observations:
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
        declared_dkim_selectors: list[str] | None = None,
    ) -> str:
        """Celery retries nothing: the engine owns retry policy and backoff.

        Letting both retry would double the attempt budget and hide the real one.
        """
        del self
        return run_assessment(
            UUID(assessment_id),
            UUID(organization_id),
            UUID(domain_id),
            host,
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
            )
        return len(due)

    return app


def assessment_is_settled(state: str) -> bool:
    return is_terminal(AssessmentState(state))
