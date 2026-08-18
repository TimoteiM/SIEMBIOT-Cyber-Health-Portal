"""The Celery binding.

Celery is not installed as a test dependency, and that is the point of these tests:
everything the correctness of a run depends on must be reachable and assertable
without a broker. If the queue were load-bearing, this file could not exist.
"""

from __future__ import annotations

import os
from unittest import mock

import pytest
from siembiot_worker.tasks import (
    ASSESSMENT_QUEUE,
    DEFAULT_BROKER_URL,
    SWEEP_INTERVAL_SECONDS,
    assessment_is_settled,
    broker_url,
    database_url,
)


def test_the_queue_is_configurable_and_defaults_to_local_redis() -> None:
    with mock.patch.dict(os.environ, {}, clear=True):
        assert broker_url() == DEFAULT_BROKER_URL
    with mock.patch.dict(os.environ, {"SIEMBIOT_REDIS_URL": "redis://queue:6379/2"}):
        assert broker_url() == "redis://queue:6379/2"


def test_the_worker_uses_its_own_role_not_the_apis() -> None:
    """Migration 0009 lets the worker's role write without a human membership.

    The API must not be able to reach that permission, so the worker must never fall
    back to the API's credentials even when they are the only ones present.
    """
    with mock.patch.dict(
        os.environ,
        {
            "SIEMBIOT_APP_DATABASE_URL": "postgresql://siembiot_app:x@db/siembiot",
            "SIEMBIOT_DATABASE_URL": "postgresql://siembiot_owner:x@db/siembiot",
        },
        clear=True,
    ):
        with pytest.raises(RuntimeError):
            database_url()

    with mock.patch.dict(
        os.environ,
        {"SIEMBIOT_WORKER_DATABASE_URL": "postgresql://siembiot_worker:x@db/siembiot"},
        clear=True,
    ):
        assert "siembiot_worker" in database_url()


def test_the_database_url_is_required_rather_than_guessed() -> None:
    with mock.patch.dict(os.environ, {}, clear=True), pytest.raises(RuntimeError):
        database_url()


def test_the_driver_is_normalized_for_sqlalchemy() -> None:
    with mock.patch.dict(
        os.environ,
        {"SIEMBIOT_WORKER_DATABASE_URL": "postgresql://u:p@db/siembiot"},
        clear=True,
    ):
        assert database_url().startswith("postgresql+psycopg://")


def test_a_settled_state_is_recognised_without_a_broker() -> None:
    for state in ("completed", "partially_completed", "failed", "cancelled"):
        assert assessment_is_settled(state) is True
    for state in ("queued", "collecting", "evaluating"):
        assert assessment_is_settled(state) is False


def test_the_sweep_interval_is_unhurried() -> None:
    """A run waiting out a backoff window is not lost, so the sweep need not be eager."""
    assert SWEEP_INTERVAL_SECONDS >= 10.0


def test_the_queue_name_is_explicit() -> None:
    assert ASSESSMENT_QUEUE == "assessments"


def test_the_module_imports_without_celery_installed() -> None:
    """Importing the worker must not require the broker library.

    Everything that decides what a run does lives below Celery, so the package has to
    be usable -- and testable -- with no broker present at all.
    """
    import siembiot_worker.tasks as tasks

    assert hasattr(tasks, "run_assessment")
    assert hasattr(tasks, "due_assessments")
    assert hasattr(tasks, "build_celery_app")


def _app() -> object:
    from siembiot_worker.tasks import build_celery_app

    with mock.patch.dict(os.environ, {"SIEMBIOT_REDIS_URL": "redis://localhost:6379/1"}):
        return build_celery_app()


def test_redelivery_is_safe_so_acknowledgement_is_late() -> None:
    """A worker that dies mid-run must have its message redelivered, not dropped.

    That is only safe because the engine deduplicates on idempotency keys and reclaims
    expired leases -- so a redelivered task resumes rather than repeating work.
    """
    conf = _app().conf  # type: ignore[attr-defined]
    assert conf.task_acks_late is True
    assert conf.task_reject_on_worker_lost is True


def test_a_worker_does_not_hoard_messages_it_cannot_start() -> None:
    """Assessments are long. Prefetching would idle work another worker could run."""
    assert _app().conf.worker_prefetch_multiplier == 1  # type: ignore[attr-defined]


def test_celery_does_not_retry_because_the_engine_owns_the_attempt_budget() -> None:
    """Two retry mechanisms would silently multiply the real budget and hide it."""
    app = _app()
    task = app.tasks["siembiot.run_assessment"]  # type: ignore[attr-defined]
    assert task.max_retries == 0


def test_the_sweep_is_scheduled_so_stalled_runs_recover_unattended() -> None:
    schedule = _app().conf.beat_schedule  # type: ignore[attr-defined]
    assert schedule["sweep-due-assessments"]["task"] == "siembiot.sweep"


def test_tasks_carry_identifiers_rather_than_evidence() -> None:
    """A message sitting in a broker queue must not be a copy of private findings."""
    import inspect

    app = _app()
    signature = inspect.signature(app.tasks["siembiot.run_assessment"].run)  # type: ignore[attr-defined]
    assert set(signature.parameters) == {
        "assessment_id",
        "organization_id",
        "domain_id",
        "host",
        # The mode the run was recorded with. It decides what the platform may do to
        # the domain, so it travels with the task rather than being defaulted at the
        # far end, where a scheduling detail would be making that decision.
        "mode",
        "declared_dkim_selectors",
    }


def test_only_json_is_accepted_off_the_wire() -> None:
    """Pickle would make a broker with write access a remote code execution path."""
    conf = _app().conf  # type: ignore[attr-defined]
    assert conf.task_serializer == "json"
    assert list(conf.accept_content) == ["json"]


def test_the_entrypoint_exposes_a_module_level_app_for_the_celery_cli() -> None:
    with mock.patch.dict(os.environ, {"SIEMBIOT_REDIS_URL": "redis://localhost:6379/1"}):
        from siembiot_worker import celery_app

    assert celery_app.app.main == "siembiot"


def _tasks_source() -> str:
    from pathlib import Path as _Path

    return (
        _Path(__file__).resolve().parents[2] / "services/worker/src/siembiot_worker/tasks.py"
    ).read_text(encoding="utf-8")


def test_a_failed_evidence_write_takes_back_the_terminal_state() -> None:
    """The engine marks a run terminal before its evidence is written.

    So a failure in the write left an assessment reading `completed` with nothing stored
    behind it, and a report could be minted whose findings cited no evidence at all. That
    happened: a check constraint rejected one write, the run reported success, and zero
    observations were saved.

    Asserted structurally rather than by calling the helper, because the helper working
    is not the same as it being reached -- a mistake already made once in this codebase,
    where a normalizer was written, tested, and never called.
    """
    import ast

    tree = ast.parse(_tasks_source())
    run = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "run_assessment"
    )

    guarded = []
    for node in ast.walk(run):
        if not isinstance(node, ast.Try):
            continue
        writes_evidence = any(
            isinstance(inner, ast.Call)
            and isinstance(inner.func, ast.Name)
            and inner.func.id == "persist_assessment"
            for inner in ast.walk(node)
        )
        if not writes_evidence:
            continue
        for handler in node.handlers:
            recovers = any(
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Name)
                and inner.func.id == "_mark_evidence_not_persisted"
                for inner in ast.walk(handler)
            )
            reraises = any(
                isinstance(inner, ast.Raise) and inner.exc is None for inner in ast.walk(handler)
            )
            if recovers and reraises:
                guarded.append(handler)

    assert guarded, (
        "the evidence write is not wrapped in a handler that both corrects the "
        "assessment state and re-raises"
    )


def test_the_state_correction_never_replaces_the_error_that_caused_it() -> None:
    """If the database is what failed, correcting the state fails too.

    Letting that exception escape would bury the real traceback under a less useful one,
    and the real traceback is the only thing that explains why a run has no evidence.
    """
    import ast

    tree = ast.parse(_tasks_source())
    marker = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_mark_evidence_not_persisted"
    )
    handlers = [node for node in ast.walk(marker) if isinstance(node, ast.Try)]
    assert handlers, "the correction is not itself guarded"
    assert all(
        not any(isinstance(inner, ast.Raise) for inner in ast.walk(handler))
        for node in handlers
        for handler in node.handlers
    ), "the correction re-raises and would mask the original failure"
