"""The durable engine.

The acceptance criteria for this milestone are about delivery semantics: duplicate or
out-of-order delivery must not duplicate evidence or corrupt state, and partial
completion must survive a worker or provider failure. These tests attack exactly that.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from siembiot_worker.workflows.engine import (
    StepContext,
    StepOutcome,
    WorkflowEngine,
    WorkflowError,
    backoff_seconds,
    idempotency_key,
)
from siembiot_worker.workflows.graph import DEFAULT_GRAPH, StepState
from siembiot_worker.workflows.lifecycle import AssessmentState
from siembiot_worker.workflows.memory_repository import InMemoryWorkflowRepository

ORGANIZATION = UUID("11111111-1111-4111-8111-111111111111")
ASSESSMENT = UUID("22222222-2222-4222-8222-222222222222")
START = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self, start: datetime = START) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class Recorder:
    """Counts how many times each step actually executed."""

    def __init__(self) -> None:
        self.calls: dict[str, int] = {}

    def handler(
        self, outcome: Callable[[StepContext], StepOutcome] | None = None
    ) -> Callable[[StepContext], StepOutcome]:
        def run(context: StepContext) -> StepOutcome:
            self.calls[context.step.name] = self.calls.get(context.step.name, 0) + 1
            return outcome(context) if outcome else StepOutcome.ok()

        return run


def build(
    *,
    repository: InMemoryWorkflowRepository | None = None,
    overrides: dict[str, Callable[[StepContext], StepOutcome]] | None = None,
    clock: Clock | None = None,
    recorder: Recorder | None = None,
) -> tuple[WorkflowEngine, InMemoryWorkflowRepository, Recorder, Clock]:
    the_clock = clock or Clock()
    repo = repository or InMemoryWorkflowRepository(clock=the_clock)
    rec = recorder or Recorder()
    handlers = {name: rec.handler() for name in DEFAULT_GRAPH.names}
    handlers.update(overrides or {})
    engine = WorkflowEngine(
        repo,
        handlers,
        clock=the_clock,
        jitter=lambda: 1.0,
        worker_id=uuid4(),
    )
    return engine, repo, rec, the_clock


# -- the happy path ----------------------------------------------------------


def test_a_clean_run_executes_every_step_once_and_completes() -> None:
    engine, repository, recorder, _ = build()
    outcome = engine.run(ASSESSMENT, ORGANIZATION)
    assert outcome is AssessmentState.COMPLETED
    assert set(recorder.calls) == set(DEFAULT_GRAPH.names)
    assert all(count == 1 for count in recorder.calls.values())
    assert repository.load_state(ASSESSMENT) is AssessmentState.COMPLETED


def test_progress_reaches_one_hundred_percent_only_when_every_step_settled() -> None:
    engine, _, _, _ = build()
    engine.run(ASSESSMENT, ORGANIZATION)
    progress = engine.progress(ASSESSMENT)
    assert progress.complete is True
    assert progress.percentage == 100.0


def test_the_run_walks_the_lifecycle_in_order() -> None:
    engine, repository, _, _ = build()
    engine.run(ASSESSMENT, ORGANIZATION)
    visited = [state for _, state in repository.transitions]
    assert visited.index(AssessmentState.PLANNING) < visited.index(AssessmentState.COLLECTING)
    assert visited.index(AssessmentState.COLLECTING) < visited.index(AssessmentState.NORMALIZING)
    assert visited[-1] is AssessmentState.COMPLETED


# -- duplicate and out-of-order delivery -------------------------------------


def test_a_redelivered_run_does_not_execute_any_step_twice() -> None:
    engine, _, recorder, _ = build()
    engine.run(ASSESSMENT, ORGANIZATION)
    first = dict(recorder.calls)

    # The queue redelivers the same message; the durable state already says done.
    engine.run(ASSESSMENT, ORGANIZATION)
    assert recorder.calls == first


def test_an_idempotency_key_is_deterministic_for_identical_work() -> None:
    payload = {"domain": "example.test", "profile": "passive"}
    assert idempotency_key(ASSESSMENT, "collect.dns", payload) == idempotency_key(
        ASSESSMENT, "collect.dns", payload
    )


def test_a_changed_input_is_new_work_not_a_deduplicated_repeat() -> None:
    first = idempotency_key(ASSESSMENT, "collect.dns", {"domain": "a.test"})
    second = idempotency_key(ASSESSMENT, "collect.dns", {"domain": "b.test"})
    assert first != second


def test_keys_are_scoped_to_the_run_and_the_step() -> None:
    payload = {"domain": "example.test"}
    assert idempotency_key(ASSESSMENT, "collect.dns", payload) != idempotency_key(
        uuid4(), "collect.dns", payload
    )
    assert idempotency_key(ASSESSMENT, "collect.dns", payload) != idempotency_key(
        ASSESSMENT, "collect.tls", payload
    )


def test_a_key_already_recorded_short_circuits_the_step() -> None:
    """Simulates a crash after the work completed but before the state was written."""
    clock = Clock()
    repository = InMemoryWorkflowRepository(clock=clock)
    recorder = Recorder()
    engine, _, _, _ = build(repository=repository, recorder=recorder, clock=clock)

    key = idempotency_key(ASSESSMENT, "plan", {})
    assert repository.record_completed_key(key, ASSESSMENT, "plan") is True

    engine.run(ASSESSMENT, ORGANIZATION)
    assert "plan" not in recorder.calls
    assert repository.load_steps(ASSESSMENT)["plan"].result["deduplicated"] is True


# -- leases ------------------------------------------------------------------


def test_a_live_lease_held_by_another_worker_blocks_execution() -> None:
    clock = Clock()
    repository = InMemoryWorkflowRepository(clock=clock)
    other_worker = uuid4()
    assert repository.acquire_lease(
        ASSESSMENT, "plan", other_worker, clock.now + timedelta(seconds=300)
    )

    recorder = Recorder()
    engine, _, _, _ = build(repository=repository, recorder=recorder, clock=clock)
    engine.run(ASSESSMENT, ORGANIZATION)
    assert "plan" not in recorder.calls


def test_an_expired_lease_is_reclaimed_so_a_dead_worker_cannot_strand_a_step() -> None:
    clock = Clock()
    repository = InMemoryWorkflowRepository(clock=clock)
    dead_worker = uuid4()
    repository.acquire_lease(ASSESSMENT, "plan", dead_worker, clock.now + timedelta(seconds=10))
    clock.advance(60)

    recorder = Recorder()
    engine, _, _, _ = build(repository=repository, recorder=recorder, clock=clock)
    assert engine.run(ASSESSMENT, ORGANIZATION) is AssessmentState.COMPLETED
    assert recorder.calls["plan"] == 1


# -- retries -----------------------------------------------------------------


def test_a_retryable_failure_is_retried_up_to_the_budget_then_dead_lettered() -> None:
    attempts = {"count": 0}

    def always_fails(context: StepContext) -> StepOutcome:
        attempts["count"] += 1
        return StepOutcome.retry("provider_timeout")

    clock = Clock()
    engine, repository, _, _ = build(overrides={"collect.dns": always_fails}, clock=clock)
    for _ in range(10):
        engine.run(ASSESSMENT, ORGANIZATION)
        clock.advance(600)

    step = repository.load_steps(ASSESSMENT)["collect.dns"]
    assert step.state is StepState.DEAD_LETTERED
    assert attempts["count"] == DEFAULT_GRAPH.by_name("collect.dns").max_attempts


def test_a_permanent_failure_is_not_retried() -> None:
    attempts = {"count": 0}

    def permanently_fails(context: StepContext) -> StepOutcome:
        attempts["count"] += 1
        return StepOutcome.fail("domain_not_in_registry")

    clock = Clock()
    engine, repository, _, _ = build(overrides={"collect.rdap": permanently_fails}, clock=clock)
    for _ in range(5):
        engine.run(ASSESSMENT, ORGANIZATION)
        clock.advance(600)

    assert attempts["count"] == 1
    assert repository.load_steps(ASSESSMENT)["collect.rdap"].state is StepState.FAILED


def test_a_raised_exception_is_contained_and_treated_as_retryable() -> None:
    def explodes(context: StepContext) -> StepOutcome:
        raise RuntimeError("unexpected")

    clock = Clock()
    engine, repository, _, _ = build(overrides={"collect.tls": explodes}, clock=clock)
    for _ in range(6):
        engine.run(ASSESSMENT, ORGANIZATION)
        clock.advance(600)

    step = repository.load_steps(ASSESSMENT)["collect.tls"]
    assert step.state is StepState.DEAD_LETTERED
    assert step.last_error == "RuntimeError"


def test_backoff_grows_and_stays_bounded() -> None:
    delays = [backoff_seconds(attempt, jitter=lambda: 1.0) for attempt in range(1, 12)]
    assert delays == sorted(delays)
    assert max(delays) <= 300.0


def test_backoff_applies_full_jitter() -> None:
    assert backoff_seconds(4, jitter=lambda: 0.0) == 0.0
    assert backoff_seconds(4, jitter=lambda: 1.0) == 16.0


def test_backoff_refuses_a_nonsense_attempt_number() -> None:
    with pytest.raises(WorkflowError, match="attempt_must_be_positive"):
        backoff_seconds(0, jitter=lambda: 1.0)


def test_a_step_waiting_for_its_backoff_window_is_not_run_early() -> None:
    calls = {"count": 0}

    def fails_once(context: StepContext) -> StepOutcome:
        calls["count"] += 1
        return StepOutcome.retry("transient") if calls["count"] == 1 else StepOutcome.ok()

    clock = Clock()
    engine, _, _, _ = build(overrides={"collect.dns": fails_once}, clock=clock)
    engine.run(ASSESSMENT, ORGANIZATION)
    assert calls["count"] == 1

    engine.run(ASSESSMENT, ORGANIZATION)  # still inside the backoff window
    assert calls["count"] == 1

    clock.advance(600)
    engine.run(ASSESSMENT, ORGANIZATION)
    assert calls["count"] == 2


# -- partial completion ------------------------------------------------------


def test_a_failed_optional_collector_yields_a_partially_completed_run() -> None:
    clock = Clock()
    engine, repository, _, _ = build(
        overrides={"collect.ct": lambda context: StepOutcome.fail("ct_source_unavailable")},
        clock=clock,
    )
    for _ in range(4):
        outcome = engine.run(ASSESSMENT, ORGANIZATION)
        clock.advance(600)

    assert outcome is AssessmentState.PARTIALLY_COMPLETED
    assert repository.load_steps(ASSESSMENT)["score"].state is StepState.SUCCEEDED


def test_a_failed_required_step_fails_the_run_and_skips_its_dependants() -> None:
    clock = Clock()
    engine, repository, _, _ = build(
        overrides={"normalize": lambda context: StepOutcome.fail("normalizer_defect")},
        clock=clock,
    )
    for _ in range(4):
        outcome = engine.run(ASSESSMENT, ORGANIZATION)
        clock.advance(600)

    assert outcome is AssessmentState.FAILED
    steps = repository.load_steps(ASSESSMENT)
    assert steps["evaluate"].state is StepState.SKIPPED
    assert steps["report"].state is StepState.SKIPPED


def test_evidence_already_collected_survives_a_later_failure() -> None:
    clock = Clock()
    engine, repository, _, _ = build(
        overrides={"score": lambda context: StepOutcome.fail("scoring_defect")}, clock=clock
    )
    for _ in range(4):
        engine.run(ASSESSMENT, ORGANIZATION)
        clock.advance(600)

    steps = repository.load_steps(ASSESSMENT)
    for name in DEFAULT_GRAPH.names:
        if name.startswith("collect."):
            assert steps[name].state is StepState.SUCCEEDED


# -- cancellation ------------------------------------------------------------


def test_cancellation_between_steps_stops_the_run() -> None:
    clock = Clock()
    repository = InMemoryWorkflowRepository(clock=clock)
    recorder = Recorder()

    def cancel_after_plan(context: StepContext) -> StepOutcome:
        recorder.calls["plan"] = recorder.calls.get("plan", 0) + 1
        repository.request_cancellation(context.assessment_id)
        return StepOutcome.ok()

    engine, _, _, _ = build(
        repository=repository, recorder=recorder, overrides={"plan": cancel_after_plan}, clock=clock
    )
    assert engine.run(ASSESSMENT, ORGANIZATION) is AssessmentState.CANCELLED
    assert "collect.dns" not in recorder.calls


def test_a_long_running_step_observes_cooperative_cancellation() -> None:
    clock = Clock()
    repository = InMemoryWorkflowRepository(clock=clock)

    def cancels_itself(context: StepContext) -> StepOutcome:
        repository.request_cancellation(context.assessment_id)
        context.check_cancelled()  # raises StepCancelled
        return StepOutcome.ok()

    engine, _, _, _ = build(repository=repository, overrides={"plan": cancels_itself}, clock=clock)
    assert engine.run(ASSESSMENT, ORGANIZATION) is AssessmentState.CANCELLED
    assert repository.load_steps(ASSESSMENT)["plan"].state is StepState.CANCELLED


def test_cancellation_preserves_steps_that_already_succeeded() -> None:
    clock = Clock()
    repository = InMemoryWorkflowRepository(clock=clock)

    def cancel_after_plan(context: StepContext) -> StepOutcome:
        repository.request_cancellation(context.assessment_id)
        return StepOutcome.ok()

    engine, _, _, _ = build(
        repository=repository, overrides={"plan": cancel_after_plan}, clock=clock
    )
    engine.run(ASSESSMENT, ORGANIZATION)
    steps = repository.load_steps(ASSESSMENT)
    assert steps["plan"].state is StepState.SUCCEEDED
    assert steps["collect.dns"].state is StepState.CANCELLED


# -- operator replay ---------------------------------------------------------


def test_a_dead_lettered_step_can_be_replayed_by_an_operator() -> None:
    calls = {"count": 0}

    def fails_until_replayed(context: StepContext) -> StepOutcome:
        calls["count"] += 1
        return StepOutcome.retry("provider_down") if calls["count"] <= 3 else StepOutcome.ok()

    clock = Clock()
    engine, repository, _, _ = build(overrides={"collect.dns": fails_until_replayed}, clock=clock)
    for _ in range(6):
        engine.run(ASSESSMENT, ORGANIZATION)
        clock.advance(600)
    assert repository.load_steps(ASSESSMENT)["collect.dns"].state is StepState.DEAD_LETTERED

    engine.replay(ASSESSMENT, "collect.dns")
    engine.run(ASSESSMENT, ORGANIZATION)
    assert repository.load_steps(ASSESSMENT)["collect.dns"].state is StepState.SUCCEEDED


def test_a_successful_step_cannot_be_replayed() -> None:
    engine, _, _, _ = build()
    engine.run(ASSESSMENT, ORGANIZATION)
    with pytest.raises(WorkflowError, match="only_failed_steps_may_be_replayed"):
        engine.replay(ASSESSMENT, "plan")


def test_replaying_an_unknown_step_is_refused() -> None:
    engine, _, _, _ = build()
    with pytest.raises(WorkflowError, match="unknown_step"):
        engine.replay(ASSESSMENT, "collect.nonexistent")


# -- construction ------------------------------------------------------------


def test_an_engine_without_a_handler_for_every_step_is_refused() -> None:
    repository = InMemoryWorkflowRepository()
    with pytest.raises(WorkflowError, match="handler_missing_for_step"):
        WorkflowEngine(repository, {"plan": lambda context: StepOutcome.ok()})
