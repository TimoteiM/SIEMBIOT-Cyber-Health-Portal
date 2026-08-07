"""The durable workflow engine.

PostgreSQL holds the authoritative state; the queue only ever delivers a nudge. That
inversion is what makes duplicate and out-of-order delivery harmless: a redelivered
message finds the step already settled and does nothing.

Three mechanisms carry that guarantee:

*Idempotency keys* are derived from the run, the step and the input digest, so the
same work always produces the same key and a second attempt is recognised as a repeat.

*Leases* stop two workers running one step at once. A lease expires, so a worker that
dies does not strand the step forever.

*Cooperative cancellation* is checked between steps and offered to long-running steps,
so a revoked authorization stops work rather than merely marking it stopped.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import UUID, uuid4, uuid5

from siembiot_worker.policy.evidence import canonical_bytes
from siembiot_worker.workflows.graph import (
    DEFAULT_GRAPH,
    Progress,
    StepDefinition,
    StepGraph,
    StepState,
)
from siembiot_worker.workflows.lifecycle import AssessmentState, forward_path

IDEMPOTENCY_NAMESPACE = UUID("3d2b0f1a-6c4e-4c7a-9f2b-8d1e5a7c3b90")
DEFAULT_LEASE_SECONDS = 300.0
MAX_BACKOFF_SECONDS = 300.0


class WorkflowError(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class StepCancelled(Exception):  # noqa: N818 - control flow, not an error condition
    """Raised inside a step when cancellation is observed. Never an error state."""


def idempotency_key(assessment_id: UUID, step_name: str, payload: Mapping[str, Any]) -> str:
    """Deterministic: identical work always yields the same key.

    Includes the input digest so a replay with changed inputs is correctly treated as
    new work rather than silently deduplicated against the old result.
    """
    digest = hashlib.sha256(canonical_bytes(dict(payload))).hexdigest()
    return str(uuid5(IDEMPOTENCY_NAMESPACE, f"{assessment_id}:{step_name}:{digest}"))


def backoff_seconds(attempt: int, *, base: float = 2.0, jitter: Callable[[], float]) -> float:
    """Exponential backoff with full jitter, bounded.

    Jitter is injected rather than drawn from the global RNG so the tests are
    deterministic without weakening the production behaviour.
    """
    if attempt < 1:
        raise WorkflowError("attempt_must_be_positive")
    ceiling = min(MAX_BACKOFF_SECONDS, base ** min(attempt, 16))
    return round(ceiling * jitter(), 3)


@dataclass(frozen=True)
class StepRecord:
    assessment_id: UUID
    name: str
    state: StepState
    attempts: int = 0
    idempotency_key: str | None = None
    lease_owner: UUID | None = None
    lease_expires_at: datetime | None = None
    last_error: str | None = None
    next_attempt_at: datetime | None = None
    result: dict[str, Any] = field(default_factory=dict)

    def lease_is_live(self, now: datetime) -> bool:
        return self.lease_expires_at is not None and self.lease_expires_at > now


@dataclass(frozen=True)
class StepOutcome:
    """What a step handler reports back. Retryable failures are distinguished."""

    succeeded: bool
    result: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    retryable: bool = True
    #: Settled without having done anything, and without anything being wrong.
    skipped: bool = False

    @classmethod
    def ok(cls, **result: Any) -> StepOutcome:
        return cls(True, dict(result))

    @classmethod
    def retry(cls, error: str) -> StepOutcome:
        return cls(False, error=error, retryable=True)

    @classmethod
    def fail(cls, error: str) -> StepOutcome:
        """A permanent failure. Retrying it would only waste provider budget."""
        return cls(False, error=error, retryable=False)

    @classmethod
    def skip(cls, reason: str) -> StepOutcome:
        """Settled, and nothing went wrong: this step had nothing to do.

        Distinct from `fail` on purpose. A step that does not apply -- a domain with no
        certificate transparency history, a check whose precondition is absent -- has
        produced a real answer. Recording it as a failure would report a run that
        worked as `partially_completed`, telling the reader something was wrong when
        nothing was, and blurring the line between proven absence and inconclusive
        evidence that the whole methodology rests on.
        """
        return cls(False, error=reason, retryable=False, skipped=True)


class WorkflowRepository(Protocol):
    """Authoritative durable state. Every method must be safe under concurrency."""

    def load_state(self, assessment_id: UUID) -> AssessmentState: ...

    def set_state(self, assessment_id: UUID, state: AssessmentState) -> None: ...

    def load_steps(self, assessment_id: UUID) -> dict[str, StepRecord]: ...

    def upsert_step(self, record: StepRecord) -> None: ...

    def acquire_lease(
        self, assessment_id: UUID, step_name: str, owner: UUID, expires_at: datetime
    ) -> bool: ...

    def release_lease(self, assessment_id: UUID, step_name: str, owner: UUID) -> None: ...

    def is_cancellation_requested(self, assessment_id: UUID) -> bool: ...

    def has_completed_key(self, key: str) -> bool: ...

    def record_completed_key(self, key: str, assessment_id: UUID, step_name: str) -> bool: ...


StepHandler = Callable[["StepContext"], StepOutcome]


@dataclass
class StepContext:
    """What a handler is given. ``check_cancelled`` is how long steps stay stoppable."""

    assessment_id: UUID
    organization_id: UUID
    step: StepDefinition
    attempt: int
    payload: dict[str, Any]
    deadline: datetime
    _repository: WorkflowRepository

    def check_cancelled(self) -> None:
        if self._repository.is_cancellation_requested(self.assessment_id):
            raise StepCancelled()

    def succeeded_steps(self) -> frozenset[str]:
        """Steps this run has already completed, including in earlier executions.

        A handler needs this to tell "never ran" from "ran in a process that has since
        gone away". The two look identical from inside one execution, and treating the
        second as the first is how a resumed run silently loses evidence.
        """
        return frozenset(
            name
            for name, record in self._repository.load_steps(self.assessment_id).items()
            if record.state is StepState.SUCCEEDED
        )

    def expired(self, now: datetime) -> bool:
        return now >= self.deadline


class WorkflowEngine:
    def __init__(
        self,
        repository: WorkflowRepository,
        handlers: Mapping[str, StepHandler],
        *,
        graph: StepGraph = DEFAULT_GRAPH,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        jitter: Callable[[], float] = random.random,  # noqa: S311 - backoff, not crypto
        lease_seconds: float = DEFAULT_LEASE_SECONDS,
        worker_id: UUID | None = None,
    ) -> None:
        missing = set(graph.names) - set(handlers)
        if missing:
            raise WorkflowError("handler_missing_for_step")
        self._repository = repository
        self._handlers = handlers
        self._graph = graph
        self._clock = clock
        self._jitter = jitter
        self._lease_seconds = lease_seconds
        self._worker_id = worker_id or uuid4()

    @property
    def graph(self) -> StepGraph:
        return self._graph

    def progress(self, assessment_id: UUID) -> Progress:
        return self._graph.progress(self._step_states(assessment_id))

    def _step_states(self, assessment_id: UUID) -> dict[str, StepState]:
        records = self._repository.load_steps(assessment_id)
        return {name: record.state for name, record in records.items()}

    def run(
        self, assessment_id: UUID, organization_id: UUID, payload: Mapping[str, Any] | None = None
    ) -> AssessmentState:
        """Drive the assessment until it settles or has nothing runnable left."""
        shared = dict(payload or {})
        while True:
            if self._repository.is_cancellation_requested(assessment_id):
                return self._cancel(assessment_id)

            states = self._step_states(assessment_id)

            # Record unreachable steps before deciding the outcome, so an operator can
            # see *why* a step never ran rather than finding no record of it at all.
            blocked = self._graph.blocked(states)
            if blocked:
                for step in blocked:
                    self._settle(
                        assessment_id, step, StepState.SKIPPED, error="dependency_unavailable"
                    )
                continue

            outcome = self._graph.outcome(states)
            if outcome is not None:
                self._settle_run(assessment_id, outcome)
                return outcome

            ready = self._graph.ready(states)
            if not ready:
                return self._repository.load_state(assessment_id)

            # A step can be ready yet unrunnable right now: it may be waiting out a
            # backoff window or leased by another worker. When nothing in the ready set
            # moves, the run is waiting rather than finished, so return and let the next
            # delivery pick it up instead of spinning.
            progressed = False
            for step in ready:
                progressed |= self._execute(assessment_id, organization_id, step, shared)
            if not progressed:
                return self._repository.load_state(assessment_id)

    def _execute(
        self,
        assessment_id: UUID,
        organization_id: UUID,
        step: StepDefinition,
        payload: dict[str, Any],
    ) -> bool:
        """Run one step if it can run now. Returns whether the step's state moved."""
        now = self._clock()
        records = self._repository.load_steps(assessment_id)
        record = records.get(step.name) or StepRecord(assessment_id, step.name, StepState.PENDING)

        if record.next_attempt_at is not None and record.next_attempt_at > now:
            return False
        if record.lease_is_live(now) and record.lease_owner != self._worker_id:
            return False

        key = idempotency_key(assessment_id, step.name, payload)
        expires_at = now + timedelta(seconds=self._lease_seconds)
        if not self._repository.acquire_lease(
            assessment_id, step.name, self._worker_id, expires_at
        ):
            return False

        try:
            self._advance_to(assessment_id, step.phase)

            # The key records *completed* work, so it is checked before running and
            # written only on success. Recording it up front would let one failed
            # attempt permanently mark the work as done.
            if self._repository.has_completed_key(key):
                self._settle(assessment_id, step, StepState.SUCCEEDED, key=key, deduplicated=True)
                return True

            attempt = record.attempts + 1
            self._repository.upsert_step(
                StepRecord(
                    assessment_id,
                    step.name,
                    StepState.RUNNING,
                    attempts=attempt,
                    idempotency_key=key,
                    lease_owner=self._worker_id,
                    lease_expires_at=expires_at,
                )
            )
            context = StepContext(
                assessment_id=assessment_id,
                organization_id=organization_id,
                step=step,
                attempt=attempt,
                payload=payload,
                deadline=now + timedelta(seconds=step.deadline_seconds),
                _repository=self._repository,
            )
            try:
                outcome = self._handlers[step.name](context)
            except StepCancelled:
                self._settle(assessment_id, step, StepState.CANCELLED, attempts=attempt, key=key)
                return True
            except Exception as error:  # noqa: BLE001 - a handler must never kill the run
                outcome = StepOutcome.retry(type(error).__name__)

            if outcome.succeeded:
                self._repository.record_completed_key(key, assessment_id, step.name)
                self._settle(
                    assessment_id,
                    step,
                    StepState.SUCCEEDED,
                    attempts=attempt,
                    key=key,
                    result=outcome.result,
                )
                payload.update(outcome.result)
                return True

            if outcome.skipped:
                # Settled, so the key is recorded: a redelivery must not run it again
                # in the hope of a different answer.
                self._repository.record_completed_key(key, assessment_id, step.name)
                self._settle(
                    assessment_id,
                    step,
                    StepState.SKIPPED,
                    attempts=attempt,
                    key=key,
                    error=outcome.error,
                )
                return True

            self._handle_failure(assessment_id, step, attempt, key, outcome)
            return True
        finally:
            self._repository.release_lease(assessment_id, step.name, self._worker_id)

    def _settle_run(self, assessment_id: UUID, outcome: AssessmentState) -> None:
        """Move the run to its terminal state along a legal path.

        A reopened run may be several phases behind its outcome, so completion walks
        forward to report generation first rather than jumping there illegally.
        """
        if outcome in {AssessmentState.COMPLETED, AssessmentState.PARTIALLY_COMPLETED}:
            self._advance_to(assessment_id, AssessmentState.REPORT_GENERATION)
        self._repository.set_state(assessment_id, outcome)

    def _advance_to(self, assessment_id: UUID, phase: AssessmentState) -> None:
        """Walk the lifecycle forward to a step's phase, never backwards."""
        current = self._repository.load_state(assessment_id)
        for state in forward_path(current, phase):
            self._repository.set_state(assessment_id, state)

    def _handle_failure(
        self,
        assessment_id: UUID,
        step: StepDefinition,
        attempt: int,
        key: str,
        outcome: StepOutcome,
    ) -> None:
        exhausted = attempt >= step.max_attempts
        if not outcome.retryable or exhausted:
            state = StepState.DEAD_LETTERED if exhausted and outcome.retryable else StepState.FAILED
            self._settle(
                assessment_id, step, state, attempts=attempt, key=None, error=outcome.error
            )
            return
        delay = backoff_seconds(attempt, jitter=self._jitter)
        self._repository.upsert_step(
            StepRecord(
                assessment_id,
                step.name,
                StepState.PENDING,
                attempts=attempt,
                idempotency_key=None,
                last_error=outcome.error,
                next_attempt_at=self._clock() + timedelta(seconds=delay),
            )
        )

    def _settle(
        self,
        assessment_id: UUID,
        step: StepDefinition,
        state: StepState,
        *,
        attempts: int = 0,
        key: str | None = None,
        error: str | None = None,
        result: dict[str, Any] | None = None,
        deduplicated: bool = False,
    ) -> None:
        payload = dict(result or {})
        if deduplicated:
            payload["deduplicated"] = True
        self._repository.upsert_step(
            StepRecord(
                assessment_id,
                step.name,
                state,
                attempts=attempts,
                idempotency_key=key,
                last_error=error,
                result=payload,
            )
        )

    def _cancel(self, assessment_id: UUID) -> AssessmentState:
        """Cancel every step that has not already settled, then the run itself."""
        records = self._repository.load_steps(assessment_id)
        for step in self._graph.steps:
            record = records.get(step.name)
            if record is not None and record.state in {
                StepState.SUCCEEDED,
                StepState.FAILED,
                StepState.DEAD_LETTERED,
                StepState.SKIPPED,
            }:
                continue
            self._settle(assessment_id, step, StepState.CANCELLED)
        self._repository.set_state(assessment_id, AssessmentState.CANCELLED)
        return AssessmentState.CANCELLED

    def replay(self, assessment_id: UUID, step_name: str) -> None:
        """Operator replay: return one dead-lettered step to the queue.

        Only a settled failure may be replayed. Replaying a success would risk a second
        write of the same evidence, which the append-only tables would reject anyway.
        """
        record = self._repository.load_steps(assessment_id).get(step_name)
        if record is None:
            raise WorkflowError("unknown_step")
        if record.state not in {StepState.FAILED, StepState.DEAD_LETTERED}:
            raise WorkflowError("only_failed_steps_may_be_replayed")
        self._repository.upsert_step(
            StepRecord(assessment_id, step_name, StepState.PENDING, attempts=0)
        )
