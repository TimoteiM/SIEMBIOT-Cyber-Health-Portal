"""An in-memory workflow repository.

Used by the tests to exercise the engine's ordering, retry and cancellation logic
without a database. It reproduces the concurrency-relevant semantics — conditional
lease acquisition and single-use idempotency keys — because those are exactly what
the tests need to be able to break.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

from siembiot_worker.workflows.engine import StepRecord
from siembiot_worker.workflows.graph import StepState
from siembiot_worker.workflows.lifecycle import AssessmentState, assert_transition


class InMemoryWorkflowRepository:
    def __init__(
        self,
        initial: AssessmentState = AssessmentState.QUEUED,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._states: dict[UUID, AssessmentState] = {}
        self._steps: dict[tuple[UUID, str], StepRecord] = {}
        self._keys: dict[str, tuple[UUID, str]] = {}
        self._cancelled: set[UUID] = set()
        self._initial = initial
        self._clock = clock
        self._lock = threading.Lock()
        self.transitions: list[tuple[UUID, AssessmentState]] = []

    # -- assessment state ----------------------------------------------------

    def load_state(self, assessment_id: UUID) -> AssessmentState:
        return self._states.setdefault(assessment_id, self._initial)

    def set_state(self, assessment_id: UUID, state: AssessmentState) -> None:
        current = self.load_state(assessment_id)
        if current is state:
            return
        assert_transition(current, state)
        self._states[assessment_id] = state
        self.transitions.append((assessment_id, state))

    # -- steps ---------------------------------------------------------------

    def load_steps(self, assessment_id: UUID) -> dict[str, StepRecord]:
        return {name: record for (run, name), record in self._steps.items() if run == assessment_id}

    def upsert_step(self, record: StepRecord) -> None:
        with self._lock:
            self._steps[(record.assessment_id, record.name)] = record

    # -- leases --------------------------------------------------------------

    def acquire_lease(
        self, assessment_id: UUID, step_name: str, owner: UUID, expires_at: datetime
    ) -> bool:
        """Conditional: a live lease held by another worker blocks acquisition."""
        with self._lock:
            record = self._steps.get((assessment_id, step_name))
            if record is None:
                record = StepRecord(assessment_id, step_name, StepState.PENDING)
            if record.lease_is_live(self._clock()) and record.lease_owner != owner:
                return False
            self._steps[(assessment_id, step_name)] = replace(
                record, lease_owner=owner, lease_expires_at=expires_at
            )
            return True

    def release_lease(self, assessment_id: UUID, step_name: str, owner: UUID) -> None:
        with self._lock:
            record = self._steps.get((assessment_id, step_name))
            if record is None or record.lease_owner != owner:
                return
            self._steps[(assessment_id, step_name)] = replace(
                record, lease_owner=None, lease_expires_at=None
            )

    # -- cancellation --------------------------------------------------------

    def request_cancellation(self, assessment_id: UUID) -> None:
        self._cancelled.add(assessment_id)

    def is_cancellation_requested(self, assessment_id: UUID) -> bool:
        return assessment_id in self._cancelled

    # -- idempotency ---------------------------------------------------------

    def has_completed_key(self, key: str) -> bool:
        """Whether this exact work has already completed successfully."""
        with self._lock:
            return key in self._keys

    def record_completed_key(self, key: str, assessment_id: UUID, step_name: str) -> bool:
        """Record completion. False when the key was already present."""
        with self._lock:
            if key in self._keys:
                return False
            self._keys[key] = (assessment_id, step_name)
            return True

    @property
    def recorded_keys(self) -> dict[str, tuple[UUID, str]]:
        return dict(self._keys)
