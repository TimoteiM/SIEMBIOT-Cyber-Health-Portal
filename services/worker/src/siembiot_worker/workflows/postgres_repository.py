"""The authoritative workflow repository.

Implements the same protocol the in-memory version does, so the engine and its tests
are unchanged. What differs is where the concurrency guarantees come from: here they
are database constraints rather than a lock in one process, which is what makes them
hold across workers.

Two operations must be atomic under concurrency and are written as single statements:

``acquire_lease``
    A conditional ``UPDATE`` that only matches when no other worker holds a live lease.
    Whoever's statement lands first wins; the loser sees zero rows and backs off.

``record_completed_key``
    An ``INSERT ... ON CONFLICT DO NOTHING``. The primary key is the deduplication
    guarantee, so a redelivered message cannot record the same completion twice.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, text

from siembiot_worker.workflows.engine import StepRecord
from siembiot_worker.workflows.graph import StepState
from siembiot_worker.workflows.lifecycle import AssessmentState, assert_transition


class PostgresWorkflowRepository:
    def __init__(self, connection: Connection, organization_id: UUID) -> None:
        self._connection = connection
        self._organization_id = organization_id

    # -- assessment state ----------------------------------------------------

    def load_state(self, assessment_id: UUID) -> AssessmentState:
        row = self._connection.execute(
            text("SELECT state FROM assessments WHERE id = :id"),
            {"id": assessment_id},
        ).scalar_one()
        return AssessmentState(row)

    def set_state(self, assessment_id: UUID, state: AssessmentState) -> None:
        current = self.load_state(assessment_id)
        if current is state:
            return
        # Validated in the application as well as the database so an illegal move fails
        # with a named reason rather than a constraint violation.
        assert_transition(current, state)
        completed = state in {AssessmentState.COMPLETED, AssessmentState.PARTIALLY_COMPLETED}
        self._connection.execute(
            text(
                """
                UPDATE assessments
                SET state = :state,
                    completed_at = CASE WHEN :completed THEN now() ELSE NULL END
                WHERE id = :id
                """
            ),
            {"state": str(state), "completed": completed, "id": assessment_id},
        )

    # -- steps ---------------------------------------------------------------

    def load_steps(self, assessment_id: UUID) -> dict[str, StepRecord]:
        rows = self._connection.execute(
            text(
                """
                SELECT name, state, attempts, idempotency_key, lease_owner,
                       lease_expires_at, last_error, next_attempt_at, result
                FROM assessment_steps
                WHERE assessment_id = :assessment_id
                """
            ),
            {"assessment_id": assessment_id},
        ).mappings()
        return {
            row["name"]: StepRecord(
                assessment_id=assessment_id,
                name=row["name"],
                state=StepState(row["state"]),
                attempts=row["attempts"],
                idempotency_key=row["idempotency_key"],
                lease_owner=row["lease_owner"],
                lease_expires_at=row["lease_expires_at"],
                last_error=row["last_error"],
                next_attempt_at=row["next_attempt_at"],
                result=dict(row["result"] or {}),
            )
            for row in rows
        }

    def upsert_step(self, record: StepRecord) -> None:
        self._connection.execute(
            text(
                """
                INSERT INTO assessment_steps (
                    organization_id, assessment_id, name, state, attempts,
                    idempotency_key, lease_owner, lease_expires_at, last_error,
                    next_attempt_at, result
                ) VALUES (
                    :organization_id, :assessment_id, :name, :state, :attempts,
                    :idempotency_key, :lease_owner, :lease_expires_at, :last_error,
                    :next_attempt_at, CAST(:result AS jsonb)
                )
                ON CONFLICT (assessment_id, name) DO UPDATE SET
                    state = excluded.state,
                    attempts = excluded.attempts,
                    idempotency_key = excluded.idempotency_key,
                    lease_owner = excluded.lease_owner,
                    lease_expires_at = excluded.lease_expires_at,
                    last_error = excluded.last_error,
                    next_attempt_at = excluded.next_attempt_at,
                    result = excluded.result
                """
            ),
            {
                "organization_id": self._organization_id,
                "assessment_id": record.assessment_id,
                "name": record.name,
                "state": str(record.state),
                "attempts": record.attempts,
                "idempotency_key": record.idempotency_key,
                "lease_owner": record.lease_owner,
                "lease_expires_at": record.lease_expires_at,
                "last_error": record.last_error,
                "next_attempt_at": record.next_attempt_at,
                "result": json.dumps(record.result),
            },
        )

    def record_attempt(
        self,
        assessment_id: UUID,
        step_name: str,
        attempt: int,
        outcome: str,
        *,
        error: str | None = None,
        worker_id: UUID | None = None,
    ) -> None:
        """Append one attempt. Duplicates are ignored so a replay cannot corrupt history."""
        self._connection.execute(
            text(
                """
                INSERT INTO assessment_step_attempts (
                    organization_id, assessment_id, step_name, attempt, outcome,
                    error, worker_id, finished_at
                ) VALUES (
                    :organization_id, :assessment_id, :step_name, :attempt, :outcome,
                    :error, :worker_id, now()
                )
                ON CONFLICT (assessment_id, step_name, attempt) DO NOTHING
                """
            ),
            {
                "organization_id": self._organization_id,
                "assessment_id": assessment_id,
                "step_name": step_name,
                "attempt": attempt,
                "outcome": outcome,
                "error": error,
                "worker_id": worker_id,
            },
        )

    # -- leases --------------------------------------------------------------

    def acquire_lease(
        self, assessment_id: UUID, step_name: str, owner: UUID, expires_at: datetime
    ) -> bool:
        """Take the lease only when nobody else holds a live one.

        Written as one conditional statement so two workers racing here cannot both
        succeed: the database serializes them and the loser matches zero rows.
        """
        inserted = self._connection.execute(
            text(
                """
                INSERT INTO assessment_steps (
                    organization_id, assessment_id, name, state, lease_owner, lease_expires_at
                ) VALUES (
                    :organization_id, :assessment_id, :name, 'pending', :owner, :expires_at
                )
                ON CONFLICT (assessment_id, name) DO UPDATE
                SET lease_owner = excluded.lease_owner,
                    lease_expires_at = excluded.lease_expires_at
                WHERE assessment_steps.lease_owner IS NULL
                   OR assessment_steps.lease_owner = excluded.lease_owner
                   OR assessment_steps.lease_expires_at <= now()
                RETURNING id
                """
            ),
            {
                "organization_id": self._organization_id,
                "assessment_id": assessment_id,
                "name": step_name,
                "owner": owner,
                "expires_at": expires_at,
            },
        ).scalar_one_or_none()
        return inserted is not None

    def release_lease(self, assessment_id: UUID, step_name: str, owner: UUID) -> None:
        self._connection.execute(
            text(
                """
                UPDATE assessment_steps
                SET lease_owner = NULL, lease_expires_at = NULL
                WHERE assessment_id = :assessment_id
                  AND name = :name
                  AND lease_owner = :owner
                """
            ),
            {"assessment_id": assessment_id, "name": step_name, "owner": owner},
        )

    # -- cancellation --------------------------------------------------------

    def request_cancellation(self, assessment_id: UUID, reason: str) -> None:
        self._connection.execute(
            text(
                """
                UPDATE assessments
                SET cancellation_requested_at = COALESCE(cancellation_requested_at, now()),
                    cancellation_reason = COALESCE(cancellation_reason, :reason)
                WHERE id = :id
                """
            ),
            {"id": assessment_id, "reason": reason},
        )

    def is_cancellation_requested(self, assessment_id: UUID) -> bool:
        return (
            self._connection.execute(
                text(
                    "SELECT cancellation_requested_at IS NOT NULL FROM assessments WHERE id = :id"
                ),
                {"id": assessment_id},
            ).scalar_one()
            is True
        )

    # -- idempotency ---------------------------------------------------------

    def has_completed_key(self, key: str) -> bool:
        return (
            self._connection.execute(
                text("SELECT 1 FROM workflow_idempotency_keys WHERE key = :key"),
                {"key": key},
            ).scalar_one_or_none()
            is not None
        )

    def record_completed_key(self, key: str, assessment_id: UUID, step_name: str) -> bool:
        """Record completion. The primary key makes a second record impossible."""
        inserted = self._connection.execute(
            text(
                """
                INSERT INTO workflow_idempotency_keys (
                    key, organization_id, assessment_id, step_name
                ) VALUES (:key, :organization_id, :assessment_id, :step_name)
                ON CONFLICT (key) DO NOTHING
                RETURNING key
                """
            ),
            {
                "key": key,
                "organization_id": self._organization_id,
                "assessment_id": assessment_id,
                "step_name": step_name,
            },
        ).scalar_one_or_none()
        return inserted is not None

    # -- reporting -----------------------------------------------------------

    def attempts_for(self, assessment_id: UUID) -> tuple[dict[str, Any], ...]:
        rows = self._connection.execute(
            text(
                """
                SELECT step_name, attempt, outcome, error
                FROM assessment_step_attempts
                WHERE assessment_id = :assessment_id
                ORDER BY step_name, attempt
                """
            ),
            {"assessment_id": assessment_id},
        ).mappings()
        return tuple(dict(row) for row in rows)
