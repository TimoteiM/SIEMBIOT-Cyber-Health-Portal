"""Reading and setting a domain's assessment cadence.

Writing a schedule is authorized with `ASSESSMENT_RUN`, not with a read permission:
setting a cadence decides what the platform will do to somebody's domain repeatedly and
unattended, which is the same decision as pressing the button, made once for every
future occasion.

The next firing time is computed here rather than accepted from the client. A caller
that could name its own `next_run_at` could ask to be assessed every second, and the
cadence would become a label on a number somebody else chose.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy import Connection, text
from sqlalchemy.engine import RowMapping

from siembiot.audit import append_audit_event
from siembiot.auth import current_principal, require_trusted_origin
from siembiot.authorization import Action
from siembiot.contracts import (
    ASSESSMENT_MODES,
    SCHEDULE_CADENCES,
    ScheduleResponse,
    ScheduleUpdate,
)
from siembiot.db import Database
from siembiot.errors import AppError
from siembiot.identity import Principal
from siembiot.organizations import authorize

#: Mirrors siembiot_worker.scheduling.CADENCE_INTERVALS. Duplicated because the API does
#: not import the worker package; the database's check constraint is what keeps the two
#: sets of names honest, and a cadence in one but not the other fails a test.
CADENCE_INTERVALS: dict[str, timedelta] = {
    "daily": timedelta(days=1),
    "weekly": timedelta(days=7),
    "monthly": timedelta(days=30),
    "quarterly": timedelta(days=91),
}
CADENCE_OFF: SCHEDULE_CADENCES = "off"

AUTHORIZED_ASSESSMENT = "authorized_assessment"


def _database(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def _first_run_for(cadence: str, now: datetime) -> datetime | None:
    """When a newly set cadence should first fire.

    Immediately, rather than one interval away. Somebody who has just asked for weekly
    monitoring wants to know where they stand now, not in seven days; and a first run
    today is what makes the setting visibly take effect.
    """
    if cadence == CADENCE_OFF:
        return None
    if cadence not in CADENCE_INTERVALS:
        raise AppError(422, "validation_error", "The request is invalid.")
    return now


def _response(row: RowMapping) -> ScheduleResponse:
    return ScheduleResponse(
        domain_id=row["domain_id"],
        # The database constrains both columns to the same literals the contract
        # names, so the cast asserts a guarantee rather than papering over one.
        cadence=cast(SCHEDULE_CADENCES, row["cadence"]),
        mode=cast(ASSESSMENT_MODES, row["mode"]),
        quiet_hours_start=row["quiet_hours_start"],
        quiet_hours_end=row["quiet_hours_end"],
        timezone=str(row["timezone"]),
        next_run_at=row["next_run_at"],
        last_run_at=row["last_run_at"],
    )


def _unscheduled(domain_id: UUID) -> ScheduleResponse:
    """What a domain with no schedule row looks like.

    A 404 would be wrong: the domain exists and its cadence is a real answer, namely
    'off'. Reporting absence as an error would make every client handle two shapes for
    the same fact.
    """
    return ScheduleResponse(
        domain_id=domain_id,
        cadence=CADENCE_OFF,
        mode="passive_observation",
        timezone="Europe/Bucharest",
    )


def build_schedule_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/organizations", tags=["schedules"])

    def _load_domain(connection: Connection, organization_id: UUID, domain_id: UUID) -> RowMapping:
        row = (
            connection.execute(
                text(
                    "SELECT id, ownership_state FROM domains "
                    "WHERE id = :domain_id AND organization_id = :organization_id"
                ),
                {"domain_id": domain_id, "organization_id": organization_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise AppError(404, "not_found", "The requested resource was not found.")
        return row

    @router.get("/{organization_id}/domains/{domain_id}/schedule", response_model=ScheduleResponse)
    def read(
        organization_id: UUID,
        domain_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> ScheduleResponse:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.ASSESSMENT_READ)
            _load_domain(connection, organization_id, domain_id)

            row = (
                connection.execute(
                    text(
                        "SELECT domain_id, cadence, mode, quiet_hours_start, quiet_hours_end, "
                        "timezone, next_run_at, last_run_at FROM assessment_schedules "
                        "WHERE domain_id = :domain_id"
                    ),
                    {"domain_id": domain_id},
                )
                .mappings()
                .one_or_none()
            )
        return _response(row) if row is not None else _unscheduled(domain_id)

    @router.put("/{organization_id}/domains/{domain_id}/schedule", response_model=ScheduleResponse)
    def update(
        organization_id: UUID,
        domain_id: UUID,
        payload: ScheduleUpdate,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> ScheduleResponse:
        if (payload.quiet_hours_start is None) != (payload.quiet_hours_end is None):
            raise AppError(
                422,
                "validation_error",
                "Quiet hours need both a start and an end, or neither.",
            )

        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.ASSESSMENT_RUN)
            domain = _load_domain(connection, organization_id, domain_id)

            # The same rule the one-off endpoint applies, for the same reason. Setting
            # an unattended authorized cadence on an unverified domain would postpone
            # the ownership question to a moment nobody is present for.
            if payload.mode == AUTHORIZED_ASSESSMENT and domain["ownership_state"] != "verified":
                raise AppError(
                    409,
                    "ownership_not_verified",
                    "An authorized assessment requires verified control of the domain. "
                    "Passive observation of published data needs no proof of control.",
                )

            next_run_at = _first_run_for(payload.cadence, datetime.now(UTC))
            row = (
                connection.execute(
                    text(
                        """
                        INSERT INTO assessment_schedules (
                            organization_id, domain_id, cadence, mode, quiet_hours_start,
                            quiet_hours_end, timezone, next_run_at, created_by_user_id
                        ) VALUES (
                            :organization_id, :domain_id, :cadence, :mode, :quiet_start,
                            :quiet_end, :timezone, :next_run_at, :user_id
                        )
                        ON CONFLICT (domain_id) DO UPDATE SET
                            cadence = excluded.cadence,
                            mode = excluded.mode,
                            quiet_hours_start = excluded.quiet_hours_start,
                            quiet_hours_end = excluded.quiet_hours_end,
                            timezone = excluded.timezone,
                            -- An existing schedule keeps its place in the queue when
                            -- only the quiet hours change; re-setting the same cadence
                            -- should not silently postpone the next run.
                            next_run_at = CASE
                                WHEN excluded.cadence = 'off' THEN NULL
                                WHEN assessment_schedules.cadence = excluded.cadence
                                     AND assessment_schedules.next_run_at IS NOT NULL
                                    THEN assessment_schedules.next_run_at
                                ELSE excluded.next_run_at
                            END,
                            updated_at = now()
                        RETURNING domain_id, cadence, mode, quiet_hours_start,
                                  quiet_hours_end, timezone, next_run_at, last_run_at
                        """
                    ),
                    {
                        "organization_id": organization_id,
                        "domain_id": domain_id,
                        "cadence": payload.cadence,
                        "mode": payload.mode,
                        "quiet_start": payload.quiet_hours_start,
                        "quiet_end": payload.quiet_hours_end,
                        "timezone": payload.timezone,
                        "next_run_at": next_run_at,
                        "user_id": principal.user_id,
                    },
                )
                .mappings()
                .one()
            )

            append_audit_event(
                connection,
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(principal.user_id),
                action="assessment.schedule_changed",
                resource_type="domain",
                resource_id=str(domain_id),
                request_id=cast(str, request.state.request_id),
                correlation_id=request.state.correlation_id,
                outcome="success",
                # Recorded because a cadence decides what the platform does repeatedly
                # and unattended: an auditor asking "why was this domain contacted on a
                # Sunday" needs the setting and who made it, not only the runs.
                context={"cadence": payload.cadence, "mode": payload.mode},
            )
        return _response(row)

    return router
