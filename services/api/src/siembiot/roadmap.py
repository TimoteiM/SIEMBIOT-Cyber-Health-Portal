"""Work planned against findings, and whether the evidence agrees it happened.

The remediation catalog says what to do. This records that somebody intends to do it,
who, and by when -- and then reports that intention next to what the next assessment
actually observed.

**The pairing is the point.** A person marking work complete is an assertion; an
assessment finding the weakness gone is an observation. This product exists because
those two things come apart, so the API never reconciles them into one number. Where
they disagree it says so plainly: either the fix did not work, or it was applied
somewhere the assessment does not reach, and both are worth somebody's attention.

Marking an action complete therefore cannot close a finding. Nothing a user types
changes what was measured; only the next run does.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy import Connection, text
from sqlalchemy.engine import RowMapping

from siembiot.audit import append_audit_event
from siembiot.auth import current_principal, require_trusted_origin
from siembiot.authorization import Action
from siembiot.check_metadata import CheckMetadata, load_check_metadata
from siembiot.contracts import (
    ACTION_STATUSES,
    ACTION_VERIFICATION,
    FINDING_SEVERITIES,
    FINDING_STATES,
    ActionResponse,
    ActionUpsert,
    RoadmapResponse,
)
from siembiot.db import Database
from siembiot.errors import AppError
from siembiot.identity import Principal
from siembiot.organizations import authorize

#: Finding states that mean the weakness is no longer observed. `suppressed` and
#: `accepted_risk` are deliberately absent: somebody deciding not to fix a thing does
#: not make an action to fix it confirmed.
RESOLVED_STATES = frozenset({"resolved"})
COMPLETED = "completed"


def _database(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def _verification(status: str, finding_state: str) -> ACTION_VERIFICATION:
    """How the assertion and the evidence relate."""
    resolved = finding_state in RESOLVED_STATES
    if status == COMPLETED:
        return "confirmed" if resolved else "asserted_not_observed"
    return "resolved_without_action" if resolved else "in_flight"


def _action_response(row: RowMapping, metadata: dict[str, CheckMetadata]) -> ActionResponse:
    check_id = str(row["check_id"])
    entry = metadata.get(check_id)
    status = cast(ACTION_STATUSES, row["status"])
    finding_state = cast(FINDING_STATES, row["finding_state"])
    due_at = row["due_at"]
    return ActionResponse(
        id=row["id"],
        finding_id=row["finding_id"],
        check_id=check_id,
        title_ro=entry.title_ro if entry else check_id,
        title_en=entry.title_en if entry else check_id,
        severity=cast(FINDING_SEVERITIES, row["severity"]),
        status=status,
        owner_user_id=row["owner_user_id"],
        owner_display_name=row["owner_display_name"],
        due_at=due_at,
        note=row["note"],
        completed_at=row["completed_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        finding_state=finding_state,
        verification=_verification(status, finding_state),
        overdue=bool(due_at and status != COMPLETED and due_at < datetime.now(UTC)),
    )


def _load_actions(connection: Connection, domain_id: UUID) -> list[RowMapping]:
    return list(
        connection.execute(
            text(
                """
                SELECT a.id, a.finding_id, a.status, a.owner_user_id, a.due_at, a.note,
                       a.completed_at, a.created_at, a.updated_at,
                       f.check_id, f.severity, f.state AS finding_state,
                       u.display_name AS owner_display_name
                FROM remediation_actions a
                JOIN findings f ON f.id = a.finding_id
                LEFT JOIN users u ON u.id = a.owner_user_id
                WHERE f.authorized_domain_id = :domain_id
                ORDER BY a.due_at NULLS LAST, f.severity, f.check_id
                """
            ),
            {"domain_id": domain_id},
        ).mappings()
    )


def build_roadmap_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/organizations", tags=["roadmap"])

    def _require_domain(connection: Connection, organization_id: UUID, domain_id: UUID) -> None:
        found = connection.execute(
            text(
                "SELECT id FROM domains WHERE id = :domain_id "
                "AND organization_id = :organization_id"
            ),
            {"domain_id": domain_id, "organization_id": organization_id},
        ).scalar_one_or_none()
        if found is None:
            raise AppError(404, "not_found", "The requested resource was not found.")

    @router.get("/{organization_id}/domains/{domain_id}/roadmap", response_model=RoadmapResponse)
    def index(
        organization_id: UUID,
        domain_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> RoadmapResponse:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.ASSESSMENT_READ)
            _require_domain(connection, organization_id, domain_id)

            rows = _load_actions(connection, domain_id)
            # Open findings nobody has planned anything for. The gap between what is
            # known and what anybody intends to do, which is the number a manager
            # actually wants and the one a list of tasks never shows.
            unplanned = connection.execute(
                text(
                    """
                    SELECT count(*) FROM findings f
                    WHERE f.authorized_domain_id = :domain_id
                      AND f.state IN ('open', 'regressed')
                      AND NOT EXISTS (
                          SELECT 1 FROM remediation_actions a WHERE a.finding_id = f.id
                      )
                    """
                ),
                {"domain_id": domain_id},
            ).scalar_one()

        metadata = load_check_metadata()
        actions = [_action_response(row, metadata) for row in rows]
        return RoadmapResponse(
            domain_id=domain_id,
            actions=actions,
            unplanned_count=int(unplanned),
            overdue_count=sum(1 for action in actions if action.overdue),
            contradicted_count=sum(
                1 for action in actions if action.verification == "asserted_not_observed"
            ),
        )

    @router.put("/{organization_id}/findings/{finding_id}/action", response_model=ActionResponse)
    def upsert(
        organization_id: UUID,
        finding_id: UUID,
        payload: ActionUpsert,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> ActionResponse:
        """Record or update the plan for one finding.

        Authorized with `ASSESSMENT_RUN` rather than a read permission: planning work
        is not reading, and the roles that can start an assessment are the ones that
        own what happens to a domain. Deciding *not* to fix something is a different
        decision and lives with suppressions.
        """
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.ASSESSMENT_RUN)

            finding = (
                connection.execute(
                    text(
                        "SELECT id, state FROM findings "
                        "WHERE id = :finding_id AND organization_id = :organization_id"
                    ),
                    {"finding_id": finding_id, "organization_id": organization_id},
                )
                .mappings()
                .one_or_none()
            )
            if finding is None:
                raise AppError(404, "not_found", "The requested resource was not found.")

            if payload.owner_user_id is not None:
                # An owner has to be somebody who can actually see the finding.
                # Assigning work to a person outside the organization would produce a
                # name on a screen and nobody accountable behind it.
                member = connection.execute(
                    text(
                        "SELECT 1 FROM memberships WHERE organization_id = :organization_id "
                        "AND user_id = :user_id AND status = 'active'"
                    ),
                    {"organization_id": organization_id, "user_id": payload.owner_user_id},
                ).scalar_one_or_none()
                if member is None:
                    raise AppError(
                        422,
                        "validation_error",
                        "The owner must be an active member of this organization.",
                    )

            previous = connection.execute(
                text("SELECT status FROM remediation_actions WHERE finding_id = :finding_id"),
                {"finding_id": finding_id},
            ).scalar_one_or_none()

            completed_at = datetime.now(UTC) if payload.status == COMPLETED else None
            row = (
                connection.execute(
                    text(
                        """
                        INSERT INTO remediation_actions (
                            organization_id, finding_id, status, owner_user_id, due_at,
                            note, completed_at, created_by_user_id
                        ) VALUES (
                            :organization_id, :finding_id, :status, :owner_user_id,
                            :due_at, :note, :completed_at, :actor
                        )
                        ON CONFLICT (finding_id) DO UPDATE SET
                            status = excluded.status,
                            owner_user_id = excluded.owner_user_id,
                            due_at = excluded.due_at,
                            note = excluded.note,
                            -- Preserved when it was already complete and still is, so
                            -- editing a note does not silently restate when the work
                            -- was finished.
                            completed_at = CASE
                                WHEN excluded.status <> 'completed' THEN NULL
                                WHEN remediation_actions.completed_at IS NOT NULL
                                    THEN remediation_actions.completed_at
                                ELSE excluded.completed_at
                            END,
                            updated_at = now()
                        RETURNING id
                        """
                    ),
                    {
                        "organization_id": organization_id,
                        "finding_id": finding_id,
                        "status": payload.status,
                        "owner_user_id": payload.owner_user_id,
                        "due_at": payload.due_at,
                        "note": payload.note,
                        "completed_at": completed_at,
                        "actor": principal.user_id,
                    },
                )
                .mappings()
                .one()
            )

            if previous != payload.status:
                # Only on a change of status. Recording every edit of a note would bury
                # the transitions somebody actually wants to reconstruct.
                connection.execute(
                    text(
                        """
                        INSERT INTO remediation_action_history (
                            organization_id, action_id, from_status, to_status,
                            actor_user_id, note
                        ) VALUES (
                            :organization_id, :action_id, :from_status, :to_status,
                            :actor, :note
                        )
                        """
                    ),
                    {
                        "organization_id": organization_id,
                        "action_id": row["id"],
                        "from_status": previous,
                        "to_status": payload.status,
                        "actor": principal.user_id,
                        "note": payload.note,
                    },
                )

            append_audit_event(
                connection,
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(principal.user_id),
                action="remediation.action_changed",
                resource_type="finding",
                resource_id=str(finding_id),
                request_id=cast(str, request.state.request_id),
                correlation_id=request.state.correlation_id,
                outcome="success",
                context={"status": payload.status, "previous": previous or "none"},
            )

            stored = (
                connection.execute(
                    text(
                        """
                        SELECT a.id, a.finding_id, a.status, a.owner_user_id, a.due_at,
                               a.note, a.completed_at, a.created_at, a.updated_at,
                               f.check_id, f.severity, f.state AS finding_state,
                               u.display_name AS owner_display_name
                        FROM remediation_actions a
                        JOIN findings f ON f.id = a.finding_id
                        LEFT JOIN users u ON u.id = a.owner_user_id
                        WHERE a.id = :id
                        """
                    ),
                    {"id": row["id"]},
                )
                .mappings()
                .one()
            )

        return _action_response(stored, load_check_metadata())

    return router
