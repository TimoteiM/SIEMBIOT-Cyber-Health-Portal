"""Assessment and asset-candidate endpoints.

The API starts and observes runs; it does not perform them. Creating an assessment
writes a queued row and returns, because collection can take minutes and a request
that waited for it would time out and tell the caller nothing useful.

Progress is read from settled steps rather than elapsed time, so a slow run reports
slow progress instead of a reassuring animation.
"""

from __future__ import annotations

from typing import cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request
from siembiot_worker.workflows.graph import ASSESSMENT_GRAPH
from sqlalchemy import Connection, text
from sqlalchemy.engine import RowMapping

from siembiot.audit import append_audit_event
from siembiot.auth import current_principal, require_trusted_origin
from siembiot.authorization import Action
from siembiot.contracts import (
    AssessmentCancel,
    AssessmentCreate,
    AssessmentProgressResponse,
    AssessmentResponse,
    AssessmentStepResponse,
    AssetCandidateDecision,
    AssetCandidateResponse,
)
from siembiot.db import Database
from siembiot.errors import AppError
from siembiot.identity import Principal
from siembiot.organizations import authorize

#: The steps a run is expected to walk, so one that has not started yet reports honestly
#: rather than showing an empty, complete-looking bar.
#:
#: Read from the worker's graph rather than copied. It used to be a literal list with a
#: comment asking whoever edited the graph to keep it in step, and the first step added
#: after that comment was written did not reach it: the interface reported 13 of 13
#: complete while a fourteenth step was running. The API already imports the worker
#: package for the shared network-safety boundary, so there is nothing to be gained by
#: keeping a second copy of this.
EXPECTED_STEP_NAMES: tuple[str, ...] = tuple(step.name for step in ASSESSMENT_GRAPH)
#: Mirrors siembiot_worker.observation.mode.AssessmentMode. Duplicated rather than
#: imported so that a request handler does not pull in the collection machinery to name
#: two strings; the migration's check constraint is what keeps the two honest. The API
#: does import the worker package elsewhere, for the shared network-safety boundary.
PASSIVE_OBSERVATION = "passive_observation"
AUTHORIZED_ASSESSMENT = "authorized_assessment"

SETTLED_STEP_STATES = frozenset({"succeeded", "failed", "skipped", "cancelled", "dead_lettered"})
TERMINAL_ASSESSMENT_STATES = frozenset(
    {
        "completed",
        "cancelled",
        "partially_completed",
        "failed",
        "expired",
        "blocked_by_policy",
    }
)


def _request_id(request: Request) -> str:
    return cast(str, request.state.request_id)


def _database(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def _assessment_row(connection: Connection, assessment_id: UUID) -> RowMapping | None:
    return (
        connection.execute(
            text(
                """
                SELECT a.id, a.organization_id, a.domain_id, a.state, a.mode,
                       a.methodology_version, a.created_at, a.completed_at,
                       a.cancellation_requested_at,
                       s.score, s.band, s.coverage_percentage
                FROM assessments a
                LEFT JOIN score_snapshots s
                    ON s.assessment_id = a.id AND s.is_projection = false
                WHERE a.id = :assessment_id
                """
            ),
            {"assessment_id": assessment_id},
        )
        .mappings()
        .one_or_none()
    )


def _require_assessment_row(connection: Connection, assessment_id: UUID) -> RowMapping:
    """Re-read a row we have just written or selected inside this transaction.

    An `assert` would be stripped under `-O`, turning a missing row into a confusing
    `None` attribute error further down. This raises the same 404 the caller would get
    for any other unreachable assessment, which is also the correct answer if row-level
    security has hidden it.
    """
    row = _assessment_row(connection, assessment_id)
    if row is None:
        raise AppError(404, "not_found", "The requested resource was not found.")
    return row


def _steps(connection: Connection, assessment_id: UUID) -> list[AssessmentStepResponse]:
    rows = connection.execute(
        text(
            "SELECT name, state, attempts, last_error FROM assessment_steps "
            "WHERE assessment_id = :assessment_id ORDER BY name"
        ),
        {"assessment_id": assessment_id},
    ).mappings()
    return [
        AssessmentStepResponse(
            name=row["name"],
            state=row["state"],
            attempts=row["attempts"],
            last_error=row["last_error"],
        )
        for row in rows
    ]


def _progress(steps: list[AssessmentStepResponse]) -> AssessmentProgressResponse:
    """Count settled steps against the graph the run is expected to walk."""
    total = len(EXPECTED_STEP_NAMES)
    by_name = {step.name: step for step in steps}
    settled = sum(
        1
        for name in EXPECTED_STEP_NAMES
        if name in by_name and by_name[name].state in SETTLED_STEP_STATES
    )
    succeeded = sum(
        1 for name in EXPECTED_STEP_NAMES if name in by_name and by_name[name].state == "succeeded"
    )
    failed = [
        name
        for name in EXPECTED_STEP_NAMES
        if name in by_name and by_name[name].state in {"failed", "dead_lettered"}
    ]
    return AssessmentProgressResponse(
        total_steps=total,
        settled_steps=settled,
        succeeded_steps=succeeded,
        percentage=round(100.0 * settled / total, 1) if total else 0.0,
        failed_steps=failed,
    )


def _assessment_response(connection: Connection, row: RowMapping) -> AssessmentResponse:
    steps = _steps(connection, row["id"])
    return AssessmentResponse(
        id=row["id"],
        organization_id=row["organization_id"],
        domain_id=row["domain_id"],
        state=row["state"],
        mode=row["mode"],
        methodology_version=row["methodology_version"],
        created_at=row["created_at"],
        completed_at=row["completed_at"],
        cancellation_requested=row["cancellation_requested_at"] is not None,
        progress=_progress(steps),
        steps=steps,
        score=float(row["score"]) if row["score"] is not None else None,
        band=row["band"],
        coverage_percentage=(
            float(row["coverage_percentage"]) if row["coverage_percentage"] is not None else None
        ),
    )


def build_assessment_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/organizations", tags=["assessments"])

    @router.post(
        "/{organization_id}/assessments", response_model=AssessmentResponse, status_code=201
    )
    def create(
        organization_id: UUID,
        payload: AssessmentCreate,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> AssessmentResponse:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.ASSESSMENT_RUN)
            domain = (
                connection.execute(
                    text(
                        "SELECT id, ownership_state FROM domains "
                        "WHERE id = :domain_id AND organization_id = :organization_id"
                    ),
                    {"domain_id": payload.domain_id, "organization_id": organization_id},
                )
                .mappings()
                .one_or_none()
            )
            if domain is None:
                raise AppError(404, "not_found", "The requested resource was not found.")

            # Ownership proof is required by what the run will *do*, not by the fact
            # that it is a run. A passive observation reads DNS, RDAP, Certificate
            # Transparency, the TLS handshake and the page a browser would fetch --
            # nothing the target does not already publish to everyone -- so demanding
            # proof of control for it would be a ceremony that protects nobody, and
            # would put the whole methodology out of reach of anyone evaluating a
            # domain they do not run.
            #
            # Authorized assessment keeps every requirement, because it is the mode
            # that can reach past what a visitor sees.
            if payload.mode == AUTHORIZED_ASSESSMENT and domain["ownership_state"] != "verified":
                raise AppError(
                    409,
                    "ownership_not_verified",
                    "An authorized assessment requires verified control of the domain. "
                    "Passive observation of published data needs no proof of control.",
                )

            # An assessment already in flight for this domain is reused rather than
            # duplicated: two concurrent runs would compete for the same evidence rows.
            existing = connection.execute(
                text(
                    """
                    SELECT id FROM assessments
                    WHERE domain_id = :domain_id
                      AND state NOT IN (
                        'completed', 'cancelled', 'partially_completed', 'failed',
                        'expired', 'blocked_by_policy'
                      )
                    LIMIT 1
                    """
                ),
                {"domain_id": payload.domain_id},
            ).scalar_one_or_none()
            if existing is not None:
                row = _require_assessment_row(connection, existing)
                return _assessment_response(connection, row)

            methodology = connection.execute(
                text("SELECT version FROM methodology_versions ORDER BY version DESC LIMIT 1")
            ).scalar_one_or_none()
            if methodology is None:
                raise AppError(
                    409, "methodology_unavailable", "No methodology version is published."
                )

            assessment_id = uuid4()
            # The API does not talk to the broker. Writing 'queued' inside this
            # transaction *is* the enqueue: the worker's sweep claims anything unsettled
            # and not waiting out a backoff window. Publishing a message here instead
            # would be a second write that can fail after this one commits, leaving a
            # run nobody ever picks up -- and it would make creating an assessment
            # depend on Redis being reachable, which it need not be.
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
                    "organization_id": organization_id,
                    "domain_id": payload.domain_id,
                    "methodology_version": methodology,
                    "mode": payload.mode,
                },
            )
            append_audit_event(
                connection,
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(principal.user_id),
                action="assessment.queued",
                resource_type="assessment",
                resource_id=str(assessment_id),
                request_id=_request_id(request),
                correlation_id=request.state.correlation_id,
                outcome="success",
                # The mode is recorded in the audit trail as well as on the row: an
                # auditor asking "what did this platform do to that domain, and under
                # what authority" must be able to answer it from the log alone.
                context={"domain_id": str(payload.domain_id), "mode": payload.mode},
            )
            row = _require_assessment_row(connection, assessment_id)
            return _assessment_response(connection, row)

    @router.get("/{organization_id}/assessments", response_model=list[AssessmentResponse])
    def index(
        organization_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> list[AssessmentResponse]:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.ASSESSMENT_READ)
            identifiers = connection.execute(
                text(
                    "SELECT id FROM assessments WHERE organization_id = :organization_id "
                    "ORDER BY created_at DESC LIMIT 100"
                ),
                {"organization_id": organization_id},
            ).scalars()
            responses: list[AssessmentResponse] = []
            for assessment_id in identifiers:
                row = _assessment_row(connection, assessment_id)
                if row is not None:
                    responses.append(_assessment_response(connection, row))
            return responses

    @router.get("/{organization_id}/assessments/{assessment_id}", response_model=AssessmentResponse)
    def show(
        organization_id: UUID,
        assessment_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> AssessmentResponse:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.ASSESSMENT_READ)
            row = _assessment_row(connection, assessment_id)
            if row is None or row["organization_id"] != organization_id:
                raise AppError(404, "not_found", "The requested resource was not found.")
            return _assessment_response(connection, row)

    @router.post(
        "/{organization_id}/assessments/{assessment_id}/cancel",
        response_model=AssessmentResponse,
    )
    def cancel(
        organization_id: UUID,
        assessment_id: UUID,
        payload: AssessmentCancel,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> AssessmentResponse:
        """Request cancellation. Work in flight observes it and settles itself."""
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.ASSESSMENT_CANCEL)
            row = _assessment_row(connection, assessment_id)
            if row is None or row["organization_id"] != organization_id:
                raise AppError(404, "not_found", "The requested resource was not found.")
            if row["state"] in TERMINAL_ASSESSMENT_STATES:
                raise AppError(
                    409, "assessment_already_settled", "The assessment has already finished."
                )
            connection.execute(
                text(
                    """
                    UPDATE assessments
                    SET cancellation_requested_at = COALESCE(cancellation_requested_at, now()),
                        cancellation_reason = COALESCE(cancellation_reason, :reason)
                    WHERE id = :id
                    """
                ),
                {"id": assessment_id, "reason": payload.reason},
            )
            append_audit_event(
                connection,
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(principal.user_id),
                action="assessment.cancellation_requested",
                resource_type="assessment",
                resource_id=str(assessment_id),
                request_id=_request_id(request),
                correlation_id=request.state.correlation_id,
                outcome="success",
                context={"reason": payload.reason},
            )
            refreshed = _require_assessment_row(connection, assessment_id)
            return _assessment_response(connection, refreshed)

    return router


def build_asset_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/organizations", tags=["assets"])

    @router.get(
        "/{organization_id}/domains/{domain_id}/asset-candidates",
        response_model=list[AssetCandidateResponse],
    )
    def index(
        organization_id: UUID,
        domain_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> list[AssetCandidateResponse]:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.ASSET_READ)
            rows = connection.execute(
                text(
                    """
                    SELECT id, domain_id, name, source, attribution_confidence,
                           attribution_basis, shared_hosting, state, first_seen_at,
                           last_seen_at, observation_count
                    FROM asset_candidates
                    WHERE domain_id = :domain_id AND organization_id = :organization_id
                    ORDER BY state, attribution_confidence DESC, name
                    """
                ),
                {"domain_id": domain_id, "organization_id": organization_id},
            ).mappings()
            return [
                AssetCandidateResponse(
                    id=row["id"],
                    domain_id=row["domain_id"],
                    name=row["name"],
                    source=row["source"],
                    attribution_confidence=float(row["attribution_confidence"]),
                    attribution_basis=row["attribution_basis"],
                    shared_hosting=row["shared_hosting"],
                    state=row["state"],
                    first_seen_at=row["first_seen_at"],
                    last_seen_at=row["last_seen_at"],
                    observation_count=row["observation_count"],
                )
                for row in rows
            ]

    @router.post(
        "/{organization_id}/asset-candidates/{candidate_id}/decision",
        response_model=AssetCandidateResponse,
    )
    def decide(
        organization_id: UUID,
        candidate_id: UUID,
        payload: AssetCandidateDecision,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> AssetCandidateResponse:
        """Accept or reject a candidate.

        Accepting decides what may be assessed, so it is attributable and audited.
        """
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.ASSET_DECIDE)
            candidate = (
                connection.execute(
                    text("SELECT id, organization_id, state FROM asset_candidates WHERE id = :id"),
                    {"id": candidate_id},
                )
                .mappings()
                .one_or_none()
            )
            if candidate is None or candidate["organization_id"] != organization_id:
                raise AppError(404, "not_found", "The requested resource was not found.")
            if candidate["state"] == payload.decision:
                raise AppError(
                    409, "decision_unchanged", "The candidate already has that decision."
                )

            connection.execute(
                text("UPDATE asset_candidates SET state = :state WHERE id = :id"),
                {"state": payload.decision, "id": candidate_id},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO asset_candidate_decisions (
                        organization_id, candidate_id, decision, reason, actor_user_id
                    ) VALUES (
                        :organization_id, :candidate_id, :decision, :reason, :actor_user_id
                    )
                    """
                ),
                {
                    "organization_id": organization_id,
                    "candidate_id": candidate_id,
                    "decision": payload.decision,
                    "reason": payload.reason,
                    "actor_user_id": principal.user_id,
                },
            )
            append_audit_event(
                connection,
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(principal.user_id),
                action=f"asset.{payload.decision}",
                resource_type="asset_candidate",
                resource_id=str(candidate_id),
                request_id=_request_id(request),
                correlation_id=request.state.correlation_id,
                outcome="success",
                context={"reason": payload.reason} if payload.reason else {},
            )
            row = (
                connection.execute(
                    text(
                        """
                        SELECT id, domain_id, name, source, attribution_confidence,
                               attribution_basis, shared_hosting, state, first_seen_at,
                               last_seen_at, observation_count
                        FROM asset_candidates WHERE id = :id
                        """
                    ),
                    {"id": candidate_id},
                )
                .mappings()
                .one()
            )
            return AssetCandidateResponse(
                id=row["id"],
                domain_id=row["domain_id"],
                name=row["name"],
                source=row["source"],
                attribution_confidence=float(row["attribution_confidence"]),
                attribution_basis=row["attribution_basis"],
                shared_hosting=row["shared_hosting"],
                state=row["state"],
                first_seen_at=row["first_seen_at"],
                last_seen_at=row["last_seen_at"],
                observation_count=row["observation_count"],
            )

    return router
