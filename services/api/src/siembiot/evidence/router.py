from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text

from siembiot.audit import append_audit_event
from siembiot.auth import Principal, current_principal, require_csrf
from siembiot.authorization import Action
from siembiot.db import Database
from siembiot.errors import AppError
from siembiot.evidence.contracts import (
    FindingEventCreate,
    FindingEventResponse,
    FindingResponse,
    ScoreSnapshotResponse,
)
from siembiot.organizations import authorize


def _database(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def build_evidence_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/organizations/{organization_id}/evidence", tags=["evidence"])

    @router.get("/findings", response_model=list[FindingResponse])
    def list_findings(
        organization_id: UUID, request: Request, principal: Principal = Depends(current_principal)
    ) -> list[FindingResponse]:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.EVIDENCE_READ)
            rows = (
                connection.execute(
                    text(
                        "SELECT id, asset_id, check_id, evidence_mode, severity, first_seen_at, "
                        "publishable, classification FROM findings ORDER BY first_seen_at, id"
                    )
                )
                .mappings()
                .all()
            )
        return [FindingResponse.model_validate(row) for row in rows]

    @router.get("/snapshots", response_model=list[ScoreSnapshotResponse])
    def list_snapshots(
        organization_id: UUID, request: Request, principal: Principal = Depends(current_principal)
    ) -> list[ScoreSnapshotResponse]:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.EVIDENCE_READ)
            rows = (
                connection.execute(
                    text(
                        "SELECT id, asset_id, evidence_mode, methodology_version, "
                        "technical_posture, "
                        "coverage, evidence_confidence, attribution_confidence, publishable, "
                        "classification, created_at FROM score_snapshots ORDER BY created_at, id"
                    )
                )
                .mappings()
                .all()
            )
        return [ScoreSnapshotResponse.model_validate(row) for row in rows]

    @router.get("/findings/{finding_id}/history", response_model=list[FindingEventResponse])
    def finding_history(
        organization_id: UUID,
        finding_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> list[FindingEventResponse]:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.EVIDENCE_READ)
            exists = connection.execute(
                text("SELECT 1 FROM findings WHERE id=:id"), {"id": finding_id}
            ).scalar_one_or_none()
            if exists is None:
                raise AppError(404, "not_found", "The requested resource was not found.")
            rows = (
                connection.execute(
                    text(
                        "SELECT id, finding_id, event_type, actor_id, reason, scope_reference, "
                        "occurred_at, review_at, request_id, correlation_id FROM finding_events "
                        "WHERE finding_id=:id ORDER BY occurred_at, id"
                    ),
                    {"id": finding_id},
                )
                .mappings()
                .all()
            )
        return [FindingEventResponse.model_validate(row) for row in rows]

    @router.post(
        "/findings/{finding_id}/events", response_model=FindingEventResponse, status_code=201
    )
    def create_finding_event(
        organization_id: UUID,
        finding_id: UUID,
        body: FindingEventCreate,
        request: Request,
        principal: Principal = Depends(require_csrf),
    ) -> FindingEventResponse:
        occurred_at = datetime.now(UTC)
        if body.review_at is not None and body.review_at <= occurred_at:
            raise AppError(422, "decision_review_required", "A future review date is required.")
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.FINDING_MANAGE)
            finding = (
                connection.execute(
                    text("SELECT id,evidence_mode FROM findings WHERE id=:id"), {"id": finding_id}
                )
                .mappings()
                .one_or_none()
            )
            if finding is None:
                raise AppError(404, "not_found", "The requested resource was not found.")
            audit_id = append_audit_event(
                connection,
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(principal.user_id),
                action=f"finding.{body.event_type}",
                resource_type="finding",
                resource_id=str(finding_id),
                request_id=request.state.request_id,
                correlation_id=request.state.correlation_id,
                outcome="success",
                context={
                    "scope_reference": body.scope_reference,
                    "review_at": body.review_at.isoformat() if body.review_at else None,
                },
            )
            event_id = uuid4()
            identity = {
                "finding_id": str(finding_id),
                "event_type": body.event_type,
                "actor_id": str(principal.user_id),
                "reason": body.reason,
                "scope_reference": body.scope_reference,
                "occurred_at": occurred_at.isoformat(),
                "review_at": body.review_at.isoformat() if body.review_at else None,
                "request_id": request.state.request_id,
                "correlation_id": request.state.correlation_id,
            }
            event_hash = hashlib.sha256(
                json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
            ).digest()
            row = (
                connection.execute(
                    text(
                        "INSERT INTO finding_events(id, organization_id, finding_id, "
                        "evidence_mode, "
                        "event_hash, event_type, actor_id, reason, scope_reference, occurred_at, "
                        "review_at, request_id, correlation_id, audit_event_id) VALUES(:id, "
                        ":organization_id, :finding_id, :mode, :event_hash, :event_type, "
                        ":actor_id, "
                        ":reason, :scope_reference, :occurred_at, :review_at, :request_id, "
                        ":correlation_id, :audit_event_id) RETURNING id, finding_id, event_type, "
                        "actor_id, reason, scope_reference, occurred_at, review_at, request_id, "
                        "correlation_id"
                    ),
                    {
                        "id": event_id,
                        "organization_id": organization_id,
                        "finding_id": finding_id,
                        "mode": finding["evidence_mode"],
                        "event_hash": event_hash,
                        "event_type": body.event_type,
                        "actor_id": principal.user_id,
                        "reason": body.reason,
                        "scope_reference": body.scope_reference,
                        "occurred_at": occurred_at,
                        "review_at": body.review_at,
                        "request_id": request.state.request_id,
                        "correlation_id": request.state.correlation_id,
                        "audit_event_id": audit_id,
                    },
                )
                .mappings()
                .one()
            )
        return FindingEventResponse.model_validate(row)

    return router
