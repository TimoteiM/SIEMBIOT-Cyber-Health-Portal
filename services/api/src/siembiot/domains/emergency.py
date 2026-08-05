from __future__ import annotations

from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request
from sqlalchemy import Connection, text
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import IntegrityError

from siembiot.audit import append_audit_event
from siembiot.auth import current_principal, require_trusted_origin
from siembiot.authorization import Action
from siembiot.contracts import (
    EmergencyControlCreate,
    EmergencyControlDeactivate,
    EmergencyControlResponse,
)
from siembiot.db import Database
from siembiot.errors import AppError
from siembiot.identity import Principal
from siembiot.organizations import authorize


def _database(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def _response(row: RowMapping) -> EmergencyControlResponse:
    now = datetime.now(UTC)
    return EmergencyControlResponse(
        id=row["id"],
        scope=row["scope"],
        organization_id=row["organization_id"],
        domain_id=row["domain_id"],
        operation_class=row["operation_class"],
        reason=row["reason"],
        active=row["deactivated_at"] is None
        and (row["expires_at"] is None or row["expires_at"] > now),
        created_at=row["created_at"],
        expires_at=row["expires_at"],
    )


def _cancel_matching_operations(
    connection: Connection,
    *,
    organization_id: UUID,
    scope: str,
    domain_id: UUID | None,
    operation_class: str | None,
) -> None:
    connection.execute(
        text(
            """
            UPDATE network_operations
            SET cancel_requested_at = COALESCE(cancel_requested_at, now()),
                status = CASE WHEN status = 'queued' THEN 'cancelled' ELSE status END,
                completed_at = CASE WHEN status = 'queued' THEN now() ELSE completed_at END,
                reason_code = 'emergency_control_active'
            WHERE organization_id = :organization_id
              AND status IN ('queued', 'running')
              AND (
                :scope = 'organization'
                OR (:scope = 'domain' AND domain_id = :domain_id)
                OR (:scope = 'operation_class' AND operation_class = :operation_class)
              )
            """
        ),
        {
            "organization_id": organization_id,
            "scope": scope,
            "domain_id": domain_id,
            "operation_class": operation_class,
        },
    )


def build_emergency_router() -> APIRouter:
    router = APIRouter(
        prefix="/api/v1/organizations/{organization_id}/emergency-controls",
        tags=["emergency-controls"],
    )

    @router.post("", response_model=EmergencyControlResponse, status_code=201)
    def activate(
        organization_id: UUID,
        body: EmergencyControlCreate,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> EmergencyControlResponse:
        if body.scope == "global":
            raise AppError(403, "forbidden", "Global controls require the platform endpoint.")
        if body.scope == "domain" and body.domain_id is None:
            raise AppError(422, "invalid_scope", "A domain control requires a domain.")
        if body.scope == "operation_class" and body.operation_class is None:
            raise AppError(422, "invalid_scope", "An operation control requires a class.")
        if body.scope in {"organization"} and (
            body.domain_id is not None or body.operation_class is not None
        ):
            raise AppError(422, "invalid_scope", "The control scope is invalid.")
        if body.expires_at is not None and body.expires_at <= datetime.now(UTC):
            raise AppError(422, "invalid_expiry", "The expiry must be in the future.")
        control_id = uuid4()
        try:
            with _database(request).tenant_connection(
                principal.user_id, organization_id
            ) as connection:
                authorize(
                    connection,
                    request,
                    principal,
                    organization_id,
                    Action.EMERGENCY_CONTROL_MANAGE,
                )
                connection.execute(
                    text(
                        "UPDATE emergency_controls SET deactivated_at = now(), "
                        "deactivated_by_user_id = :user_id, "
                        "deactivation_reason = 'Expired control replaced by operator' "
                        "WHERE deactivated_at IS NULL AND expires_at <= now() "
                        "AND organization_id = :organization_id"
                    ),
                    {"user_id": principal.user_id, "organization_id": organization_id},
                )
                row = (
                    connection.execute(
                        text(
                            """
                            INSERT INTO emergency_controls (
                                id, scope, organization_id, domain_id, operation_class,
                                reason, created_by_user_id, expires_at
                            ) VALUES (
                                :id, :scope, :organization_id, :domain_id, :operation_class,
                                :reason, :user_id, :expires_at
                            ) RETURNING id, scope, organization_id, domain_id,
                                operation_class, reason, created_at, expires_at, deactivated_at
                            """
                        ),
                        {
                            "id": control_id,
                            "scope": body.scope,
                            "organization_id": organization_id,
                            "domain_id": body.domain_id,
                            "operation_class": body.operation_class,
                            "reason": body.reason,
                            "user_id": principal.user_id,
                            "expires_at": body.expires_at,
                        },
                    )
                    .mappings()
                    .one()
                )
                _cancel_matching_operations(
                    connection,
                    organization_id=organization_id,
                    scope=body.scope,
                    domain_id=body.domain_id,
                    operation_class=body.operation_class,
                )
                append_audit_event(
                    connection,
                    organization_id=organization_id,
                    actor_type="user",
                    actor_id=str(principal.user_id),
                    action="emergency_control.activated",
                    resource_type="emergency_control",
                    resource_id=str(control_id),
                    request_id=request.state.request_id,
                    correlation_id=request.state.correlation_id,
                    outcome="success",
                    context={
                        "scope": body.scope,
                        "domain_id": str(body.domain_id) if body.domain_id else None,
                        "operation_class": body.operation_class,
                    },
                )
        except IntegrityError as exc:
            raise AppError(409, "control_active", "An active control already exists.") from exc
        return _response(row)

    @router.get("", response_model=list[EmergencyControlResponse])
    def list_controls(
        organization_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> list[EmergencyControlResponse]:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(
                connection,
                request,
                principal,
                organization_id,
                Action.EMERGENCY_CONTROL_READ,
            )
            rows = (
                connection.execute(
                    text(
                        "SELECT id, scope, organization_id, domain_id, operation_class, "
                        "reason, created_at, expires_at, deactivated_at "
                        "FROM emergency_controls WHERE organization_id = :organization_id "
                        "ORDER BY created_at DESC"
                    ),
                    {"organization_id": organization_id},
                )
                .mappings()
                .all()
            )
        return [_response(row) for row in rows]

    @router.post("/{control_id}/deactivate", response_model=EmergencyControlResponse)
    def deactivate(
        organization_id: UUID,
        control_id: UUID,
        body: EmergencyControlDeactivate,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> EmergencyControlResponse:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(
                connection,
                request,
                principal,
                organization_id,
                Action.EMERGENCY_CONTROL_MANAGE,
            )
            row = (
                connection.execute(
                    text(
                        """
                        UPDATE emergency_controls
                        SET deactivated_at = now(), deactivated_by_user_id = :user_id,
                            deactivation_reason = :reason
                        WHERE id = :control_id AND organization_id = :organization_id
                          AND deactivated_at IS NULL
                        RETURNING id, scope, organization_id, domain_id, operation_class,
                            reason, created_at, expires_at, deactivated_at
                        """
                    ),
                    {
                        "user_id": principal.user_id,
                        "reason": body.reason,
                        "control_id": control_id,
                        "organization_id": organization_id,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise AppError(404, "not_found", "The requested resource was not found.")
            append_audit_event(
                connection,
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(principal.user_id),
                action="emergency_control.deactivated",
                resource_type="emergency_control",
                resource_id=str(control_id),
                request_id=request.state.request_id,
                correlation_id=request.state.correlation_id,
                outcome="success",
                context={"reason_recorded": True},
            )
        return _response(row)

    return router


def build_global_emergency_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/emergency-controls", tags=["emergency-controls"])

    @router.post("", response_model=EmergencyControlResponse, status_code=201)
    def activate_global(
        body: EmergencyControlCreate,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> EmergencyControlResponse:
        if body.scope != "global" or body.domain_id is not None or body.operation_class is not None:
            raise AppError(422, "invalid_scope", "Only a global control is accepted here.")
        if body.expires_at is not None and body.expires_at <= datetime.now(UTC):
            raise AppError(422, "invalid_expiry", "The expiry must be in the future.")
        control_id = uuid4()
        try:
            with _database(request).user_connection(principal.user_id) as connection:
                permitted = connection.execute(
                    text("SELECT app_is_phishing_resistant_platform_admin()")
                ).scalar_one()
                if not permitted:
                    raise AppError(
                        403,
                        "forbidden",
                        "A phishing-resistant platform administrator is required.",
                    )
                connection.execute(
                    text(
                        "UPDATE emergency_controls SET deactivated_at = now(), "
                        "deactivated_by_user_id = :user_id, "
                        "deactivation_reason = 'Expired control replaced by operator' "
                        "WHERE scope = 'global' AND deactivated_at IS NULL AND expires_at <= now()"
                    ),
                    {"user_id": principal.user_id},
                )
                row = (
                    connection.execute(
                        text(
                            """
                            INSERT INTO emergency_controls (
                                id, scope, reason, created_by_user_id, expires_at
                            ) VALUES (
                                :id, 'global', :reason, :user_id, :expires_at
                            ) RETURNING id, scope, organization_id, domain_id,
                                operation_class, reason, created_at, expires_at, deactivated_at
                            """
                        ),
                        {
                            "id": control_id,
                            "reason": body.reason,
                            "user_id": principal.user_id,
                            "expires_at": body.expires_at,
                        },
                    )
                    .mappings()
                    .one()
                )
                append_audit_event(
                    connection,
                    organization_id=None,
                    actor_type="user",
                    actor_id=str(principal.user_id),
                    action="emergency_control.activated",
                    resource_type="emergency_control",
                    resource_id=str(control_id),
                    request_id=request.state.request_id,
                    correlation_id=request.state.correlation_id,
                    outcome="success",
                    context={"scope": "global"},
                )
        except IntegrityError as exc:
            raise AppError(409, "control_active", "An active control already exists.") from exc
        return _response(row)

    @router.post("/{control_id}/deactivate", response_model=EmergencyControlResponse)
    def deactivate_global(
        control_id: UUID,
        body: EmergencyControlDeactivate,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> EmergencyControlResponse:
        with _database(request).user_connection(principal.user_id) as connection:
            permitted = connection.execute(
                text("SELECT app_is_phishing_resistant_platform_admin()")
            ).scalar_one()
            if not permitted:
                raise AppError(
                    403,
                    "forbidden",
                    "A phishing-resistant platform administrator is required.",
                )
            row = (
                connection.execute(
                    text(
                        """
                        UPDATE emergency_controls
                        SET deactivated_at = now(), deactivated_by_user_id = :user_id,
                            deactivation_reason = :reason
                        WHERE id = :control_id AND scope = 'global' AND deactivated_at IS NULL
                        RETURNING id, scope, organization_id, domain_id, operation_class,
                            reason, created_at, expires_at, deactivated_at
                        """
                    ),
                    {
                        "user_id": principal.user_id,
                        "reason": body.reason,
                        "control_id": control_id,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise AppError(404, "not_found", "The requested resource was not found.")
            append_audit_event(
                connection,
                organization_id=None,
                actor_type="user",
                actor_id=str(principal.user_id),
                action="emergency_control.deactivated",
                resource_type="emergency_control",
                resource_id=str(control_id),
                request_id=request.state.request_id,
                correlation_id=request.state.correlation_id,
                outcome="success",
                context={"reason_recorded": True},
            )
        return _response(row)

    return router
