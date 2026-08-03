from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request
from sqlalchemy import Connection, text
from sqlalchemy.engine import RowMapping

from siembiot.audit import append_audit_event
from siembiot.auth import Principal, current_principal, require_csrf
from siembiot.authorization import Action
from siembiot.contracts import (
    AssessmentAuthorizationCreate,
    AssessmentAuthorizationResponse,
    AuthorizationRevoke,
    ScopeManifestResponse,
)
from siembiot.db import Database
from siembiot.domains.manifests import canonical_manifest_bytes, scope_manifest_payload
from siembiot.domains.signing import ManifestSigner
from siembiot.errors import AppError
from siembiot.organizations import authorize


def _database(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def _request_id(request: Request) -> str:
    return cast(str, request.state.request_id)


def _authorization_response(row: RowMapping) -> AssessmentAuthorizationResponse:
    return AssessmentAuthorizationResponse(
        id=row["id"],
        organization_id=row["organization_id"],
        state=row["state"],
        policy_version=row["policy_version"],
        consent_version=row["consent_version"],
        valid_from=row["valid_from"],
        valid_until=row["valid_until"],
        operation_classes=list(row["operation_classes"] or []),
    )


def _authorization_row(connection: Connection, authorization_id: UUID) -> RowMapping | None:
    return (
        connection.execute(
            text(
                """
                SELECT a.id, a.organization_id, a.authorized_by_user_id, a.state,
                    a.policy_version, a.consent_version, a.consent_text,
                    a.valid_from, a.valid_until,
                    array_agg(DISTINCT t.operation_class ORDER BY t.operation_class)
                        FILTER (WHERE t.operation_class IS NOT NULL) AS operation_classes
                FROM assessment_authorizations a
                LEFT JOIN authorization_targets t ON t.authorization_id = a.id
                WHERE a.id = :authorization_id
                GROUP BY a.id
                """
            ),
            {"authorization_id": authorization_id},
        )
        .mappings()
        .one_or_none()
    )


def _domain_for_authorization(connection: Connection, domain_id: UUID) -> RowMapping | None:
    return (
        connection.execute(
            text(
                "SELECT id, canonical_name, ownership_state, reverification_due_at "
                "FROM domains WHERE id = :domain_id"
            ),
            {"domain_id": domain_id},
        )
        .mappings()
        .one_or_none()
    )


def _require_current_verification(row: RowMapping) -> None:
    due_at = row["reverification_due_at"]
    if row["ownership_state"] != "verified" or due_at is None or due_at <= datetime.now(UTC):
        raise AppError(
            409,
            "domain_not_verified",
            "Current domain verification is required before authorization.",
        )


def build_authorization_router() -> APIRouter:
    router = APIRouter(
        prefix="/api/v1/organizations/{organization_id}/authorizations",
        tags=["authorizations"],
    )

    @router.post("", response_model=AssessmentAuthorizationResponse, status_code=201)
    def create_authorization(
        organization_id: UUID,
        body: AssessmentAuthorizationCreate,
        request: Request,
        principal: Principal = Depends(require_csrf),
    ) -> AssessmentAuthorizationResponse:
        if (
            body.valid_from.tzinfo is None
            or body.valid_until.tzinfo is None
            or body.valid_until <= body.valid_from
            or body.valid_until <= datetime.now(UTC)
            or body.valid_until - body.valid_from > timedelta(days=365)
            or len(set(body.domain_ids)) != len(body.domain_ids)
            or len(set(body.operation_classes)) != len(body.operation_classes)
        ):
            raise AppError(422, "invalid_authorization", "The authorization is invalid.")

        authorization_id = uuid4()
        consent_digest = hashlib.sha256(body.consent_text.encode("utf-8")).digest()
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.AUTHORIZATION_MANAGE)
            domains: list[RowMapping] = []
            for domain_id in body.domain_ids:
                domain = _domain_for_authorization(connection, domain_id)
                if domain is None:
                    raise AppError(404, "not_found", "The requested resource was not found.")
                _require_current_verification(domain)
                domains.append(domain)

            connection.execute(
                text(
                    """
                    INSERT INTO assessment_authorizations (
                        id, organization_id, authorized_by_user_id, policy_version,
                        consent_version, consent_text, consent_text_digest, valid_from, valid_until
                    ) VALUES (
                        :id, :organization_id, :user_id, :policy_version,
                        :consent_version, :consent_text, :consent_digest, :valid_from, :valid_until
                    )
                    """
                ),
                {
                    "id": authorization_id,
                    "organization_id": organization_id,
                    "user_id": principal.user_id,
                    "policy_version": body.policy_version,
                    "consent_version": body.consent_version,
                    "consent_text": body.consent_text,
                    "consent_digest": consent_digest,
                    "valid_from": body.valid_from,
                    "valid_until": body.valid_until,
                },
            )
            for domain in domains:
                for operation_class in body.operation_classes:
                    connection.execute(
                        text(
                            """
                            INSERT INTO authorization_targets (
                                organization_id, authorization_id, domain_id,
                                canonical_host, operation_class
                            ) VALUES (
                                :organization_id, :authorization_id, :domain_id,
                                :canonical_host, :operation_class
                            )
                            """
                        ),
                        {
                            "organization_id": organization_id,
                            "authorization_id": authorization_id,
                            "domain_id": domain["id"],
                            "canonical_host": domain["canonical_name"],
                            "operation_class": operation_class,
                        },
                    )
            append_audit_event(
                connection,
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(principal.user_id),
                action="authorization.created",
                resource_type="assessment_authorization",
                resource_id=str(authorization_id),
                request_id=_request_id(request),
                correlation_id=request.state.correlation_id,
                outcome="success",
                context={
                    "domain_count": len(domains),
                    "operation_classes": list(body.operation_classes),
                    "policy_version": body.policy_version,
                    "consent_version": body.consent_version,
                },
            )
            row = _authorization_row(connection, authorization_id)
        if row is None:
            raise AppError(500, "internal_error", "The request could not be completed.")
        return _authorization_response(row)

    @router.get("", response_model=list[AssessmentAuthorizationResponse])
    def list_authorizations(
        organization_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> list[AssessmentAuthorizationResponse]:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.AUTHORIZATION_READ)
            rows = (
                connection.execute(
                    text(
                        """
                        SELECT a.id, a.organization_id, a.state, a.policy_version,
                            a.consent_version, a.valid_from, a.valid_until,
                            array_agg(DISTINCT t.operation_class ORDER BY t.operation_class)
                                FILTER (WHERE t.operation_class IS NOT NULL) AS operation_classes
                        FROM assessment_authorizations a
                        LEFT JOIN authorization_targets t ON t.authorization_id = a.id
                        GROUP BY a.id ORDER BY a.created_at DESC, a.id
                        """
                    )
                )
                .mappings()
                .all()
            )
        return [_authorization_response(row) for row in rows]

    @router.post(
        "/{authorization_id}/accept", response_model=ScopeManifestResponse, status_code=201
    )
    def accept_authorization(
        organization_id: UUID,
        authorization_id: UUID,
        request: Request,
        principal: Principal = Depends(require_csrf),
    ) -> ScopeManifestResponse:
        signer = cast(ManifestSigner, request.app.state.manifest_signer)
        manifest_id = uuid4()
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.AUTHORIZATION_MANAGE)
            authorization = (
                connection.execute(
                    text(
                        "SELECT * FROM assessment_authorizations "
                        "WHERE id = :authorization_id FOR UPDATE"
                    ),
                    {"authorization_id": authorization_id},
                )
                .mappings()
                .one_or_none()
            )
            if authorization is None:
                raise AppError(404, "not_found", "The requested resource was not found.")
            now = datetime.now(UTC)
            if authorization["state"] != "draft":
                raise AppError(409, "authorization_inactive", "The authorization is not a draft.")
            if not (authorization["valid_from"] <= now < authorization["valid_until"]):
                raise AppError(
                    409, "authorization_not_current", "The authorization is not current."
                )
            targets = (
                connection.execute(
                    text(
                        "SELECT t.domain_id, t.canonical_host, t.operation_class, "
                        "d.ownership_state, d.reverification_due_at "
                        "FROM authorization_targets t JOIN domains d ON d.id = t.domain_id "
                        "WHERE t.authorization_id = :authorization_id "
                        "ORDER BY t.canonical_host, t.operation_class, t.domain_id"
                    ),
                    {"authorization_id": authorization_id},
                )
                .mappings()
                .all()
            )
            if not targets:
                raise AppError(409, "authorization_empty", "The authorization has no targets.")
            for target in targets:
                _require_current_verification(target)
            payload_targets: list[dict[str, str]] = [
                {
                    "domain_id": str(target["domain_id"]),
                    "canonical_host": target["canonical_host"],
                    "operation_class": target["operation_class"],
                }
                for target in targets
            ]
            payload = scope_manifest_payload(
                authorization_id=authorization_id,
                organization_id=organization_id,
                actor_id=principal.user_id,
                targets=payload_targets,
                policy_version=authorization["policy_version"],
                consent_version=authorization["consent_version"],
                consent_text=authorization["consent_text"],
                valid_from=authorization["valid_from"],
                valid_until=authorization["valid_until"],
                issued_at=now,
            )
            canonical = canonical_manifest_bytes(cast(dict[str, Any], payload))
            payload_hash = hashlib.sha256(canonical).digest()
            signature = signer.sign(canonical)
            created_at = connection.execute(
                text(
                    """
                    INSERT INTO scope_manifests (
                        id, organization_id, authorization_id, manifest_version,
                        canonical_payload, payload_hash, signature, key_id, algorithm
                    ) VALUES (
                        :id, :organization_id, :authorization_id, 'v1',
                        CAST(:payload AS jsonb), :payload_hash, :signature, :key_id, :algorithm
                    ) RETURNING created_at
                    """
                ),
                {
                    "id": manifest_id,
                    "organization_id": organization_id,
                    "authorization_id": authorization_id,
                    "payload": canonical.decode("utf-8"),
                    "payload_hash": payload_hash,
                    "signature": signature,
                    "key_id": signer.key_id,
                    "algorithm": signer.algorithm,
                },
            ).scalar_one()
            connection.execute(
                text(
                    "UPDATE assessment_authorizations SET state = 'active', activated_at = now() "
                    "WHERE id = :authorization_id"
                ),
                {"authorization_id": authorization_id},
            )
            for action, resource_type, resource_id in (
                ("authorization.accepted", "assessment_authorization", authorization_id),
                ("scope_manifest.created", "scope_manifest", manifest_id),
            ):
                append_audit_event(
                    connection,
                    organization_id=organization_id,
                    actor_type="user",
                    actor_id=str(principal.user_id),
                    action=action,
                    resource_type=resource_type,
                    resource_id=str(resource_id),
                    request_id=_request_id(request),
                    correlation_id=request.state.correlation_id,
                    outcome="success",
                    context={"authorization_id": str(authorization_id), "key_id": signer.key_id},
                )
        return ScopeManifestResponse(
            id=manifest_id,
            authorization_id=authorization_id,
            payload_sha256=payload_hash.hex(),
            key_id=signer.key_id,
            created_at=created_at,
        )

    @router.post("/{authorization_id}/revoke", response_model=AssessmentAuthorizationResponse)
    def revoke_authorization(
        organization_id: UUID,
        authorization_id: UUID,
        body: AuthorizationRevoke,
        request: Request,
        principal: Principal = Depends(require_csrf),
    ) -> AssessmentAuthorizationResponse:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.AUTHORIZATION_MANAGE)
            current = _authorization_row(connection, authorization_id)
            if current is None:
                raise AppError(404, "not_found", "The requested resource was not found.")
            if current["state"] not in {"draft", "active"}:
                raise AppError(409, "authorization_inactive", "The authorization is inactive.")
            connection.execute(
                text(
                    "UPDATE assessment_authorizations SET state = 'revoked', revoked_at = now(), "
                    "revoked_by_user_id = :user_id, revocation_reason = :reason "
                    "WHERE id = :authorization_id"
                ),
                {
                    "authorization_id": authorization_id,
                    "user_id": principal.user_id,
                    "reason": body.reason,
                },
            )
            connection.execute(
                text(
                    """
                    UPDATE network_operations
                    SET cancel_requested_at = COALESCE(cancel_requested_at, now()),
                        status = CASE WHEN status = 'queued' THEN 'cancelled' ELSE status END,
                        completed_at = CASE WHEN status = 'queued' THEN now() ELSE completed_at END,
                        reason_code = 'authorization_revoked'
                    WHERE organization_id = :organization_id
                      AND manifest_id IN (
                        SELECT id FROM scope_manifests
                        WHERE authorization_id = :authorization_id
                      )
                      AND status IN ('queued', 'running')
                    """
                ),
                {
                    "organization_id": organization_id,
                    "authorization_id": authorization_id,
                },
            )
            append_audit_event(
                connection,
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(principal.user_id),
                action="authorization.revoked",
                resource_type="assessment_authorization",
                resource_id=str(authorization_id),
                request_id=_request_id(request),
                correlation_id=request.state.correlation_id,
                outcome="success",
                context={"reason": body.reason},
            )
            row = _authorization_row(connection, authorization_id)
        if row is None:
            raise AppError(500, "internal_error", "The request could not be completed.")
        return _authorization_response(row)

    return router
