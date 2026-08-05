from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import Connection, text
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import IntegrityError

from siembiot.audit import append_audit_event
from siembiot.auth import current_principal, require_trusted_origin
from siembiot.authorization import Action
from siembiot.config import Settings
from siembiot.contracts import (
    DomainChallengeCreate,
    DomainChallengeCreatedResponse,
    DomainCreate,
    DomainResponse,
)
from siembiot.db import Database
from siembiot.domains.challenges import new_challenge_token
from siembiot.domains.dns_verification import DNSVerificationService, TXTResolver
from siembiot.domains.network_adapter import HTTPSVerificationService, NetworkBrokerFactory
from siembiot.domains.normalization import DomainValidationError, normalize_domain
from siembiot.domains.service import challenge_response, domain_response
from siembiot.errors import AppError
from siembiot.identity import Principal
from siembiot.organizations import authorize


def _request_id(request: Request) -> str:
    return cast(str, request.state.request_id)


def _database(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def _settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def _domain_row(connection: Connection, domain_id: UUID) -> RowMapping | None:
    return (
        connection.execute(
            text(
                "SELECT id, organization_id, canonical_name, unicode_display, "
                "registrable_domain, warnings, ownership_state, created_at "
                "FROM domains WHERE id = :domain_id"
            ),
            {"domain_id": domain_id},
        )
        .mappings()
        .one_or_none()
    )


def _record_verification_event(
    connection: Connection,
    *,
    organization_id: UUID,
    domain_id: UUID,
    challenge_id: UUID | None,
    event_type: str,
    outcome: str,
    reason_code: str,
    context: dict[str, str] | None = None,
) -> None:
    connection.execute(
        text(
            """
            INSERT INTO domain_verification_events (
                organization_id, domain_id, challenge_id, event_type, outcome, reason_code, context
            ) VALUES (
                :organization_id, :domain_id, :challenge_id, :event_type, :outcome,
                :reason_code, CAST(:context AS jsonb)
            )
            """
        ),
        {
            "organization_id": organization_id,
            "domain_id": domain_id,
            "challenge_id": challenge_id,
            "event_type": event_type,
            "outcome": outcome,
            "reason_code": reason_code,
            "context": json.dumps(context or {}, separators=(",", ":"), sort_keys=True),
        },
    )


def build_domain_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/organizations/{organization_id}/domains", tags=["domains"])

    @router.post("", response_model=DomainResponse, status_code=201)
    def create_domain(
        organization_id: UUID,
        body: DomainCreate,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> DomainResponse:
        try:
            normalized = normalize_domain(body.domain)
        except DomainValidationError as exc:
            raise AppError(422, exc.reason, "The domain is invalid.") from exc
        domain_id = uuid4()
        try:
            with _database(request).tenant_connection(
                principal.user_id, organization_id
            ) as connection:
                authorize(connection, request, principal, organization_id, Action.DOMAIN_MANAGE)
                row = (
                    connection.execute(
                        text(
                            """
                            INSERT INTO domains (
                                id, organization_id, canonical_name, unicode_display,
                                registrable_domain, warnings, created_by_user_id
                            ) VALUES (
                                :id, :organization_id, :canonical_name, :unicode_display,
                                :registrable_domain, CAST(:warnings AS jsonb), :user_id
                            )
                            RETURNING id, organization_id, canonical_name, unicode_display,
                                registrable_domain, warnings, ownership_state, created_at
                            """
                        ),
                        {
                            "id": domain_id,
                            "organization_id": organization_id,
                            "canonical_name": normalized.canonical_name,
                            "unicode_display": normalized.unicode_display,
                            "registrable_domain": normalized.registrable_domain,
                            "warnings": json.dumps(normalized.warnings),
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
                    action="domain.created",
                    resource_type="domain",
                    resource_id=str(domain_id),
                    request_id=_request_id(request),
                    correlation_id=request.state.correlation_id,
                    outcome="success",
                    context={"warnings": list(normalized.warnings)},
                )
        except IntegrityError as exc:
            raise AppError(409, "domain_exists", "The domain already exists.") from exc
        return domain_response(row)

    @router.get("", response_model=list[DomainResponse])
    def list_domains(
        organization_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> list[DomainResponse]:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.DOMAIN_READ)
            rows = (
                connection.execute(
                    text(
                        "SELECT id, organization_id, canonical_name, unicode_display, "
                        "registrable_domain, warnings, ownership_state, created_at "
                        "FROM domains ORDER BY canonical_name"
                    )
                )
                .mappings()
                .all()
            )
        return [domain_response(row) for row in rows]

    @router.get("/{domain_id}", response_model=DomainResponse)
    def get_domain(
        organization_id: UUID,
        domain_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> DomainResponse:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.DOMAIN_READ)
            row = _domain_row(connection, domain_id)
        if row is None:
            raise AppError(404, "not_found", "The requested resource was not found.")
        return domain_response(row)

    @router.post(
        "/{domain_id}/challenges", response_model=DomainChallengeCreatedResponse, status_code=201
    )
    def create_challenge(
        organization_id: UUID,
        domain_id: UUID,
        body: DomainChallengeCreate,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> DomainChallengeCreatedResponse:
        settings = _settings(request)
        token, digest = new_challenge_token()
        challenge_id = uuid4()
        expires_at = datetime.now(UTC) + timedelta(seconds=settings.domain_challenge_ttl_seconds)
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.DOMAIN_VERIFY)
            domain = _domain_row(connection, domain_id)
            if domain is None:
                raise AppError(404, "not_found", "The requested resource was not found.")
            active = connection.execute(
                text(
                    "SELECT 1 FROM domain_challenges WHERE domain_id = :domain_id "
                    "AND method = :method AND state = 'pending'"
                ),
                {"domain_id": domain_id, "method": body.method},
            ).scalar_one_or_none()
            if active is not None:
                raise AppError(409, "challenge_active", "An active challenge already exists.")
            recent_count = connection.execute(
                text(
                    "SELECT count(*) FROM domain_challenges WHERE domain_id = :domain_id "
                    "AND created_at > now() - interval '1 hour'"
                ),
                {"domain_id": domain_id},
            ).scalar_one()
            if recent_count >= settings.domain_challenge_create_limit_per_hour:
                raise AppError(429, "rate_limited", "Challenge creation is temporarily limited.")
            row = (
                connection.execute(
                    text(
                        """
                        INSERT INTO domain_challenges (
                            id, organization_id, domain_id, method, token_digest,
                            expires_at, created_by_user_id
                        ) VALUES (
                            :id, :organization_id, :domain_id, :method, :token_digest,
                            :expires_at, :user_id
                        ) RETURNING id, domain_id, method, state, attempts, max_attempts, expires_at
                        """
                    ),
                    {
                        "id": challenge_id,
                        "organization_id": organization_id,
                        "domain_id": domain_id,
                        "method": body.method,
                        "token_digest": digest,
                        "expires_at": expires_at,
                        "user_id": principal.user_id,
                    },
                )
                .mappings()
                .one()
            )
            response_row = {**row, "canonical_name": domain["canonical_name"]}
            _record_verification_event(
                connection,
                organization_id=organization_id,
                domain_id=domain_id,
                challenge_id=challenge_id,
                event_type="challenge_created",
                outcome="success",
                reason_code="created",
                context={"method": body.method},
            )
            append_audit_event(
                connection,
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(principal.user_id),
                action="domain.challenge_created",
                resource_type="domain_challenge",
                resource_id=str(challenge_id),
                request_id=_request_id(request),
                correlation_id=request.state.correlation_id,
                outcome="success",
                context={"domain_id": str(domain_id), "method": body.method},
            )
        response = challenge_response(response_row)
        return DomainChallengeCreatedResponse(**response.model_dump(), verification_token=token)

    @router.delete("/{domain_id}/challenges/{challenge_id}", status_code=204)
    def revoke_challenge(
        organization_id: UUID,
        domain_id: UUID,
        challenge_id: UUID,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> Response:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.DOMAIN_VERIFY)
            row = (
                connection.execute(
                    text(
                        "SELECT state FROM domain_challenges "
                        "WHERE id = :challenge_id AND domain_id = :domain_id FOR UPDATE"
                    ),
                    {"challenge_id": challenge_id, "domain_id": domain_id},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise AppError(404, "not_found", "The requested resource was not found.")
            if row["state"] != "pending":
                raise AppError(409, "challenge_inactive", "The challenge is no longer active.")
            connection.execute(
                text(
                    "UPDATE domain_challenges SET state = 'revoked', revoked_at = now() "
                    "WHERE id = :challenge_id"
                ),
                {"challenge_id": challenge_id},
            )
            _record_verification_event(
                connection,
                organization_id=organization_id,
                domain_id=domain_id,
                challenge_id=challenge_id,
                event_type="challenge_revoked",
                outcome="success",
                reason_code="revoked",
            )
            append_audit_event(
                connection,
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(principal.user_id),
                action="domain.challenge_revoked",
                resource_type="domain_challenge",
                resource_id=str(challenge_id),
                request_id=_request_id(request),
                correlation_id=request.state.correlation_id,
                outcome="success",
                context={"domain_id": str(domain_id)},
            )
        return Response(status_code=204)

    @router.post("/{domain_id}/challenges/{challenge_id}/verify", response_model=DomainResponse)
    def verify_challenge(
        organization_id: UUID,
        domain_id: UUID,
        challenge_id: UUID,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> DomainResponse:
        failure: AppError | None = None
        result = None
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.DOMAIN_VERIFY)
            challenge = (
                connection.execute(
                    text(
                        """
                        SELECT c.id, c.domain_id, c.method, c.state, c.token_digest,
                            c.attempts, c.max_attempts, c.expires_at, d.canonical_name
                        FROM domain_challenges c JOIN domains d ON d.id = c.domain_id
                        WHERE c.id = :challenge_id AND c.domain_id = :domain_id
                        FOR UPDATE OF c, d
                        """
                    ),
                    {"challenge_id": challenge_id, "domain_id": domain_id},
                )
                .mappings()
                .one_or_none()
            )
            if challenge is None:
                raise AppError(404, "not_found", "The requested resource was not found.")
            if challenge["state"] != "pending":
                raise AppError(409, "challenge_inactive", "The challenge is no longer active.")
            if challenge["expires_at"] <= datetime.now(UTC):
                connection.execute(
                    text("UPDATE domain_challenges SET state = 'expired' WHERE id = :id"),
                    {"id": challenge_id},
                )
                connection.execute(
                    text(
                        "UPDATE domains SET ownership_state = 'expired', updated_at = now() "
                        "WHERE id = :domain_id"
                    ),
                    {"domain_id": domain_id},
                )
                _record_verification_event(
                    connection,
                    organization_id=organization_id,
                    domain_id=domain_id,
                    challenge_id=challenge_id,
                    event_type="challenge_expired",
                    outcome="failure",
                    reason_code="expired",
                )
                append_audit_event(
                    connection,
                    organization_id=organization_id,
                    actor_type="user",
                    actor_id=str(principal.user_id),
                    action="domain.verification_attempted",
                    resource_type="domain_challenge",
                    resource_id=str(challenge_id),
                    request_id=_request_id(request),
                    correlation_id=request.state.correlation_id,
                    outcome="failure",
                    context={
                        "domain_id": str(domain_id),
                        "method": challenge["method"],
                        "reason_code": "expired",
                    },
                )
                failure = AppError(410, "challenge_expired", "The challenge has expired.")
            elif challenge["method"] in {"dns_txt", "https_file"}:
                reason_code = "token_not_found"
                resolver = cast(TXTResolver, request.app.state.txt_resolver)
                if challenge["method"] == "dns_txt":
                    matched = DNSVerificationService(resolver).verify(
                        challenge["canonical_name"], challenge["token_digest"]
                    )
                else:
                    broker_factory = cast(
                        NetworkBrokerFactory, request.app.state.network_broker_factory
                    )
                    outcome = HTTPSVerificationService(broker_factory).verify(
                        connection,
                        organization_id=organization_id,
                        domain_id=domain_id,
                        challenge_id=challenge_id,
                        canonical_host=challenge["canonical_name"],
                        expected_digest=challenge["token_digest"],
                    )
                    matched = outcome.matched
                    reason_code = outcome.reason_code
                if reason_code in {"emergency_control_active", "authorization_revoked"}:
                    _record_verification_event(
                        connection,
                        organization_id=organization_id,
                        domain_id=domain_id,
                        challenge_id=challenge_id,
                        event_type="verification_denied",
                        outcome="denied",
                        reason_code=reason_code,
                        context={"method": challenge["method"]},
                    )
                    failure = AppError(
                        409, reason_code, "Verification is disabled by current security policy."
                    )
                elif matched:
                    connection.execute(
                        text(
                            "UPDATE domain_challenges SET state = 'verified', verified_at = now(), "
                            "last_attempt_at = now() WHERE id = :id"
                        ),
                        {"id": challenge_id},
                    )
                    connection.execute(
                        text(
                            "UPDATE domains SET ownership_state = 'verified', verified_at = now(), "
                            "reverification_due_at = now() + (:days * interval '1 day'), "
                            "revoked_at = NULL, updated_at = now() WHERE id = :domain_id"
                        ),
                        {
                            "domain_id": domain_id,
                            "days": _settings(request).domain_reverification_days,
                        },
                    )
                    _record_verification_event(
                        connection,
                        organization_id=organization_id,
                        domain_id=domain_id,
                        challenge_id=challenge_id,
                        event_type="ownership_verified",
                        outcome="success",
                        reason_code="token_matched",
                        context={"method": challenge["method"]},
                    )
                    append_audit_event(
                        connection,
                        organization_id=organization_id,
                        actor_type="user",
                        actor_id=str(principal.user_id),
                        action="domain.ownership_verified",
                        resource_type="domain",
                        resource_id=str(domain_id),
                        request_id=_request_id(request),
                        correlation_id=request.state.correlation_id,
                        outcome="success",
                        context={
                            "method": challenge["method"],
                            "challenge_id": str(challenge_id),
                        },
                    )
                    result = _domain_row(connection, domain_id)
                else:
                    attempts = challenge["attempts"] + 1
                    terminal = attempts >= challenge["max_attempts"]
                    connection.execute(
                        text(
                            "UPDATE domain_challenges SET attempts = :attempts, "
                            "last_attempt_at = now(), state = :state WHERE id = :id"
                        ),
                        {
                            "attempts": attempts,
                            "state": "failed" if terminal else "pending",
                            "id": challenge_id,
                        },
                    )
                    if terminal:
                        connection.execute(
                            text(
                                "UPDATE domains SET ownership_state = 'failed', updated_at = now() "
                                "WHERE id = :domain_id"
                            ),
                            {"domain_id": domain_id},
                        )
                    _record_verification_event(
                        connection,
                        organization_id=organization_id,
                        domain_id=domain_id,
                        challenge_id=challenge_id,
                        event_type="verification_attempted",
                        outcome="failure",
                        reason_code=reason_code,
                        context={"method": challenge["method"]},
                    )
                    append_audit_event(
                        connection,
                        organization_id=organization_id,
                        actor_type="user",
                        actor_id=str(principal.user_id),
                        action="domain.verification_attempted",
                        resource_type="domain_challenge",
                        resource_id=str(challenge_id),
                        request_id=_request_id(request),
                        correlation_id=request.state.correlation_id,
                        outcome="failure",
                        context={
                            "domain_id": str(domain_id),
                            "method": challenge["method"],
                            "reason_code": reason_code,
                            "attempts_remaining": max(0, challenge["max_attempts"] - attempts),
                        },
                    )
                    failure = AppError(
                        409,
                        "challenge_not_verified",
                        "The verification value was not found.",
                    )
            else:
                failure = AppError(
                    409,
                    "verification_method_unavailable",
                    "The verification method is unavailable.",
                )
        if failure is not None:
            raise failure
        if result is None:
            raise AppError(500, "internal_error", "The request could not be completed.")
        return domain_response(result)

    return router
