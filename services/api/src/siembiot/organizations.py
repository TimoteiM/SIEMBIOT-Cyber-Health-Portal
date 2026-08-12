from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import Connection, text
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import IntegrityError

from siembiot.audit import append_audit_event
from siembiot.auth import current_principal, hash_token, random_token, require_trusted_origin
from siembiot.authorization import Action, Role, is_allowed
from siembiot.contracts import (
    AuditEventResponse,
    InvitationAccept,
    InvitationCreate,
    InvitationCreatedResponse,
    InvitationResponse,
    MembershipResponse,
    MembershipUpdate,
    OrganizationCreate,
    OrganizationResponse,
)
from siembiot.db import Database
from siembiot.errors import AppError
from siembiot.identity import Principal

log = logging.getLogger("siembiot.authorization")


def _request_id(request: Request) -> str:
    return cast(str, request.state.request_id)


def _support_role(connection: Connection, organization_id: UUID) -> str | None:
    """`platform_support` where a live support grant covers this organization.

    Asks the database function that row-level security itself consults, rather than
    re-writing its conditions here. Those conditions are not simple -- the grant must be
    unexpired and unrevoked, and the holder must still be a `platform_admin` with
    phishing-resistant MFA -- and a second copy is a second thing to keep in step. If
    they ever disagreed, the wrong direction is this one saying yes while the policies
    say no: every query would then return nothing and read as an empty organization
    rather than as a refusal.
    """
    covered = connection.execute(
        text("SELECT app_has_support_access(:organization_id)"),
        {"organization_id": organization_id},
    ).scalar_one()
    return Role.PLATFORM_SUPPORT.value if covered else None


def authorize(
    connection: Connection,
    request: Request,
    principal: Principal,
    organization_id: UUID,
    action: Action,
) -> Role:
    role_value = connection.execute(
        text(
            """
            SELECT role FROM memberships
            WHERE organization_id = :organization_id
              AND user_id = :user_id
              AND status = 'active'
            """
        ),
        {"organization_id": organization_id, "user_id": principal.user_id},
    ).scalar_one_or_none()
    if role_value is None:
        # No membership. Platform staff holding a live support grant get here, and row
        # level security has been letting them read this organization's rows since the
        # first migration -- so refusing outright made the capability reachable at one
        # layer and unusable at the other. That is the same shape migration 0016 fixed
        # for *listing* the organizations a grant covers; this is the acting half.
        role_value = _support_role(connection, organization_id)
    if role_value is None:
        raise AppError(403, "forbidden", "The requested operation is not permitted.")
    role = Role(role_value)
    if not is_allowed(role, action):
        _record_denial(request, principal, organization_id, action, role)
        raise AppError(403, "forbidden", "The requested operation is not permitted.")
    return role


def _record_denial(
    request: Request,
    principal: Principal,
    organization_id: UUID,
    action: Action,
    role: Role,
) -> None:
    """Write the refusal on its own connection, so raising does not discard it.

    This used to append to the request's connection and then raise. `engine.begin()`
    rolls back on an exception, so every denied attempt was recorded and thrown away in
    the same breath: a database with fifteen `assessment.queued` rows had zero
    `authorization.denied` rows, and refusals had certainly happened.

    A separate transaction is the whole fix. The audit of a refusal has to outlive the
    refusal, or the trail says only what succeeded -- which is the opposite of what an
    audit trail is for, since the attempts worth investigating are the ones that failed.

    Failure to record is swallowed deliberately. The caller is being denied either way,
    and turning an audit problem into a 500 would tell an attacker they had found
    something more interesting than a refusal.
    """
    database = cast("Database", request.app.state.database)
    try:
        with database.tenant_connection(principal.user_id, organization_id) as audit:
            append_audit_event(
                audit,
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(principal.user_id),
                action="authorization.denied",
                resource_type="organization",
                resource_id=str(organization_id),
                request_id=_request_id(request),
                correlation_id=request.state.correlation_id,
                outcome="denied",
                context={"requested_action": action.value, "role": role.value},
            )
    except Exception:  # noqa: BLE001 - see the docstring
        log.warning("could not record an authorization denial", exc_info=True)


def _organization_response(row: RowMapping) -> OrganizationResponse:
    return OrganizationResponse(
        id=row["id"],
        name=row["name"],
        slug=row["slug"],
        created_at=row["created_at"],
        # Present only where the query establishes it. `RowMapping.get` rather than
        # indexing: the single-organization route selects four columns and would raise.
        role=row.get("role"),
    )


def build_organization_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/organizations", tags=["organizations"])

    @router.post("", response_model=OrganizationResponse, status_code=201)
    def create_organization(
        request: Request,
        body: OrganizationCreate,
        principal: Principal = Depends(require_trusted_origin),
    ) -> OrganizationResponse:
        organization_id = uuid4()
        database: Database = request.app.state.database
        try:
            return _create(request, body, principal, database, organization_id)
        except IntegrityError as exc:
            # The slug is unique across the platform, so this is somebody choosing a name
            # that is taken -- an ordinary thing to do, and until now it surfaced as a 500
            # with a stack trace in the log and "an internal error occurred" on screen.
            # A conflict is the caller's to resolve, and they can only resolve it if they
            # are told which field is at fault.
            raise AppError(
                409, "organization_slug_taken", "That short identifier is already in use."
            ) from exc

    def _create(
        request: Request,
        body: OrganizationCreate,
        principal: Principal,
        database: Database,
        organization_id: UUID,
    ) -> OrganizationResponse:
        with database.tenant_connection(principal.user_id, organization_id) as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO organizations (id, name, slug, created_by_user_id)
                    VALUES (:id, :name, :slug, :user_id)
                    """
                ),
                {
                    "id": organization_id,
                    "name": body.name,
                    "slug": body.slug,
                    "user_id": principal.user_id,
                },
            )
            connection.execute(
                text(
                    """
                    INSERT INTO memberships (organization_id, user_id, role, status)
                    VALUES (:organization_id, :user_id, 'organization_owner', 'active')
                    """
                ),
                {"organization_id": organization_id, "user_id": principal.user_id},
            )
            row = (
                connection.execute(
                    text(
                        "SELECT id, name, slug, created_at FROM organizations "
                        "WHERE id = :organization_id"
                    ),
                    {"organization_id": organization_id},
                )
                .mappings()
                .one()
            )
            append_audit_event(
                connection,
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(principal.user_id),
                action="organization.created",
                resource_type="organization",
                resource_id=str(organization_id),
                request_id=_request_id(request),
                correlation_id=request.state.correlation_id,
                outcome="success",
                context={},
            )
        return _organization_response(row)

    @router.get("", response_model=list[OrganizationResponse])
    def list_organizations(
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> list[OrganizationResponse]:
        database: Database = request.app.state.database
        with database.user_connection(principal.user_id) as connection:
            rows = (
                connection.execute(
                    text("SELECT id, name, slug, created_at, role FROM app_list_my_organizations()")
                )
                .mappings()
                .all()
            )
        return [_organization_response(row) for row in rows]

    @router.get("/{organization_id}", response_model=OrganizationResponse)
    def get_organization(
        organization_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> OrganizationResponse:
        database: Database = request.app.state.database
        with database.tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.ORGANIZATION_READ)
            row = (
                connection.execute(
                    text(
                        "SELECT id, name, slug, created_at FROM organizations "
                        "WHERE id = :organization_id"
                    ),
                    {"organization_id": organization_id},
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise AppError(404, "not_found", "The requested resource was not found.")
        return _organization_response(row)

    @router.patch(
        "/{organization_id}/memberships/{membership_id}", response_model=MembershipResponse
    )
    def change_membership(
        organization_id: UUID,
        membership_id: UUID,
        body: MembershipUpdate,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> MembershipResponse:
        database: Database = request.app.state.database
        with database.tenant_connection(principal.user_id, organization_id) as connection:
            caller_role = authorize(
                connection, request, principal, organization_id, Action.MEMBERSHIP_CHANGE
            )
            target = (
                connection.execute(
                    text(
                        """
                    SELECT id, organization_id, user_id, role, status, created_at
                    FROM memberships
                    WHERE id = :membership_id AND organization_id = :organization_id
                    """
                    ),
                    {"membership_id": membership_id, "organization_id": organization_id},
                )
                .mappings()
                .one_or_none()
            )
            if target is None:
                raise AppError(404, "not_found", "The requested resource was not found.")
            if (
                body.role == Role.ORGANIZATION_OWNER.value
                and caller_role != Role.ORGANIZATION_OWNER
            ):
                raise AppError(403, "forbidden", "The requested operation is not permitted.")
            row = (
                connection.execute(
                    text(
                        """
                    UPDATE memberships SET role = :role
                    WHERE id = :membership_id AND organization_id = :organization_id
                    RETURNING id, organization_id, user_id, role, status, created_at
                    """
                    ),
                    {
                        "role": body.role,
                        "membership_id": membership_id,
                        "organization_id": organization_id,
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
                action="membership.role_changed",
                resource_type="membership",
                resource_id=str(membership_id),
                request_id=_request_id(request),
                correlation_id=request.state.correlation_id,
                outcome="success",
                context={"new_role": body.role},
            )
        return MembershipResponse(**row)

    @router.get("/{organization_id}/memberships", response_model=list[MembershipResponse])
    def list_memberships(
        organization_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> list[MembershipResponse]:
        database: Database = request.app.state.database
        with database.tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.MEMBERSHIP_READ)
            rows = (
                connection.execute(
                    text(
                        """
                    SELECT id, organization_id, user_id, role, status, created_at
                    FROM memberships WHERE organization_id = :organization_id
                    ORDER BY created_at, id
                    """
                    ),
                    {"organization_id": organization_id},
                )
                .mappings()
                .all()
            )
        return [MembershipResponse(**row) for row in rows]

    @router.delete(
        "/{organization_id}/memberships/{membership_id}",
        status_code=204,
        response_class=Response,
    )
    def revoke_membership(
        organization_id: UUID,
        membership_id: UUID,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> Response:
        database: Database = request.app.state.database
        with database.tenant_connection(principal.user_id, organization_id) as connection:
            caller_role = authorize(
                connection, request, principal, organization_id, Action.MEMBERSHIP_REVOKE
            )
            target = (
                connection.execute(
                    text(
                        "SELECT user_id, role, status FROM memberships "
                        "WHERE id = :id AND organization_id = :organization_id"
                    ),
                    {"id": membership_id, "organization_id": organization_id},
                )
                .mappings()
                .one_or_none()
            )
            if target is None:
                raise AppError(404, "not_found", "The requested resource was not found.")
            if target["role"] == Role.ORGANIZATION_OWNER:
                owner_count = connection.execute(
                    text(
                        "SELECT count(*) FROM memberships WHERE organization_id = :organization_id "
                        "AND role = 'organization_owner' AND status = 'active'"
                    ),
                    {"organization_id": organization_id},
                ).scalar_one()
                if caller_role != Role.ORGANIZATION_OWNER or owner_count <= 1:
                    raise AppError(409, "owner_required", "The organization must retain an owner.")
            connection.execute(
                text(
                    "UPDATE memberships SET status = 'revoked', revoked_at = now() "
                    "WHERE id = :id AND organization_id = :organization_id"
                ),
                {"id": membership_id, "organization_id": organization_id},
            )
            append_audit_event(
                connection,
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(principal.user_id),
                action="membership.revoked",
                resource_type="membership",
                resource_id=str(membership_id),
                request_id=_request_id(request),
                correlation_id=request.state.correlation_id,
                outcome="success",
                context={},
            )
        return Response(status_code=204)

    @router.post(
        "/{organization_id}/invitations",
        response_model=InvitationCreatedResponse,
        status_code=201,
    )
    def create_invitation(
        organization_id: UUID,
        body: InvitationCreate,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> InvitationCreatedResponse:
        database: Database = request.app.state.database
        token = random_token()
        invitation_id = uuid4()
        expires_at = datetime.now(UTC) + timedelta(days=7)
        try:
            with database.tenant_connection(principal.user_id, organization_id) as connection:
                caller_role = authorize(
                    connection, request, principal, organization_id, Action.MEMBERSHIP_INVITE
                )
                if (
                    body.role == Role.ORGANIZATION_OWNER.value
                    and caller_role != Role.ORGANIZATION_OWNER
                ):
                    raise AppError(403, "forbidden", "The requested operation is not permitted.")
                row = (
                    connection.execute(
                        text(
                            """
                        INSERT INTO invitations (
                            id, organization_id, email, role, token_hash,
                            invited_by_user_id, expires_at
                        ) VALUES (
                            :id, :organization_id, :email, :role, :token_hash, :user_id, :expires_at
                        ) RETURNING id, organization_id, email, role, status, expires_at, created_at
                        """
                        ),
                        {
                            "id": invitation_id,
                            "organization_id": organization_id,
                            "email": body.email.lower(),
                            "role": body.role,
                            "token_hash": hash_token(token),
                            "user_id": principal.user_id,
                            "expires_at": expires_at,
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
                    action="membership.invited",
                    resource_type="invitation",
                    resource_id=str(invitation_id),
                    request_id=_request_id(request),
                    correlation_id=request.state.correlation_id,
                    outcome="success",
                    context={"role": body.role},
                )
        except IntegrityError as error:
            raise AppError(
                409, "invitation_exists", "A pending invitation already exists."
            ) from error
        return InvitationCreatedResponse(**row, acceptance_token=token)

    @router.get("/{organization_id}/audit-events", response_model=list[AuditEventResponse])
    def list_audit_events(
        organization_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
        limit: int = 50,
    ) -> list[AuditEventResponse]:
        bounded_limit = min(max(limit, 1), 100)
        database: Database = request.app.state.database
        with database.tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.AUDIT_READ)
            rows = (
                connection.execute(
                    text(
                        """
                    SELECT id, organization_id, actor_type, actor_id, action, resource_type,
                           resource_id, request_id, correlation_id, occurred_at, outcome, context
                    FROM audit_events WHERE organization_id = :organization_id
                    ORDER BY occurred_at DESC, id DESC LIMIT :limit
                    """
                    ),
                    {"organization_id": organization_id, "limit": bounded_limit},
                )
                .mappings()
                .all()
            )
        return [
            AuditEventResponse(
                id=row["id"],
                organization_id=row["organization_id"],
                actor={"type": row["actor_type"], "id": row["actor_id"]},
                action=row["action"],
                resource={"type": row["resource_type"], "id": row["resource_id"]},
                request_id=row["request_id"],
                correlation_id=row["correlation_id"],
                occurred_at=row["occurred_at"],
                outcome=row["outcome"],
                context=row["context"],
            )
            for row in rows
        ]

    return router


def build_invitation_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/invitations", tags=["invitations"])

    @router.post("/accept", response_model=InvitationResponse)
    def accept_invitation(
        body: InvitationAccept,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> InvitationResponse:
        database: Database = request.app.state.database
        try:
            with database.user_connection(principal.user_id) as connection:
                invitation = (
                    connection.execute(
                        text(
                            """
                        SELECT id, organization_id, email, role, status, expires_at, created_at
                        FROM invitations
                        WHERE token_hash = :token_hash AND status = 'pending' AND expires_at > now()
                        FOR UPDATE
                        """
                        ),
                        {"token_hash": hash_token(body.token)},
                    )
                    .mappings()
                    .one_or_none()
                )
                if invitation is None or invitation["email"].lower() != principal.email.lower():
                    raise AppError(404, "not_found", "The invitation is invalid or expired.")
                organization_id = invitation["organization_id"]
                connection.execute(
                    text("SELECT set_config('app.organization_id', :organization_id, true)"),
                    {"organization_id": str(organization_id)},
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO memberships (organization_id, user_id, role, status)
                        VALUES (:organization_id, :user_id, :role, 'active')
                        """
                    ),
                    {
                        "organization_id": organization_id,
                        "user_id": principal.user_id,
                        "role": invitation["role"],
                    },
                )
                row = (
                    connection.execute(
                        text(
                            """
                        UPDATE invitations SET status = 'accepted', accepted_by_user_id = :user_id,
                            consumed_at = now()
                        WHERE id = :id
                        RETURNING id, organization_id, email, role, status, expires_at, created_at
                        """
                        ),
                        {"user_id": principal.user_id, "id": invitation["id"]},
                    )
                    .mappings()
                    .one()
                )
                append_audit_event(
                    connection,
                    organization_id=organization_id,
                    actor_type="user",
                    actor_id=str(principal.user_id),
                    action="membership.invitation_accepted",
                    resource_type="invitation",
                    resource_id=str(invitation["id"]),
                    request_id=_request_id(request),
                    correlation_id=request.state.correlation_id,
                    outcome="success",
                    context={"role": invitation["role"]},
                )
        except IntegrityError as error:
            raise AppError(409, "membership_exists", "Membership already exists.") from error
        return InvitationResponse(**row)

    return router
