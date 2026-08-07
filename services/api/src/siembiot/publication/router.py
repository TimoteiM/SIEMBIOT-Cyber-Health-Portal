"""Consenting to publication, and withdrawing that consent.

Two endpoints, and the asymmetry between them is the design.

Granting consent publishes nothing. It records that an organization is willing, and the
profile appears only when the projector next runs -- which requires a completed
assessment, verified control, and a recorded privacy review. Consent is a precondition,
not a trigger, so nobody can put their own institution on a public page by clicking once.

Withdrawing consent removes the published profile immediately, in the same transaction
that records the withdrawal. Not a flag for a reader to respect: the row is deleted.
A flag survives in every cache, every replica and every query written afterwards by
somebody who did not know to check it, and "we marked it hidden" is not an answer to
"why is our data still on your website".

The two directions are also separated in the grants: this service can delete a published
profile and cannot create one.
"""

from __future__ import annotations

from typing import cast
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy import Connection, text

from siembiot.audit import append_audit_event
from siembiot.auth import current_principal, require_trusted_origin
from siembiot.authorization import Action
from siembiot.contracts import ConsentResponse, ConsentWithdrawal
from siembiot.db import Database
from siembiot.errors import AppError
from siembiot.identity import Principal
from siembiot.organizations import authorize


def _database(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def _domain(connection: Connection, organization_id: UUID, domain_id: UUID) -> dict[str, str]:
    row = (
        connection.execute(
            text(
                "SELECT registrable_domain, ownership_state FROM domains "
                "WHERE id = :domain_id AND organization_id = :organization_id"
            ),
            {"domain_id": domain_id, "organization_id": organization_id},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise AppError(404, "not_found", "The requested resource was not found.")
    return {
        "registrable_domain": str(row["registrable_domain"]),
        "ownership_state": str(row["ownership_state"]),
    }


def _state(connection: Connection, domain_id: UUID, registrable_domain: str) -> ConsentResponse:
    consent = (
        connection.execute(
            text(
                "SELECT granted_at FROM publication_consents "
                "WHERE domain_id = :domain_id AND revoked_at IS NULL"
            ),
            {"domain_id": domain_id},
        )
        .mappings()
        .one_or_none()
    )
    published = connection.execute(
        text(
            "SELECT published_at FROM observatory.profiles "
            "WHERE registrable_domain = :registrable_domain"
        ),
        {"registrable_domain": registrable_domain},
    ).scalar_one_or_none()

    return ConsentResponse(
        domain_id=domain_id,
        consented=consent is not None,
        granted_at=consent["granted_at"] if consent else None,
        # Reported separately from consent rather than inferred from it. Consent is
        # permission; this is whether anything is actually on a public page right now,
        # and somebody asking "are we published" is asking the second question.
        published_at=published,
    )


def build_publication_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/organizations", tags=["publication"])

    @router.get(
        "/{organization_id}/domains/{domain_id}/publication",
        response_model=ConsentResponse,
    )
    def show(
        organization_id: UUID,
        domain_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> ConsentResponse:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.DOMAIN_READ)
            domain = _domain(connection, organization_id, domain_id)
            return _state(connection, domain_id, domain["registrable_domain"])

    @router.put(
        "/{organization_id}/domains/{domain_id}/publication",
        response_model=ConsentResponse,
    )
    def grant(
        organization_id: UUID,
        domain_id: UUID,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> ConsentResponse:
        """Agree to publication. Publishes nothing by itself.

        Held at `DOMAIN_MANAGE` rather than a reporting permission: this decides what
        the world sees about the institution, which is the same weight of decision as
        deciding what may be assessed.
        """
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.DOMAIN_MANAGE)
            domain = _domain(connection, organization_id, domain_id)

            # Refused here as well as in the projector. The projector's check is the one
            # that protects the public page; this one exists so that somebody consenting
            # is told immediately, rather than agreeing and then silently never appearing.
            if domain["ownership_state"] != "verified":
                raise AppError(
                    422,
                    "ownership_not_verified",
                    "Publishing a profile requires verified control of the domain.",
                )

            connection.execute(
                text(
                    """
                    INSERT INTO publication_consents (
                        organization_id, domain_id, granted_by_user_id
                    ) VALUES (:organization_id, :domain_id, :actor)
                    ON CONFLICT (domain_id) WHERE revoked_at IS NULL DO NOTHING
                    """
                ),
                {
                    "organization_id": organization_id,
                    "domain_id": domain_id,
                    "actor": principal.user_id,
                },
            )

            append_audit_event(
                connection,
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(principal.user_id),
                action="publication.consent_granted",
                resource_type="domain",
                resource_id=str(domain_id),
                request_id=cast(str, request.state.request_id),
                correlation_id=request.state.correlation_id,
                outcome="success",
                context={"registrable_domain": domain["registrable_domain"]},
            )
            return _state(connection, domain_id, domain["registrable_domain"])

    @router.delete(
        "/{organization_id}/domains/{domain_id}/publication",
        response_model=ConsentResponse,
    )
    def withdraw(
        organization_id: UUID,
        domain_id: UUID,
        payload: ConsentWithdrawal,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> ConsentResponse:
        """Withdraw consent and take the profile down in the same transaction.

        The deletion is not scheduled, queued or flagged. If this call returns, the
        profile is gone -- which is the only version of this promise that can be made
        honestly, because anything asynchronous has a window during which the answer to
        "is our data still public" is yes.
        """
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.DOMAIN_MANAGE)
            domain = _domain(connection, organization_id, domain_id)

            connection.execute(
                text(
                    """
                    UPDATE publication_consents
                    SET revoked_at = now(),
                        revoked_by_user_id = :actor,
                        revocation_reason = :reason
                    WHERE domain_id = :domain_id AND revoked_at IS NULL
                    """
                ),
                {
                    "domain_id": domain_id,
                    "actor": principal.user_id,
                    "reason": payload.reason,
                },
            )

            removed = connection.execute(
                text(
                    "DELETE FROM observatory.profiles "
                    "WHERE registrable_domain = :registrable_domain"
                ),
                {"registrable_domain": domain["registrable_domain"]},
            ).rowcount

            append_audit_event(
                connection,
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(principal.user_id),
                action="publication.consent_withdrawn",
                resource_type="domain",
                resource_id=str(domain_id),
                request_id=cast(str, request.state.request_id),
                correlation_id=request.state.correlation_id,
                outcome="success",
                # Recorded because "we took it down" and "there was nothing to take
                # down" are different answers to give somebody who asks later.
                context={
                    "registrable_domain": domain["registrable_domain"],
                    "profile_removed": str(bool(removed)),
                },
            )
            return _state(connection, domain_id, domain["registrable_domain"])

    return router
