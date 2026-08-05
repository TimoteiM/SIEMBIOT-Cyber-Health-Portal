"""The identity boundary.

Authentication is owned by a separate team and happens upstream of this service.
This module is the seam: it turns whatever that upstream layer asserts into a
``Principal``, and refuses to guess when the assertion is absent or unverifiable.

Everything downstream of this seam is unchanged — tenant context, RBAC, object
authorization, row-level security and audit actor attribution all still apply.
Removing authentication does not remove authorization.

Two resolvers ship:

``TrustedGatewayIdentityResolver``
    For real deployments. The authenticating gateway forwards the verified identity
    in headers plus a shared secret proving the request came from the gateway rather
    than from a client that reached the API directly. Without the secret the headers
    are ignored, so identity cannot be spoofed by anyone who can talk to this service.

``DevelopmentIdentityResolver``
    For local work only. Trusts the same headers with no secret, and is refused
    outright unless the environment is ``development``.
"""

from __future__ import annotations

from dataclasses import dataclass
from hmac import compare_digest
from typing import Protocol
from uuid import UUID

from fastapi import Request
from sqlalchemy import Connection, text

from siembiot.errors import AppError

IDENTITY_SUBJECT_HEADER = "X-SIEMBIOT-Identity-Subject"
IDENTITY_ISSUER_HEADER = "X-SIEMBIOT-Identity-Issuer"
IDENTITY_EMAIL_HEADER = "X-SIEMBIOT-Identity-Email"
IDENTITY_NAME_HEADER = "X-SIEMBIOT-Identity-Name"
GATEWAY_PROOF_HEADER = "X-SIEMBIOT-Gateway-Secret"

MAX_SUBJECT_LENGTH = 255
MAX_EMAIL_LENGTH = 320
MAX_NAME_LENGTH = 200


@dataclass(frozen=True)
class Principal:
    """The authenticated actor, as asserted upstream and provisioned locally."""

    user_id: UUID
    email: str
    display_name: str


@dataclass(frozen=True)
class AssertedIdentity:
    """A verified upstream assertion, before it is mapped to a local user."""

    issuer: str
    subject: str
    email: str
    display_name: str


class IdentityResolver(Protocol):
    def resolve(self, request: Request) -> AssertedIdentity | None: ...


def _read_assertion(request: Request) -> AssertedIdentity | None:
    """Parse and bound the identity headers. Anything malformed resolves to nothing."""
    subject = request.headers.get(IDENTITY_SUBJECT_HEADER, "").strip()
    issuer = request.headers.get(IDENTITY_ISSUER_HEADER, "").strip()
    email = request.headers.get(IDENTITY_EMAIL_HEADER, "").strip().lower()
    name = request.headers.get(IDENTITY_NAME_HEADER, "").strip()
    if not subject or not issuer or not email:
        return None
    if len(subject) > MAX_SUBJECT_LENGTH or len(issuer) > MAX_SUBJECT_LENGTH:
        return None
    if len(email) > MAX_EMAIL_LENGTH or "@" not in email:
        return None
    return AssertedIdentity(
        issuer=issuer,
        subject=subject,
        email=email,
        display_name=(name or email)[:MAX_NAME_LENGTH],
    )


class TrustedGatewayIdentityResolver:
    """Accept an identity only when it arrives with the gateway's shared secret."""

    def __init__(self, gateway_secret: str) -> None:
        if len(gateway_secret) < 32:
            raise RuntimeError("SIEMBIOT_IDENTITY_GATEWAY_SECRET must be at least 32 characters")
        self._expected_proof = gateway_secret

    def resolve(self, request: Request) -> AssertedIdentity | None:
        supplied = request.headers.get(GATEWAY_PROOF_HEADER, "")
        if not supplied or not compare_digest(supplied, self._expected_proof):
            return None
        return _read_assertion(request)


class DevelopmentIdentityResolver:
    """Trust the identity headers directly. Local development only."""

    def resolve(self, request: Request) -> AssertedIdentity | None:
        return _read_assertion(request)


class NullIdentityResolver:
    """Assert nothing. Every request is unauthenticated."""

    def resolve(self, request: Request) -> AssertedIdentity | None:
        del request
        return None


def build_identity_resolver(environment: str, gateway_secret: str | None) -> IdentityResolver:
    """Choose a resolver, failing closed outside development.

    A deployment that is not local development must configure the gateway secret.
    Falling back to the development resolver there would turn a header into an
    authentication bypass, so the service refuses to start instead.
    """
    if gateway_secret:
        return TrustedGatewayIdentityResolver(gateway_secret)
    if environment == "development":
        return DevelopmentIdentityResolver()
    raise RuntimeError(
        "SIEMBIOT_IDENTITY_GATEWAY_SECRET is required outside development; "
        "the development identity resolver must never be enabled in a deployed "
        "environment because it would accept an unauthenticated identity header."
    )


def provision_user(connection: Connection, identity: AssertedIdentity) -> Principal:
    """Map an upstream identity to a local user, creating it on first sight.

    The join key stays (issuer, subject) so the same person keeps the same local user
    across logins, and so a change of e-mail address does not fork their account.
    """
    row = (
        connection.execute(
            text(
                """
                INSERT INTO users (identity_issuer, identity_subject, email, display_name)
                VALUES (:issuer, :subject, :email, :display_name)
                ON CONFLICT (identity_issuer, identity_subject) DO UPDATE
                SET email = excluded.email,
                    display_name = excluded.display_name,
                    updated_at = now()
                RETURNING id, email, display_name
                """
            ),
            {
                "issuer": identity.issuer,
                "subject": identity.subject,
                "email": identity.email,
                "display_name": identity.display_name,
            },
        )
        .mappings()
        .one()
    )
    return Principal(user_id=row["id"], email=row["email"], display_name=row["display_name"])


def unauthenticated() -> AppError:
    return AppError(401, "unauthenticated", "Authentication is required.")
