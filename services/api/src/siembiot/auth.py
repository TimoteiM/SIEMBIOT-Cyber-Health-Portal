"""Request-level access control.

Authentication itself lives upstream and enters through ``siembiot.identity``. What
remains here is what this service still owns regardless of who authenticates: turning
an asserted identity into a local principal, and refusing cross-origin state changes.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from typing import cast

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text

from siembiot.config import Settings
from siembiot.contracts import SessionResponse, UserResponse
from siembiot.db import Database
from siembiot.errors import AppError
from siembiot.identity import IdentityResolver, Principal, provision_user, unauthenticated

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

log = logging.getLogger("siembiot.api")


def hash_token(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def random_token() -> str:
    return secrets.token_urlsafe(32)


def _database(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def _settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def _resolver(request: Request) -> IdentityResolver:
    return cast(IdentityResolver, request.app.state.identity_resolver)


def current_principal(request: Request) -> Principal:
    """Resolve the caller, provisioning the local user on first sight."""
    identity = _resolver(request).resolve(request)
    if identity is None:
        raise unauthenticated()
    with _database(request).connection() as connection:
        return provision_user(connection, identity)


def require_trusted_origin(
    request: Request,
    principal: Principal = Depends(current_principal),
) -> Principal:
    """Reject a state change that did not originate from this application.

    Token-based CSRF belongs to whoever issues the session cookie, which is now the
    upstream authentication layer. A strict origin check remains this service's job
    and costs nothing, so it stays.
    """
    if request.method in SAFE_METHODS:
        return principal
    expected = _settings(request).public_base_url.rstrip("/")
    supplied = request.headers.get("Origin")
    if supplied != expected:
        # Logged, not returned. The response stays deliberately uninformative -- telling
        # a caller which origin would be accepted is telling an attacker what to forge --
        # but the server knows exactly why it refused, and saying nothing anywhere turns
        # a misconfiguration into a mystery.
        #
        # It is worth a warning rather than a debug line because of how this fails: every
        # read works and every write is refused, so the application looks alive and
        # subtly broken. The usual cause is `SIEMBIOT_PUBLIC_BASE_URL` disagreeing with
        # where the interface is actually served -- most often on scheme, because the
        # development server runs HTTPS and the production-like stack has no TLS
        # termination and serves plain HTTP.
        log.warning(
            "origin rejected: expected %r, received %r. Set SIEMBIOT_PUBLIC_BASE_URL to "
            "the scheme, host and port the interface is served on.",
            expected,
            supplied,
        )
        raise AppError(403, "origin_rejected", "The request could not be verified.")
    return principal


def build_auth_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["identity"])

    @router.get("/session", response_model=SessionResponse)
    def session(
        request: Request, principal: Principal = Depends(current_principal)
    ) -> SessionResponse:
        """Report who the upstream authentication layer says the caller is."""
        with _database(request).connection() as connection:
            connection.execute(
                text("UPDATE users SET last_seen_at = now() WHERE id = :id"),
                {"id": principal.user_id},
            )
        return SessionResponse(
            user=UserResponse(
                id=principal.user_id,
                email=principal.email,
                display_name=principal.display_name,
            )
        )

    return router
