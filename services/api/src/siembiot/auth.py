from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hmac import compare_digest
from typing import cast
from uuid import UUID

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Cookie, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import text

from siembiot.config import Settings
from siembiot.contracts import LogoutResponse, SessionResponse, UserResponse
from siembiot.db import Database
from siembiot.errors import AppError
from siembiot.oidc import OIDCClient

SESSION_COOKIE = "__Host-siembiot_session"


@dataclass(frozen=True)
class Principal:
    session_id: UUID
    user_id: UUID
    email: str
    display_name: str
    expires_at: datetime
    csrf_hash: bytes


def hash_token(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def random_token() -> str:
    return secrets.token_urlsafe(32)


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _database(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def _settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def _oidc(request: Request) -> OIDCClient:
    return cast(OIDCClient, request.app.state.oidc_client)


def _cipher(settings: Settings) -> Fernet:
    if not settings.session_encryption_key:
        raise RuntimeError("SIEMBIOT_SESSION_ENCRYPTION_KEY is required for authentication")
    return Fernet(settings.session_encryption_key.encode("ascii"))


def current_principal(
    request: Request,
    session_secret: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> Principal:
    if not session_secret:
        raise AppError(401, "unauthenticated", "Authentication is required.")
    with _database(request).connection() as connection:
        row = (
            connection.execute(
                text(
                    """
                SELECT s.id, s.user_id, u.email, u.display_name, s.expires_at, s.csrf_hash
                FROM sessions s JOIN users u ON u.id = s.user_id
                WHERE s.secret_hash = :secret_hash
                  AND s.revoked_at IS NULL
                  AND s.expires_at > now()
                """
                ),
                {"secret_hash": hash_token(session_secret)},
            )
            .mappings()
            .one_or_none()
        )
    if row is None:
        raise AppError(401, "unauthenticated", "Authentication is required.")
    return Principal(
        session_id=row["id"],
        user_id=row["user_id"],
        email=row["email"],
        display_name=row["display_name"],
        expires_at=row["expires_at"],
        csrf_hash=row["csrf_hash"],
    )


def require_csrf(
    request: Request,
    principal: Principal = Depends(current_principal),
) -> Principal:
    expected_origin = _settings(request).public_base_url.rstrip("/")
    if request.headers.get("Origin") != expected_origin:
        raise AppError(403, "csrf_rejected", "The request could not be verified.")
    supplied = request.headers.get("X-CSRF-Token", "")
    if not supplied or not compare_digest(hash_token(supplied), principal.csrf_hash):
        raise AppError(403, "csrf_rejected", "The request could not be verified.")
    return principal


def build_auth_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["authentication"])

    @router.get("/auth/login")
    def login(request: Request, return_path: str = "/") -> RedirectResponse:
        if return_path != "/" and (not return_path.startswith("/") or return_path.startswith("//")):
            raise AppError(400, "invalid_return_path", "The return path is invalid.")
        settings = _settings(request)
        state, nonce, verifier = random_token(), random_token(), random_token()
        expires_at = datetime.now(UTC) + timedelta(seconds=settings.oidc_transaction_ttl_seconds)
        with _database(request).connection() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO oidc_login_transactions (
                        state_hash, nonce_hash, pkce_verifier_ciphertext, return_path, expires_at
                    ) VALUES (:state_hash, :nonce_hash, :verifier, :return_path, :expires_at)
                    """
                ),
                {
                    "state_hash": hash_token(state),
                    "nonce_hash": hash_token(nonce),
                    "verifier": _cipher(settings).encrypt(verifier.encode("ascii")),
                    "return_path": return_path,
                    "expires_at": expires_at,
                },
            )
        authorization_url = _oidc(request).authorization_url(
            state=state,
            nonce=nonce,
            code_challenge=pkce_challenge(verifier),
            redirect_uri=settings.callback_url,
        )
        return RedirectResponse(authorization_url, status_code=307)

    @router.get("/auth/callback")
    def callback(request: Request, state: str, code: str) -> RedirectResponse:
        settings = _settings(request)
        with _database(request).connection() as connection:
            transaction = (
                connection.execute(
                    text(
                        """
                    SELECT id, nonce_hash, pkce_verifier_ciphertext, return_path
                    FROM oidc_login_transactions
                    WHERE state_hash = :state_hash AND consumed_at IS NULL AND expires_at > now()
                    FOR UPDATE
                    """
                    ),
                    {"state_hash": hash_token(state)},
                )
                .mappings()
                .one_or_none()
            )
            if transaction is None:
                raise AppError(
                    400, "invalid_oidc_state", "The login request is invalid or expired."
                )
            try:
                verifier = _cipher(settings).decrypt(transaction["pkce_verifier_ciphertext"])
            except InvalidToken as error:
                raise AppError(
                    400, "invalid_oidc_state", "The login request is invalid."
                ) from error
            claims = _oidc(request).exchange_code(
                code=code,
                code_verifier=verifier.decode("ascii"),
                redirect_uri=settings.callback_url,
            )
            if claims.get("iss") != settings.oidc_issuer.rstrip("/"):
                raise AppError(400, "invalid_identity", "The identity response is invalid.")
            nonce = claims.get("nonce")
            if not isinstance(nonce, str) or not compare_digest(
                hash_token(nonce), transaction["nonce_hash"]
            ):
                raise AppError(400, "invalid_identity", "The identity response is invalid.")
            subject, email = claims.get("sub"), claims.get("email")
            if not isinstance(subject, str) or not isinstance(email, str):
                raise AppError(400, "invalid_identity", "The identity response is invalid.")
            name_claim = claims.get("name")
            display_name = name_claim if isinstance(name_claim, str) else email
            user_id = connection.execute(
                text(
                    """
                    INSERT INTO users (oidc_issuer, oidc_subject, email, display_name)
                    VALUES (:issuer, :subject, :email, :display_name)
                    ON CONFLICT (oidc_issuer, oidc_subject) DO UPDATE
                    SET email = excluded.email,
                        display_name = excluded.display_name,
                        updated_at = now()
                    RETURNING id
                    """
                ),
                {
                    "issuer": settings.oidc_issuer.rstrip("/"),
                    "subject": subject,
                    "email": email.lower(),
                    "display_name": display_name[:200],
                },
            ).scalar_one()
            connection.execute(
                text("UPDATE oidc_login_transactions SET consumed_at = now() WHERE id = :id"),
                {"id": transaction["id"]},
            )
            session_secret, csrf_token = random_token(), random_token()
            expires_at = datetime.now(UTC) + timedelta(seconds=settings.session_ttl_seconds)
            connection.execute(
                text(
                    """
                    INSERT INTO sessions (user_id, secret_hash, csrf_hash, expires_at)
                    VALUES (:user_id, :secret_hash, :csrf_hash, :expires_at)
                    """
                ),
                {
                    "user_id": user_id,
                    "secret_hash": hash_token(session_secret),
                    "csrf_hash": hash_token(csrf_token),
                    "expires_at": expires_at,
                },
            )
        response = RedirectResponse(transaction["return_path"], status_code=303)
        response.set_cookie(
            SESSION_COOKIE,
            session_secret,
            max_age=settings.session_ttl_seconds,
            secure=True,
            httponly=True,
            samesite="lax",
            path="/",
        )
        return response

    @router.get("/session", response_model=SessionResponse)
    def session(
        request: Request, principal: Principal = Depends(current_principal)
    ) -> SessionResponse:
        csrf_token = random_token()
        with _database(request).connection() as connection:
            connection.execute(
                text(
                    "UPDATE sessions SET csrf_hash = :csrf_hash, last_seen_at = now() "
                    "WHERE id = :id"
                ),
                {"csrf_hash": hash_token(csrf_token), "id": principal.session_id},
            )
        return SessionResponse(
            user=UserResponse(
                id=principal.user_id,
                email=principal.email,
                display_name=principal.display_name,
            ),
            expires_at=principal.expires_at,
            csrf_token=csrf_token,
        )

    @router.post("/auth/logout", response_model=LogoutResponse)
    def logout(request: Request, principal: Principal = Depends(require_csrf)) -> LogoutResponse:
        with _database(request).connection() as connection:
            connection.execute(
                text(
                    "UPDATE sessions SET revoked_at = now(), revoke_reason = 'user_logout' "
                    "WHERE id = :id"
                ),
                {"id": principal.session_id},
            )
        request.state.clear_session_cookie = True
        return LogoutResponse(
            logout_url=_oidc(request).logout_url(
                post_logout_redirect_uri=_settings(request).public_base_url
            )
        )

    return router
