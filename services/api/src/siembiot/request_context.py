from __future__ import annotations

import re
import secrets

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_request_id() -> str:
    return "".join(secrets.choice(CROCKFORD) for _ in range(26))


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        supplied = request.headers.get("X-Request-ID", "")
        request_id = supplied if ULID_RE.fullmatch(supplied) else new_request_id()
        request.state.request_id = request_id
        request.state.correlation_id = request_id
        response = await call_next(request)
        if getattr(request.state, "clear_session_cookie", False):
            response.delete_cookie(
                "__Host-siembiot_session",
                path="/",
                secure=True,
                httponly=True,
                samesite="lax",
            )
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response
