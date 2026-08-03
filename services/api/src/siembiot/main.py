from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from siembiot.auth import build_auth_router
from siembiot.config import Settings
from siembiot.contracts import ErrorBody, ErrorEnvelope, HealthResponse
from siembiot.db import Database
from siembiot.errors import AppError
from siembiot.oidc import OIDCClient, StandardOIDCClient
from siembiot.organizations import build_invitation_router, build_organization_router
from siembiot.request_context import RequestContextMiddleware, new_request_id


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", new_request_id())


def _error(request: Request, status_code: int, code: str, message: str) -> JSONResponse:
    body = ErrorEnvelope(
        error=ErrorBody(code=code, message=message, request_id=_request_id(request))
    )
    return JSONResponse(status_code=status_code, content=body.model_dump(mode="json"))


def create_app(
    settings: Settings | None = None,
    oidc_client: OIDCClient | None = None,
) -> FastAPI:
    resolved_settings = settings or Settings()
    database = Database(resolved_settings.database_url)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        database.close()

    app = FastAPI(title="SIEMBIOT Private API", version="1.0.0", lifespan=lifespan)
    app.state.settings = resolved_settings
    app.state.database = database
    app.state.oidc_client = oidc_client or StandardOIDCClient(resolved_settings)
    app.add_middleware(RequestContextMiddleware)

    @app.exception_handler(AppError)
    async def app_error(request: Request, exc: AppError) -> JSONResponse:
        return _error(request, exc.status_code, exc.code, exc.message)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = "not_found" if exc.status_code == 404 else "request_rejected"
        message = (
            "The requested resource was not found."
            if exc.status_code == 404
            else "The request was rejected."
        )
        return _error(request, exc.status_code, code, message)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, _: RequestValidationError) -> JSONResponse:
        return _error(request, 422, "validation_error", "The request is invalid.")

    @app.exception_handler(Exception)
    async def internal_error(request: Request, _: Exception) -> JSONResponse:
        return _error(request, 500, "internal_error", "The request could not be completed.")

    @app.get("/api/v1/health", response_model=HealthResponse, tags=["system"])
    def health() -> HealthResponse:
        return HealthResponse()

    app.include_router(build_auth_router())
    app.include_router(build_organization_router())
    app.include_router(build_invitation_router())

    return app


app = create_app()
