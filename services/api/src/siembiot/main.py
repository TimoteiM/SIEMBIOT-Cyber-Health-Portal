from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from siembiot.assessments import build_assessment_router, build_asset_router
from siembiot.auth import build_auth_router
from siembiot.config import Settings
from siembiot.contracts import ErrorBody, ErrorEnvelope, HealthResponse
from siembiot.db import Database
from siembiot.domains.authorization_router import build_authorization_router
from siembiot.domains.dns_verification import BoundedTXTResolver, TXTResolver
from siembiot.domains.emergency import build_emergency_router, build_global_emergency_router
from siembiot.domains.network_adapter import (
    NetworkBrokerFactory,
    default_network_broker_factory,
)
from siembiot.domains.router import build_domain_router
from siembiot.domains.signing import (
    Ed25519ManifestSigner,
    ManifestSigner,
    ensure_signer_allowed,
)
from siembiot.errors import AppError
from siembiot.findings import build_findings_router
from siembiot.identity import IdentityResolver, build_identity_resolver
from siembiot.organizations import build_invitation_router, build_organization_router
from siembiot.request_context import RequestContextMiddleware, new_request_id
from siembiot.schedules import build_schedule_router


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", new_request_id())


def _error(request: Request, status_code: int, code: str, message: str) -> JSONResponse:
    body = ErrorEnvelope(
        error=ErrorBody(code=code, message=message, request_id=_request_id(request))
    )
    return JSONResponse(status_code=status_code, content=body.model_dump(mode="json"))


def create_app(
    settings: Settings | None = None,
    identity_resolver: IdentityResolver | None = None,
    txt_resolver: TXTResolver | None = None,
    manifest_signer: ManifestSigner | None = None,
    network_broker_factory: NetworkBrokerFactory | None = None,
) -> FastAPI:
    resolved_settings = settings or Settings()
    database = Database(resolved_settings.app_database_url)
    resolved_signer = manifest_signer or Ed25519ManifestSigner.generate(
        "dev-ephemeral", development_only=True
    )
    ensure_signer_allowed(resolved_settings.environment, resolved_signer)
    # Fails closed: outside development an unconfigured gateway secret raises here
    # rather than letting a plain header authenticate a request.
    resolved_identity_resolver = identity_resolver or build_identity_resolver(
        resolved_settings.environment, resolved_settings.identity_gateway_secret
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        # Checked at startup rather than per request: a role that bypasses row-level
        # security disables tenant isolation without any query failing, so there is no
        # later moment at which the problem announces itself. Refusing to serve is the
        # only outcome that cannot be missed.
        database.verify_least_privilege()
        yield
        database.close()

    app = FastAPI(title="SIEMBIOT Private API", version="1.0.0", lifespan=lifespan)
    app.state.settings = resolved_settings
    app.state.database = database
    app.state.identity_resolver = resolved_identity_resolver
    app.state.txt_resolver = txt_resolver or BoundedTXTResolver()
    app.state.manifest_signer = resolved_signer
    app.state.network_broker_factory = network_broker_factory or default_network_broker_factory
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
    app.include_router(build_domain_router())
    app.include_router(build_authorization_router())
    app.include_router(build_emergency_router())
    app.include_router(build_global_emergency_router())
    app.include_router(build_assessment_router())
    app.include_router(build_asset_router())
    app.include_router(build_findings_router())
    app.include_router(build_schedule_router())

    return app


app = create_app()
