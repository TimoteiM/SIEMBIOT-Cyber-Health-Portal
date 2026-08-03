from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from siembiot.contracts import ErrorBody, ErrorEnvelope, HealthResponse
from siembiot.request_context import RequestContextMiddleware, new_request_id


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", new_request_id())


def _error(request: Request, status_code: int, code: str, message: str) -> JSONResponse:
    body = ErrorEnvelope(
        error=ErrorBody(code=code, message=message, request_id=_request_id(request))
    )
    return JSONResponse(status_code=status_code, content=body.model_dump(mode="json"))


def create_app() -> FastAPI:
    app = FastAPI(title="SIEMBIOT Private API", version="1.0.0")
    app.add_middleware(RequestContextMiddleware)

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

    return app


app = create_app()
