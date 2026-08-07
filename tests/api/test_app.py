"""Contract shape of the application itself: health, errors, and the OpenAPI document.

These take the database fixture even though none of them reads a row. Startup verifies
that the API is connected as a role row-level security applies to, so an app that comes
up at all has proved something about its configuration -- and a test that skipped the
fixture would pass or fail depending on whatever happened to be listening on the
developer's machine, which is how these three came to depend on the dev stack being up.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from siembiot.config import Settings
from siembiot.main import create_app


def app_for(postgres_database: dict[str, str]) -> TestClient:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        environment="development",
        app_database_url=postgres_database["app_url"].replace(
            "postgresql://", "postgresql+psycopg://"
        ),
    )
    return TestClient(create_app(settings))


def test_health_is_typed_private_and_correlated(postgres_database: dict[str, str]) -> None:
    with app_for(postgres_database) as client:
        response = client.get("/api/v1/health", headers={"X-Request-ID": "not-a-valid-ulid"})

    assert response.status_code == 200
    assert response.json() == {"contract_version": "v1", "status": "ok"}
    assert response.headers["Cache-Control"] == "no-store"
    # A caller-supplied request id that is not a ULID is replaced rather than echoed,
    # so an identifier in a log is always one this service issued.
    assert len(response.headers["X-Request-ID"]) == 26


def test_unknown_route_uses_generic_versioned_error(postgres_database: dict[str, str]) -> None:
    with app_for(postgres_database) as client:
        response = client.get("/api/v1/not-present")

    assert response.status_code == 404
    assert response.json()["contract_version"] == "v1"
    assert response.json()["error"]["code"] == "not_found"
    assert "trace" not in str(response.json()).lower()
    assert response.json()["error"]["request_id"] == response.headers["X-Request-ID"]


def test_openapi_is_explicitly_versioned(postgres_database: dict[str, str]) -> None:
    with app_for(postgres_database) as client:
        document = client.get("/openapi.json").json()

    assert document["info"]["version"] == "1.0.0"
    assert document["info"]["title"] == "SIEMBIOT Private API"
