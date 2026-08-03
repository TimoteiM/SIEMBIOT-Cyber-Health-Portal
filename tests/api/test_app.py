from __future__ import annotations

from fastapi.testclient import TestClient
from siembiot.main import create_app


def test_health_is_typed_private_and_correlated() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/health", headers={"X-Request-ID": "not-a-valid-ulid"})

    assert response.status_code == 200
    assert response.json() == {"contract_version": "v1", "status": "ok"}
    assert response.headers["Cache-Control"] == "no-store"
    assert len(response.headers["X-Request-ID"]) == 26


def test_unknown_route_uses_generic_versioned_error() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/not-present")

    assert response.status_code == 404
    assert response.json()["contract_version"] == "v1"
    assert response.json()["error"]["code"] == "not_found"
    assert "trace" not in str(response.json()).lower()
    assert response.json()["error"]["request_id"] == response.headers["X-Request-ID"]


def test_openapi_is_explicitly_versioned() -> None:
    with TestClient(create_app()) as client:
        document = client.get("/openapi.json").json()

    assert document["info"]["version"] == "1.0.0"
    assert document["info"]["title"] == "SIEMBIOT Private API"
