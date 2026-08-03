from __future__ import annotations

from fastapi.testclient import TestClient
from siembiot.main import create_app


def test_collection_capability_is_typed_and_fixture_only() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/collection/capabilities")

    assert response.status_code == 200
    assert response.json() == {
        "contract_version": "v1",
        "milestone_status": "fixture_validation_only",
        "fixture_only": True,
        "live_execution": False,
        "publishable": False,
        "execution_modes": {
            "fixture": "available",
            "unavailable": "structured_result_state",
            "disabled_by_policy": "structured_result_state",
            "live": "future_requires_explicit_activation",
        },
        "restricted_egress_boundary": "required_before_live_activation",
        "report_banner": "FIXTURE DATA — NOT A LIVE ASSESSMENT",
    }
    assert response.headers["Cache-Control"] == "no-store"


def test_api_exposes_status_but_no_collector_execution_route() -> None:
    with TestClient(create_app()) as client:
        document = client.get("/openapi.json").json()

    collection_paths = [path for path in document["paths"] if "collection" in path]
    assert collection_paths == ["/api/v1/collection/capabilities"]
    assert set(document["paths"][collection_paths[0]]) == {"get"}
