from __future__ import annotations

from pathlib import Path

import pytest
from siembiot_worker.collection.broker import (
    BrokerRequestError,
    FixtureInternetBroker,
    HTTPFixtureRequest,
)
from siembiot_worker.collection.fixtures import FixtureScenarioPack
from siembiot_worker.collection.models import ObservationOutcome
from siembiot_worker.collectors.common import FixtureCollectorContext
from siembiot_worker.collectors.http.collector import HTTPCollector

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "fake_internet" / "v1"


def _components(
    scenario_id: str = "healthy",
) -> tuple[FixtureInternetBroker, FixtureCollectorContext]:
    pack = FixtureScenarioPack.load(FIXTURE_ROOT)
    scenario = pack.scenario(scenario_id)
    return FixtureInternetBroker(pack), FixtureCollectorContext(
        scope_reference="scope-portal-example-test",
        scenario_id=scenario.id,
        scenario_sha256=scenario.digest,
    )


def test_http_collector_reports_bounded_headers_and_security_text_metadata() -> None:
    broker, context = _components()
    observations = HTTPCollector(broker).collect(context, "portal.example.test")
    head, security_text = observations
    assert head.outcome is ObservationOutcome.PASS
    assert head.payload["status"] == 200
    assert head.payload["headers"] == {
        "content_security_policy": True,
        "frame_protection": True,
        "hsts": True,
        "permissions_policy": True,
        "referrer_policy": True,
    }
    assert head.payload["public_cookie_secure"] is True
    assert head.payload["public_cookie_httponly"] is True
    assert security_text.payload["body_present"] is True
    assert "body" not in security_text.payload
    assert all(not item.publishable and not item.real_world for item in observations)


def test_http_timeout_is_a_structured_fixture_error() -> None:
    broker, context = _components("partial-failure")
    observations = HTTPCollector(broker).collect(context, "portal.example.test")
    assert [item.outcome for item in observations] == [
        ObservationOutcome.ERROR,
        ObservationOutcome.UNKNOWN,
    ]
    assert all(
        item.payload["reason_code"] in {"timeout", "fixture_unavailable"} for item in observations
    )


@pytest.mark.parametrize("path", ["/?query=1", "/#fragment", "/admin", "//evil.test/"])
def test_broker_has_no_arbitrary_path_or_crawl_surface(path: str) -> None:
    with pytest.raises(BrokerRequestError, match="forbidden_path"):
        HTTPFixtureRequest.https("portal.example.test", path=path, method="GET")
