from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from siembiot_worker.collection.broker import FixtureBrokerResult, FixtureInternetBroker
from siembiot_worker.collection.fixtures import FixtureScenarioPack
from siembiot_worker.collection.models import ObservationOutcome
from siembiot_worker.collectors.common import FixtureCollectorContext
from siembiot_worker.collectors.rdap.collector import RDAPCollector

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "fake_internet" / "v1"


class StaticRDAPBroker:
    def query_rdap(
        self,
        scenario_id: str,
        domain: str,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> FixtureBrokerResult:
        del scenario_id, domain, cancelled
        return FixtureBrokerResult(
            allowed=True,
            reason_code="fixture",
            fixture_timestamp=datetime(2026, 8, 3, 12, tzinfo=UTC),
            scenario_id="healthy",
            scenario_sha256="a" * 64,
            data={"status": ["x"] * 65, "events": []},
        )


def _components() -> tuple[FixtureInternetBroker, FixtureCollectorContext]:
    pack = FixtureScenarioPack.load(FIXTURE_ROOT)
    scenario = pack.scenario("healthy")
    return FixtureInternetBroker(pack), FixtureCollectorContext(
        scope_reference="scope-example-test",
        scenario_id=scenario.id,
    )


def test_rdap_collector_normalizes_status_events_and_only_entity_roles() -> None:
    broker, context = _components()
    observation = RDAPCollector(broker).collect(context, "example.test")
    assert observation.outcome is ObservationOutcome.PASS
    assert observation.payload["status"] == ("active",)
    assert observation.payload["events"] == (
        {"action": "registration", "date": "2020-01-01T00:00:00Z"},
    )
    assert observation.payload["entity_roles"] == ("registrar",)
    assert "entities" not in observation.payload
    assert "name" not in str(observation.payload)


def test_rdap_oversized_arrays_are_rejected() -> None:
    _, context = _components()
    observation = RDAPCollector(StaticRDAPBroker()).collect(context, "example.test")
    assert observation.outcome is ObservationOutcome.ERROR
    assert observation.payload["reason_code"] == "malformed_fixture_data"


def test_rdap_unavailable_is_explicit() -> None:
    broker, context = _components()
    observation = RDAPCollector(broker).collect(context, "missing.example.test")
    assert observation.outcome is ObservationOutcome.UNAVAILABLE
    assert observation.payload["reason_code"] == "fixture_unavailable"
