from __future__ import annotations

from pathlib import Path

from siembiot_worker.collection.broker import FixtureInternetBroker
from siembiot_worker.collection.fixtures import FixtureScenarioPack
from siembiot_worker.collection.models import ObservationOutcome
from siembiot_worker.collectors.common import FixtureCollectorContext
from siembiot_worker.collectors.ct.collector import CTCollector

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "fake_internet" / "v1"


def _components() -> tuple[FixtureInternetBroker, FixtureCollectorContext]:
    pack = FixtureScenarioPack.load(FIXTURE_ROOT)
    scenario = pack.scenario("healthy")
    return FixtureInternetBroker(pack), FixtureCollectorContext(
        scope_reference="scope-example-test",
        scenario_id=scenario.id,
        scenario_sha256=scenario.digest,
    )


def test_ct_names_are_passive_fixture_assertions_and_do_not_authorize_assets() -> None:
    broker, context = _components()
    observation = CTCollector(broker).collect(context, "example.test")
    assert observation.outcome is ObservationOutcome.PASS
    assert observation.payload["asserted_names"] == [
        "*.example.test",
        "example.test",
        "portal.example.test",
    ]
    assert observation.payload["ignored_unrelated_names"] == 1
    assert observation.payload["asset_authorized"] is False
    assert observation.payload["asset_created"] is False
    assert not observation.real_world and not observation.publishable


def test_ct_unavailable_is_not_an_empty_success() -> None:
    broker, context = _components()
    observation = CTCollector(broker).collect(context, "missing.example.test")
    assert observation.outcome is ObservationOutcome.UNAVAILABLE
    assert observation.payload["reason_code"] == "fixture_unavailable"
