from __future__ import annotations

import socket
from pathlib import Path

import pytest
from siembiot_worker.collection.broker import FixtureInternetBroker
from siembiot_worker.collection.fixtures import FixtureScenarioPack
from siembiot_worker.collection.runner import FixtureRunInput, FixtureSuiteRunner
from siembiot_worker.collectors.common import FixtureCollectorContext

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "fake_internet" / "v1"


def test_complete_fixture_collection_opens_no_network_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def denied(*_: object, **__: object) -> None:
        raise AssertionError("fixture collection attempted external networking")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)

    pack = FixtureScenarioPack.load(FIXTURE_ROOT)
    scenario = pack.scenario("healthy")
    result = FixtureSuiteRunner.for_broker(FixtureInternetBroker(pack)).run(
        FixtureRunInput(
            FixtureCollectorContext("scope-example-test", scenario.id, scenario.digest),
            "example.test",
            "portal.example.test",
            ("selector1",),
        )
    )
    assert result.status == "completed"
    assert result.fixture_only and not result.publishable
