from __future__ import annotations

import json
from pathlib import Path

from siembiot_worker.collection.broker import FixtureInternetBroker
from siembiot_worker.collection.fixtures import FixtureScenarioPack
from siembiot_worker.collection.reporting import render_fixture_report
from siembiot_worker.collection.runner import FixtureRunInput, FixtureSuiteRunner
from siembiot_worker.collectors.common import FixtureCollectorContext

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "fake_internet" / "v1"


def test_exact_rerun_identity_and_report_banner() -> None:
    pack = FixtureScenarioPack.load(FIXTURE_ROOT)
    scenario = pack.scenario("healthy")
    run_input = FixtureRunInput(
        FixtureCollectorContext("scope-example-test", scenario.id, scenario.digest),
        "example.test",
        "portal.example.test",
        ("selector1",),
    )
    runner = FixtureSuiteRunner.for_broker(FixtureInternetBroker(pack))
    first = runner.run(run_input)
    second = runner.run(run_input)
    assert first == second
    assert [item.evidence_id for item in first.observations] == [
        item.evidence_id for item in second.observations
    ]
    first_report = json.dumps(render_fixture_report(first), sort_keys=True, ensure_ascii=False)
    second_report = json.dumps(render_fixture_report(second), sort_keys=True, ensure_ascii=False)
    assert first_report == second_report
    assert "FIXTURE DATA — NOT A LIVE ASSESSMENT" in first_report
    assert '"live_assessment": false' in first_report
    assert '"scoring": "not_performed"' in first_report
