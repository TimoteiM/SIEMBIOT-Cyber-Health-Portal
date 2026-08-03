from __future__ import annotations

from pathlib import Path

from siembiot_worker.collection.broker import FixtureInternetBroker
from siembiot_worker.collection.fixtures import FixtureScenarioPack
from siembiot_worker.collection.runner import (
    CollectionStep,
    FixtureRunInput,
    FixtureSuiteRunner,
)
from siembiot_worker.collectors.common import FixtureCollectorContext

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "fake_internet" / "v1"


def _runner(scenario_id: str = "healthy") -> tuple[FixtureSuiteRunner, FixtureRunInput]:
    pack = FixtureScenarioPack.load(FIXTURE_ROOT)
    scenario = pack.scenario(scenario_id)
    broker = FixtureInternetBroker(pack)
    run_input = FixtureRunInput(
        context=FixtureCollectorContext(
            scope_reference="scope-example-test",
            scenario_id=scenario.id,
            scenario_sha256=scenario.digest,
        ),
        domain="example.test",
        web_host="portal.example.test",
        dkim_selectors=("selector1",),
    )
    return FixtureSuiteRunner.for_broker(broker), run_input


def test_runner_has_stable_step_order_and_fixture_only_summary() -> None:
    runner, run_input = _runner()
    result = runner.run(run_input)
    assert [item.step_id for item in result.coverage] == [
        "dns",
        "email-dns",
        "http",
        "tls",
        "rdap",
        "ct",
    ]
    assert result.status == "completed"
    assert result.fixture_only and not result.publishable
    assert result.banner == "FIXTURE DATA — NOT A LIVE ASSESSMENT"
    assert result.scoring == "not_performed"
    assert all(not item.real_world for item in result.observations)


def test_partial_failure_retains_independent_successes() -> None:
    runner, run_input = _runner("partial-failure")
    result = runner.run(run_input)
    assert result.status == "partially_completed"
    assert any(item.step_id == "tls" and item.status == "completed" for item in result.coverage)
    assert any(item.outcome.value == "pass" for item in result.observations)
    assert any(
        item.outcome.value in {"error", "unknown", "unavailable"} for item in result.observations
    )


def test_collector_exception_is_redacted_and_does_not_erase_other_steps() -> None:
    runner, run_input = _runner()

    def explode(_: FixtureRunInput) -> tuple[()]:
        raise RuntimeError("secret fixture internals")

    healthy_step = runner.steps[0]
    custom = FixtureSuiteRunner(
        (
            CollectionStep("exploding", explode),
            healthy_step,
        )
    )
    result = custom.run(run_input)
    assert result.status == "partially_completed"
    assert result.coverage[0].reason_code == "collector_error"
    assert result.coverage[1].status == "completed"
    assert "secret" not in repr(result)


def test_cancellation_retains_completed_work_and_stops_new_steps() -> None:
    runner, run_input = _runner()
    checks = 0

    def cancelled() -> bool:
        nonlocal checks
        checks += 1
        return checks >= 2

    context = FixtureCollectorContext(
        scope_reference=run_input.context.scope_reference,
        scenario_id=run_input.context.scenario_id,
        scenario_sha256=run_input.context.scenario_sha256,
        cancelled=cancelled,
    )
    result = runner.run(
        FixtureRunInput(context, run_input.domain, run_input.web_host, run_input.dkim_selectors)
    )
    assert result.status == "cancelled"
    assert result.coverage[-1].status == "cancelled"
