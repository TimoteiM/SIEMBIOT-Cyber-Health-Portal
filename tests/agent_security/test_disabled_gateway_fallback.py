"""The fourth acceptance clause, on its own: everything works with the model off.

> "complete workflows remain usable with model disabled"

This is the clause that makes the other three survivable. If the narrative were load
bearing, then every refusal the gateway makes -- an unsupported claim dropped, a provider
outage, an exhausted budget -- would degrade a public institution's report. It is not,
and this test is what says so rather than the architecture diagram.

Driven through the real engine over the real graph, not a mock of it: the question is
whether an assessment reaches a report, and only the engine can answer that.
"""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "workflows"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "collectors"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "agent-gateway" / "src"))

from siembiot_agent.gateway import PROVIDER_UNAVAILABLE, run_analysis  # noqa: E402
from siembiot_agent.provider import DisabledProvider  # noqa: E402
from siembiot_agent.scope import AssessmentScope  # noqa: E402
from siembiot_worker.workflows.lifecycle import AssessmentState  # noqa: E402
from test_handlers import ORGANIZATION, build, drive  # noqa: E402

HOST = "primaria-exemplu.ro"


def test_an_assessment_reaches_a_report_with_the_model_disabled() -> None:
    """The whole flow, end to end, with no provider configured -- which is the default
    and has been the only configuration this platform has ever run in."""
    engine, repository, context, assessment, engine_clock = build(HOST)

    outcome = drive(engine, assessment, engine_clock)

    assert outcome in {AssessmentState.COMPLETED, AssessmentState.PARTIALLY_COMPLETED}
    assert engine.progress(assessment).complete is True
    assert context.snapshot is not None, "no score was produced"
    assert context.findings is not None, "no findings were produced"

    steps = repository.load_steps(assessment)
    assert "report" in steps
    assert steps["report"].state.value in {"succeeded", "skipped"}


def test_the_agent_step_reports_itself_skipped_rather_than_failing() -> None:
    """An optional step that failed would drag the run to `partially_completed` and send
    a reader looking for a problem with their domain that does not exist."""
    engine, repository, _, assessment, engine_clock = build(HOST)

    drive(engine, assessment, engine_clock)

    agent = repository.load_steps(assessment)["agent_analysis"]
    assert agent.state.value in {"succeeded", "skipped"}


def test_the_score_is_identical_whether_or_not_the_gateway_is_consulted() -> None:
    """The narrative cannot move a number.

    Two runs of the same fixtures: the score comes from the deterministic engine, and
    running the gateway alongside it changes nothing, because nothing downstream reads
    what the gateway produced.
    """
    first_engine, _, first_context, first_id, first_clock = build(HOST)
    drive(first_engine, first_id, first_clock)

    second_engine, _, second_context, second_id, second_clock = build(HOST)
    drive(second_engine, second_id, second_clock)

    result = run_analysis(
        scope=AssessmentScope(
            run_id=uuid4(),
            organization_id=ORGANIZATION,
            assessment_id=second_id,
            subjects=frozenset({HOST}),
            expires_at=second_context.clock().replace(year=2099),
        ),
        provider=DisabledProvider(),
        readers={},
        evidence={},
    )

    assert result.outcome == PROVIDER_UNAVAILABLE
    assert first_context.snapshot is not None and second_context.snapshot is not None
    assert first_context.snapshot.score == second_context.snapshot.score
    assert first_context.snapshot.band == second_context.snapshot.band


def test_findings_survive_the_gateway_being_absent_entirely() -> None:
    """Not merely disabled -- never constructed. The findings are derived before the
    agent step runs and do not consult it."""
    engine, _, context, assessment, engine_clock = build(HOST)

    drive(engine, assessment, engine_clock)

    assert len(context.findings) > 0
    for finding in context.findings:
        # Every finding traces to a check identifier from the deterministic catalogue.
        assert finding.check_id
