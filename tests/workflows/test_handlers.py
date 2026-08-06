"""The step handlers, driven by the real engine over fixture-backed collectors.

This is where the milestone's two halves meet: the durable engine from this milestone
and the collectors and scoring engines from the previous two. The tests run the whole
graph and then attack the parts where a handler could quietly lose evidence or retry
something it should not.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "collectors"))

from collector_support import (  # noqa: E402
    AllowAllPolicy,
    PublicResolver,
    RouteTransport,
    ZoneDNSTransport,
    response,
)
from siembiot_worker.adapters.contract import CollectionStatus  # noqa: E402
from siembiot_worker.network_safety.collection_broker import (  # noqa: E402
    CollectionNetworkBroker,
)
from siembiot_worker.network_safety.dns_client import BoundedDNSClient  # noqa: E402
from siembiot_worker.observation.mode import AssessmentMode  # noqa: E402
from siembiot_worker.observation.runtime import (  # noqa: E402
    ModeEnforcingPolicy,
    ObservationRuntime,
)
from siembiot_worker.policy.catalog import Result, load_catalog  # noqa: E402
from siembiot_worker.workflows.engine import StepContext, WorkflowEngine  # noqa: E402
from siembiot_worker.workflows.graph import DEFAULT_GRAPH, StepState  # noqa: E402
from siembiot_worker.workflows.handlers import (  # noqa: E402
    PERMANENT_COLLECTION_REASONS,
    AssessmentContext,
    build_handlers,
)
from siembiot_worker.workflows.lifecycle import AssessmentState  # noqa: E402
from siembiot_worker.workflows.memory_repository import (  # noqa: E402
    InMemoryWorkflowRepository,
)

CATALOG = load_catalog()
ORGANIZATION = uuid4()
NOW = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)

STRONG_POLICY = b"version: STSv1\nmode: enforce\nmx: mail.strong.example.test\nmax_age: 604800\n"
HARDENED = {
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
}


def clock() -> datetime:
    return NOW


class EngineClock:
    """A movable clock so backoff windows can be waited out without real sleeping."""

    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def build_runtime(host: str, *, hardened: bool = True) -> ObservationRuntime:
    """A runtime whose transports are fixtures rather than sockets."""
    from collector_support import ZONES

    routes = {
        f"https://mta-sts.{host}/.well-known/mta-sts.txt": response(
            200, {"content-type": "text/plain"}, STRONG_POLICY
        ),
        f"http://{host}/": response(301, {"location": f"https://{host}/"})
        if hardened
        else response(200, {"server": "nginx/1.2.3"}, b"plain"),
        f"https://{host}/": response(
            200, HARDENED if hardened else {"server": "nginx/1.2.3"}, b"<html></html>"
        ),
    }
    policy = ModeEnforcingPolicy(AssessmentMode.PASSIVE_OBSERVATION, sleeper=lambda _: None)
    broker = CollectionNetworkBroker(
        resolver=PublicResolver(),
        transport=RouteTransport(routes),
        policy=AllowAllPolicy(),
        dns_client=BoundedDNSClient(ZoneDNSTransport(ZONES)),
    )
    return ObservationRuntime(broker=broker, policy=policy, mode=AssessmentMode.PASSIVE_OBSERVATION)


def build(
    host: str, *, hardened: bool = True
) -> tuple[WorkflowEngine, InMemoryWorkflowRepository, AssessmentContext, UUID, EngineClock]:
    assessment_id = uuid4()
    context = AssessmentContext(
        organization_id=ORGANIZATION,
        assessment_id=assessment_id,
        host=host,
        catalog=CATALOG,
        runtime=build_runtime(host, hardened=hardened),
        clock=clock,
        declared_dkim_selectors=("selector1",),
    )
    engine_clock = EngineClock()
    repository = InMemoryWorkflowRepository(clock=engine_clock)
    engine = WorkflowEngine(
        repository,
        build_handlers(context),
        clock=engine_clock,
        jitter=lambda: 1.0,
        worker_id=uuid4(),
    )
    return engine, repository, context, assessment_id, engine_clock


def drive(engine: WorkflowEngine, assessment: UUID, engine_clock: EngineClock) -> AssessmentState:
    """Run to a terminal state the way a worker would: nudge, wait, nudge again.

    A retryable failure parks the step behind a backoff window, so a single pass
    returns with work still pending. Advancing the clock is what a real redelivery
    minutes later amounts to.
    """
    from siembiot_worker.workflows.lifecycle import is_terminal

    outcome = engine.run(assessment, ORGANIZATION)
    for _ in range(12):
        if is_terminal(outcome):
            return outcome
        engine_clock.advance(600)
        outcome = engine.run(assessment, ORGANIZATION)
    return outcome


# -- the whole graph ---------------------------------------------------------


def test_a_well_configured_domain_runs_to_completion() -> None:
    engine, repository, context, assessment, engine_clock = build("strong.example.test")
    outcome = drive(engine, assessment, engine_clock)

    assert outcome in {AssessmentState.COMPLETED, AssessmentState.PARTIALLY_COMPLETED}
    assert context.snapshot is not None
    assert context.snapshot.score is not None
    assert repository.load_steps(assessment)["score"].state is StepState.SUCCEEDED


def test_the_run_produces_evidence_evaluations_a_score_and_findings() -> None:
    engine, _, context, assessment, engine_clock = build("weak.example.test", hardened=False)
    drive(engine, assessment, engine_clock)

    assert context.observations
    assert len(context.evaluations) == len(CATALOG.checks)
    assert context.snapshot is not None
    assert context.findings


def test_progress_is_reported_from_settled_steps() -> None:
    engine, _, _, assessment, engine_clock = build("strong.example.test")
    assert engine.progress(assessment).percentage == 0.0
    drive(engine, assessment, engine_clock)
    assert engine.progress(assessment).complete is True


def test_every_evaluation_traces_to_a_collected_observation_or_says_why_not() -> None:
    engine, _, context, assessment, engine_clock = build("strong.example.test")
    drive(engine, assessment, engine_clock)
    known = {item.observation_id for item in context.observations}
    for evaluation in context.evaluations:
        if evaluation.observation_ids:
            assert set(evaluation.observation_ids) <= known
        else:
            assert evaluation.result in {"unknown", "not_applicable"}


# -- degrading honestly ------------------------------------------------------


def test_an_unreachable_domain_still_completes_with_reduced_coverage() -> None:
    """Losing a collector must cost coverage, never invent a result."""
    engine, _, context, assessment, engine_clock = build("unknown.example.test", hardened=False)
    drive(engine, assessment, engine_clock)

    assert context.snapshot is not None
    assert context.snapshot.coverage.percentage < 100.0
    dns_and_email = [item for item in context.evaluations if item.check_id.startswith(("A.", "B."))]
    assert all(item.result in {"unknown", "not_applicable"} for item in dns_and_email)


def test_a_collector_that_fails_contributes_nothing_rather_than_a_substitute() -> None:
    engine, repository, context, assessment, engine_clock = build("strong.example.test")
    # Certificate Transparency has no configured source in these fixtures.
    drive(engine, assessment, engine_clock)
    assert context.collection["ct"].status is CollectionStatus.NOT_APPLICABLE
    assert repository.load_steps(assessment)["collect.ct"].state is StepState.FAILED
    assert context.snapshot is not None


def test_normalization_refuses_to_proceed_with_no_evidence_at_all() -> None:
    _, _, context, assessment, _ = build("strong.example.test")
    handlers = build_handlers(context)
    # Simulate every collector having produced nothing.
    context.collection.clear()
    outcome = handlers["normalize"](_context_for(context, assessment, "normalize"))
    assert outcome.succeeded is False
    assert outcome.error == "no_evidence_collected"
    assert outcome.retryable is False


def _context_for(context: AssessmentContext, assessment: UUID, name: str) -> StepContext:
    return StepContext(
        assessment_id=assessment,
        organization_id=context.organization_id,
        step=DEFAULT_GRAPH.by_name(name),
        attempt=1,
        payload={},
        deadline=NOW,
        _repository=InMemoryWorkflowRepository(),
    )


# -- retry judgement ---------------------------------------------------------


def test_a_domain_absent_from_the_registry_is_not_retried() -> None:
    """It will still be absent in thirty seconds; retrying only spends the budget."""
    assert "domain_not_in_registry" in PERMANENT_COLLECTION_REASONS


def test_an_authorization_refusal_is_never_retried() -> None:
    """Retrying a refused operation would be an attempt to wear down the policy."""
    assert "operation_class_requires_authorization" in PERMANENT_COLLECTION_REASONS
    assert "operation_class_mismatch" in PERMANENT_COLLECTION_REASONS


def test_a_transient_provider_failure_is_retried() -> None:
    """A resolver that timed out may well answer on the next attempt."""
    from siembiot_worker.adapters.contract import CollectionResult, Provenance
    from siembiot_worker.workflows.handlers import _collection_outcome

    result = CollectionResult(
        CollectionStatus.UNAVAILABLE,
        Provenance("dns_resilience", "1.0.0", NOW),
        reason_code="dns_unreachable",
    )
    outcome = _collection_outcome("dns", result)
    assert outcome.retryable is True
    assert outcome.error == "dns_unreachable"


def test_agent_analysis_never_blocks_a_run_when_the_model_is_disabled() -> None:
    engine, repository, context, assessment, engine_clock = build("strong.example.test")
    drive(engine, assessment, engine_clock)
    step = repository.load_steps(assessment)["agent_analysis"]
    assert step.state is StepState.SUCCEEDED
    assert step.result["agent_analysis"] == "skipped_model_disabled"


# -- asset candidates --------------------------------------------------------


def test_asset_candidates_are_produced_unreviewed() -> None:
    from collector_support import FIXTURES
    from siembiot_worker.collectors.ct_log import FixtureCTSource

    engine, _, context, assessment, engine_clock = build("strong.example.test")
    context.ct_source = FixtureCTSource(FIXTURES / "providers" / "ct")
    drive(engine, assessment, engine_clock)

    assert context.asset_candidates
    assert all(candidate.needs_review for candidate in context.asset_candidates)
    assert all(not candidate.in_scope for candidate in context.asset_candidates)


# -- determinism -------------------------------------------------------------


def test_two_runs_of_the_same_fixture_produce_the_same_score() -> None:
    scores = []
    for _ in range(2):
        engine, _, context, assessment, engine_clock = build("strong.example.test")
        drive(engine, assessment, engine_clock)
        assert context.snapshot is not None
        scores.append((context.snapshot.score, context.snapshot.band))
    assert scores[0] == scores[1]


@pytest.mark.parametrize("host", ["strong.example.test", "weak.example.test"])
def test_no_check_is_left_unevaluated(host: str) -> None:
    engine, _, context, assessment, engine_clock = build(
        host, hardened=host == "strong.example.test"
    )
    drive(engine, assessment, engine_clock)
    assert {item.check_id for item in context.evaluations} == CATALOG.check_ids
    assert all(Result(item.result) for item in context.evaluations)
