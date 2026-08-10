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
    assert context.snapshot is not None
    # Nothing is invented in its place; the gap shows up as reduced coverage.
    assert not [
        observation
        for observation in context.observations
        if observation.observation_type.startswith("ct")
    ]


def test_a_step_that_does_not_apply_is_skipped_rather_than_failed() -> None:
    """`not_applicable` is an answer, not an error.

    Recording it as a failure would drag a run in which nothing went wrong down to
    `partially_completed`, sending the reader looking for a problem that does not
    exist -- and it would blur the line between proven absence and inconclusive
    evidence that the whole methodology depends on.
    """
    engine, repository, context, assessment, engine_clock = build("strong.example.test")
    drive(engine, assessment, engine_clock)

    steps = repository.load_steps(assessment)
    assert steps["collect.ct"].state is StepState.SKIPPED
    assert steps["collect.ct"].last_error == "no_ct_entries"  # the reason survives
    # This host also has no registry entry -- likewise an answer, not a fault.
    assert steps["collect.rdap"].state is StepState.SKIPPED

    # And a skip does not itself make the run partial. `strong.example.test` still
    # reports partial here, but only because collect.tls genuinely failed: swap that
    # one failure for a success and the skips leave a clean, complete run.
    settled = {name: record.state for name, record in steps.items()}
    settled["collect.tls"] = StepState.SUCCEEDED
    assert DEFAULT_GRAPH.outcome(settled) is AssessmentState.COMPLETED


def test_a_skipped_step_is_settled_and_not_retried_on_redelivery() -> None:
    """A second delivery must not re-run it hoping for a different answer."""
    engine, repository, context, assessment, engine_clock = build("strong.example.test")
    drive(engine, assessment, engine_clock)
    attempts = repository.load_steps(assessment)["collect.ct"].attempts

    engine.run(assessment, context.organization_id)
    assert repository.load_steps(assessment)["collect.ct"].attempts == attempts


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


# -- evidence that outlives the process that collected it --------------------


def test_a_resumed_run_recollects_evidence_it_lost_with_the_previous_execution() -> None:
    """The bug this exists for cost a real assessment half its coverage.

    Collection results live in `AssessmentContext.collection`, which is memory belonging
    to one execution. Step records are durable, so a step that succeeded is never offered
    again -- and on a resumed execution its result is simply gone. On a Romanian
    municipal site one HTTP retry sent the run round again: DNS, email and TLS were
    skipped as already-succeeded, and the run finished having normalized nothing but
    HTTP. No step failed. The only symptom was a smaller coverage number.

    Simulated the way it actually happens: a run that already collected everything, then
    a second execution whose memory is empty but whose step records are not.
    """
    engine, repository, context, assessment, engine_clock = build("strong.example.test")
    drive(engine, assessment, engine_clock)
    # Whatever this fixture actually collected -- asserted from the durable records
    # rather than a hardcoded list, so the test says "everything that succeeded is
    # recovered" rather than "these four are".
    collected = {
        name.removeprefix("collect.")
        for name, record in repository.load_steps(assessment).items()
        if name.startswith("collect.") and record.state is StepState.SUCCEEDED
    }
    assert {"dns", "email", "http"} <= collected

    resumed = AssessmentContext(
        organization_id=context.organization_id,
        assessment_id=assessment,
        host=context.host,
        catalog=CATALOG,
        runtime=build_runtime(context.host, hardened=True),
        clock=context.clock,
        declared_dkim_selectors=("selector1",),
    )
    assert resumed.collection == {}, "a fresh execution starts with no evidence in memory"

    # The real repository, because the recovery turns on what it says already succeeded.
    step = StepContext(
        assessment_id=assessment,
        organization_id=resumed.organization_id,
        step=DEFAULT_GRAPH.by_name("normalize"),
        attempt=1,
        payload={},
        deadline=NOW,
        _repository=repository,
    )
    outcome = build_handlers(resumed)["normalize"](step)

    assert outcome.succeeded, outcome.error
    assert collected <= set(resumed.collection), "a collector that succeeded was not recovered"
    kinds = {observation.observation_type.split(".")[0] for observation in resumed.observations}
    assert collected <= kinds, "recovered evidence did not reach normalization"


def test_recovery_leaves_skipped_collectors_skipped() -> None:
    """Recovery is for evidence that was lost, not for steps the run decided against.

    A collector the graph skipped -- a domain absent from the registry, say -- must not
    be quietly re-run under cover of another step's retry.
    """
    engine, repository, context, assessment, engine_clock = build("strong.example.test")
    drive(engine, assessment, engine_clock)
    records = repository.load_steps(assessment)
    skipped = {name for name, record in records.items() if record.state is StepState.SKIPPED}
    assert skipped, "this fixture is expected to skip at least one collector"

    resumed = AssessmentContext(
        organization_id=context.organization_id,
        assessment_id=assessment,
        host=context.host,
        catalog=CATALOG,
        runtime=build_runtime(context.host, hardened=True),
        clock=context.clock,
        declared_dkim_selectors=("selector1",),
    )
    step = StepContext(
        assessment_id=assessment,
        organization_id=resumed.organization_id,
        step=DEFAULT_GRAPH.by_name("normalize"),
        attempt=1,
        payload={},
        deadline=NOW,
        _repository=repository,
    )
    build_handlers(resumed)["normalize"](step)

    for name in skipped:
        assert name.removeprefix("collect.") not in resumed.collection


# -- the surface beyond the apex ---------------------------------------------


def test_an_accepted_host_is_assessed_and_the_domain_score_is_not_moved() -> None:
    """Accepting a candidate used to change a row and nothing else.

    The twenty-two checks all ran against the authorized domain, so an institution could
    accept `vpn.primaria.ro` into scope and see no difference at all. Most of what gets
    exploited lives on a subdomain nobody remembered.

    The second half of this test matters as much as the first: the score is defined over
    the authorized domain under methodology 1.0.0, so assessing more hosts must not
    silently change the number reported for the domain.
    """
    engine, repository, context, assessment, engine_clock = build("strong.example.test")
    context.accepted_assets = ("www.strong.example.test",)
    drive(engine, assessment, engine_clock)

    assert context.asset_evaluations, "no accepted host was assessed"
    subjects = {evaluation.subject.identifier for evaluation in context.asset_evaluations}
    assert subjects == {"www.strong.example.test"}

    # The domain's own results are untouched by the extra host.
    assert all(
        evaluation.subject.identifier == "strong.example.test" for evaluation in context.evaluations
    )
    assert context.snapshot is not None
    scored_subjects = {evaluation.subject.identifier for evaluation in context.evaluations}
    assert scored_subjects == {"strong.example.test"}


def test_only_host_scoped_checks_run_against_an_accepted_host() -> None:
    """A zone's answers must not be repeated under every hostname.

    DNSSEC, SPF and registration expiry belong to the domain however many hosts it has.
    Re-asking them per host would report one answer many times and read as broader
    coverage than was actually observed.
    """
    engine, repository, context, assessment, engine_clock = build("strong.example.test")
    context.accepted_assets = ("www.strong.example.test",)
    drive(engine, assessment, engine_clock)

    pillars = {evaluation.check_id.split(".")[0] for evaluation in context.asset_evaluations}
    assert pillars <= {"C", "F"}, f"a zone-scoped check ran per host: {pillars}"
    assert not [
        evaluation
        for evaluation in context.asset_evaluations
        if evaluation.check_id.startswith(("A.", "B.", "D.", "E."))
    ]


def test_findings_cover_every_assessed_host() -> None:
    """Otherwise a broken subdomain is assessed and then never reported."""
    engine, repository, context, assessment, engine_clock = build("weak.example.test")
    context.accepted_assets = ("www.weak.example.test",)
    drive(engine, assessment, engine_clock)

    subjects = {finding.subject.identifier for finding in context.findings}
    assert "www.weak.example.test" in subjects


def test_nothing_is_probed_without_somebody_accepting_it() -> None:
    """Discovery is not ownership. A name in a certificate log is a candidate."""
    engine, repository, context, assessment, engine_clock = build("strong.example.test")
    assert context.accepted_assets == ()
    drive(engine, assessment, engine_clock)

    assert context.asset_evaluations == ()
    assert repository.load_steps(assessment)["assess.assets"].state is StepState.SKIPPED


# -- the authorized-only collector -------------------------------------------


def test_a_passive_run_never_probes_a_port() -> None:
    """The step is skipped, not attempted and refused.

    The broker would refuse it anyway. But a refusal recorded against a run nobody
    authorized reads as an attempt that was blocked, and the honest record is that the
    question was never asked.
    """
    engine, repository, context, assessment, engine_clock = build("strong.example.test")
    assert context.runtime.mode is AssessmentMode.PASSIVE_OBSERVATION
    drive(engine, assessment, engine_clock)

    record = repository.load_steps(assessment)["collect.ports"]
    assert record.state is StepState.SKIPPED
    assert record.last_error == "requires_authorized_assessment"
    assert "ports" not in context.collection
    assert not [
        observation
        for observation in context.observations
        if observation.observation_type == "surface.ports"
    ]
