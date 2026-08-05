"""The lifecycle state machine and the step graph.

Both are pure data, so these tests enumerate the whole space rather than sampling it.
"""

from __future__ import annotations

import pytest
from siembiot_worker.workflows.graph import (
    ASSESSMENT_GRAPH,
    DEFAULT_GRAPH,
    GraphError,
    StepDefinition,
    StepGraph,
    StepState,
)
from siembiot_worker.workflows.lifecycle import (
    REOPENABLE_STATES,
    RUNNING_STATES,
    TERMINAL_STATES,
    AssessmentState,
    LifecycleError,
    assert_transition,
    can_transition,
    is_terminal,
)

HAPPY_PATH = (
    AssessmentState.DRAFT,
    AssessmentState.AWAITING_AUTHORIZATION,
    AssessmentState.QUEUED,
    AssessmentState.PLANNING,
    AssessmentState.COLLECTING,
    AssessmentState.NORMALIZING,
    AssessmentState.EVALUATING,
    AssessmentState.AGENT_ANALYSIS,
    AssessmentState.REPORT_GENERATION,
    AssessmentState.COMPLETED,
)


# -- lifecycle ---------------------------------------------------------------


def test_the_documented_happy_path_is_walkable() -> None:
    for current, target in zip(HAPPY_PATH, HAPPY_PATH[1:], strict=False):
        assert_transition(current, target)


def test_a_final_terminal_state_can_never_be_left() -> None:
    """Completed, cancelled, expired and policy-blocked runs are final.

    Reopening one would let an already-published result change after the fact.
    """
    for state in TERMINAL_STATES - REOPENABLE_STATES:
        assert is_terminal(state)
        for target in AssessmentState:
            assert not can_transition(state, target)
            if target is not state:
                with pytest.raises(LifecycleError, match="terminal_state_is_immutable"):
                    assert_transition(state, target)


def test_only_a_failed_or_partial_run_may_be_reopened_by_an_operator() -> None:
    assert REOPENABLE_STATES == {
        AssessmentState.FAILED,
        AssessmentState.PARTIALLY_COMPLETED,
    }
    for state in REOPENABLE_STATES:
        assert is_terminal(state)
        # Reopening leads back into live work, never straight to another outcome.
        for target in RUNNING_STATES:
            assert can_transition(state, target)
        assert not can_transition(state, AssessmentState.COMPLETED)


def test_a_run_cannot_skip_evidence_collection() -> None:
    assert not can_transition(AssessmentState.QUEUED, AssessmentState.EVALUATING)
    assert not can_transition(AssessmentState.PLANNING, AssessmentState.NORMALIZING)
    assert not can_transition(AssessmentState.COLLECTING, AssessmentState.COMPLETED)


def test_agent_analysis_may_be_skipped_so_the_model_is_never_required() -> None:
    assert can_transition(AssessmentState.EVALUATING, AssessmentState.REPORT_GENERATION)
    assert can_transition(AssessmentState.EVALUATING, AssessmentState.AGENT_ANALYSIS)


def test_any_live_state_can_be_cancelled_or_blocked_by_policy() -> None:
    for state in AssessmentState:
        if state in TERMINAL_STATES:
            continue
        assert can_transition(state, AssessmentState.CANCELLED)
        assert can_transition(state, AssessmentState.BLOCKED_BY_POLICY)
        assert can_transition(state, AssessmentState.EXPIRED)


def test_only_running_states_can_fail_or_partially_complete() -> None:
    for state in AssessmentState:
        if state in TERMINAL_STATES:
            continue
        expected = state in RUNNING_STATES
        assert can_transition(state, AssessmentState.FAILED) is expected
        assert can_transition(state, AssessmentState.PARTIALLY_COMPLETED) is expected


def test_a_transition_to_the_same_state_is_refused() -> None:
    with pytest.raises(LifecycleError, match="transition_is_a_no_op"):
        assert_transition(AssessmentState.QUEUED, AssessmentState.QUEUED)


def test_an_undesigned_transition_is_refused() -> None:
    with pytest.raises(LifecycleError, match="illegal_transition"):
        assert_transition(AssessmentState.DRAFT, AssessmentState.COMPLETED)


# -- graph -------------------------------------------------------------------


def test_the_shipped_graph_is_acyclic_and_fully_connected() -> None:
    assert DEFAULT_GRAPH.names
    assert len(set(DEFAULT_GRAPH.names)) == len(ASSESSMENT_GRAPH)


def test_a_cyclic_graph_is_refused() -> None:
    with pytest.raises(GraphError, match="cyclic_dependency"):
        StepGraph(
            (
                StepDefinition("a", AssessmentState.COLLECTING, depends_on=("b",)),
                StepDefinition("b", AssessmentState.COLLECTING, depends_on=("a",)),
            )
        )


def test_an_unknown_dependency_is_refused() -> None:
    with pytest.raises(GraphError, match="unknown_dependency"):
        StepGraph((StepDefinition("a", AssessmentState.COLLECTING, depends_on=("ghost",)),))


def test_a_duplicate_step_name_is_refused() -> None:
    with pytest.raises(GraphError, match="duplicate_step_name"):
        StepGraph(
            (
                StepDefinition("a", AssessmentState.COLLECTING),
                StepDefinition("a", AssessmentState.NORMALIZING),
            )
        )


def test_only_the_planning_step_is_ready_at_the_start() -> None:
    ready = DEFAULT_GRAPH.ready({})
    assert [step.name for step in ready] == ["plan"]


def test_collectors_become_ready_together_once_planning_succeeds() -> None:
    ready = DEFAULT_GRAPH.ready({"plan": StepState.SUCCEEDED})
    assert {step.name for step in ready} == {
        "collect.dns",
        "collect.email",
        "collect.tls",
        "collect.http",
        "collect.rdap",
        "collect.ct",
    }


def test_a_failed_optional_collector_does_not_stall_the_run() -> None:
    states = {"plan": StepState.SUCCEEDED}
    states.update({name: StepState.SUCCEEDED for name in DEFAULT_GRAPH.names if "collect." in name})
    states["collect.rdap"] = StepState.FAILED
    ready = DEFAULT_GRAPH.ready(states)
    assert [step.name for step in ready] == ["normalize"]


def test_a_failed_required_step_blocks_everything_downstream() -> None:
    states = {"plan": StepState.SUCCEEDED}
    states.update({name: StepState.SUCCEEDED for name in DEFAULT_GRAPH.names if "collect." in name})
    states["normalize"] = StepState.FAILED
    assert DEFAULT_GRAPH.ready(states) == ()
    blocked = {step.name for step in DEFAULT_GRAPH.blocked(states)}
    assert "evaluate" in blocked


def test_progress_counts_settled_steps_not_elapsed_time() -> None:
    empty = DEFAULT_GRAPH.progress({})
    assert empty.percentage == 0.0
    assert empty.complete is False

    done = dict.fromkeys(DEFAULT_GRAPH.names, StepState.SUCCEEDED)
    finished = DEFAULT_GRAPH.progress(done)
    assert finished.percentage == 100.0
    assert finished.complete is True
    assert finished.succeeded_steps == len(DEFAULT_GRAPH.names)


def test_progress_names_the_failed_steps() -> None:
    states = dict.fromkeys(DEFAULT_GRAPH.names, StepState.SUCCEEDED)
    states["collect.ct"] = StepState.DEAD_LETTERED
    progress = DEFAULT_GRAPH.progress(states)
    assert progress.failed_steps == ("collect.ct",)


def test_an_all_success_run_completes() -> None:
    states = dict.fromkeys(DEFAULT_GRAPH.names, StepState.SUCCEEDED)
    assert DEFAULT_GRAPH.outcome(states) is AssessmentState.COMPLETED


def test_a_run_with_a_failed_optional_step_is_partially_completed() -> None:
    states = dict.fromkeys(DEFAULT_GRAPH.names, StepState.SUCCEEDED)
    states["collect.rdap"] = StepState.FAILED
    assert DEFAULT_GRAPH.outcome(states) is AssessmentState.PARTIALLY_COMPLETED


def test_a_run_with_a_failed_required_step_fails() -> None:
    states = dict.fromkeys(DEFAULT_GRAPH.names, StepState.SUCCEEDED)
    states["score"] = StepState.FAILED
    assert DEFAULT_GRAPH.outcome(states) is AssessmentState.FAILED


def test_a_run_with_work_remaining_has_no_outcome_yet() -> None:
    assert DEFAULT_GRAPH.outcome({"plan": StepState.SUCCEEDED}) is None


def test_a_cancelled_step_cancels_the_run() -> None:
    states = dict.fromkeys(DEFAULT_GRAPH.names, StepState.SUCCEEDED)
    states["collect.dns"] = StepState.CANCELLED
    assert DEFAULT_GRAPH.outcome(states) is AssessmentState.CANCELLED


def test_step_definitions_reject_nonsense_budgets() -> None:
    with pytest.raises(ValueError, match="max_attempts"):
        StepDefinition("a", AssessmentState.COLLECTING, max_attempts=0)
    with pytest.raises(ValueError, match="deadline_seconds"):
        StepDefinition("a", AssessmentState.COLLECTING, deadline_seconds=0)
