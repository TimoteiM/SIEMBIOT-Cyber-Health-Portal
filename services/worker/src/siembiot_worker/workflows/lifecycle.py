"""The assessment lifecycle.

A single explicit state machine, so an assessment can never drift into a state nobody
designed. Transitions are data rather than scattered ``if`` statements, which is what
lets the tests enumerate every legal and illegal move.
"""

from __future__ import annotations

from enum import StrEnum


class AssessmentState(StrEnum):
    DRAFT = "draft"
    AWAITING_AUTHORIZATION = "awaiting_authorization"
    QUEUED = "queued"
    PLANNING = "planning"
    COLLECTING = "collecting"
    NORMALIZING = "normalizing"
    EVALUATING = "evaluating"
    AGENT_ANALYSIS = "agent_analysis"
    REPORT_GENERATION = "report_generation"
    COMPLETED = "completed"
    # Terminal exceptions
    CANCELLED = "cancelled"
    PARTIALLY_COMPLETED = "partially_completed"
    FAILED = "failed"
    EXPIRED = "expired"
    BLOCKED_BY_POLICY = "blocked_by_policy"


TERMINAL_STATES = frozenset(
    {
        AssessmentState.COMPLETED,
        AssessmentState.CANCELLED,
        AssessmentState.PARTIALLY_COMPLETED,
        AssessmentState.FAILED,
        AssessmentState.EXPIRED,
        AssessmentState.BLOCKED_BY_POLICY,
    }
)

#: The only terminal states an operator may reopen, and only by replaying a failed
#: step. A completed, cancelled, expired or policy-blocked run is final: reopening one
#: would let a published result change after the fact.
REOPENABLE_STATES = frozenset({AssessmentState.FAILED, AssessmentState.PARTIALLY_COMPLETED})

#: States from which work is actively running and may therefore be cancelled.
RUNNING_STATES = frozenset(
    {
        AssessmentState.PLANNING,
        AssessmentState.COLLECTING,
        AssessmentState.NORMALIZING,
        AssessmentState.EVALUATING,
        AssessmentState.AGENT_ANALYSIS,
        AssessmentState.REPORT_GENERATION,
    }
)

#: Every state that is not terminal may be cancelled or blocked by policy, and any
#: running state may fail. Those universal edges are added below rather than repeated.
_FORWARD: dict[AssessmentState, frozenset[AssessmentState]] = {
    AssessmentState.DRAFT: frozenset({AssessmentState.AWAITING_AUTHORIZATION}),
    AssessmentState.AWAITING_AUTHORIZATION: frozenset({AssessmentState.QUEUED}),
    AssessmentState.QUEUED: frozenset({AssessmentState.PLANNING}),
    AssessmentState.PLANNING: frozenset({AssessmentState.COLLECTING}),
    AssessmentState.COLLECTING: frozenset({AssessmentState.NORMALIZING}),
    AssessmentState.NORMALIZING: frozenset({AssessmentState.EVALUATING}),
    AssessmentState.EVALUATING: frozenset({AssessmentState.AGENT_ANALYSIS}),
    # Agent analysis is optional: with the model disabled the run goes straight to
    # report generation, which is what keeps the product usable without an LLM.
    AssessmentState.AGENT_ANALYSIS: frozenset({AssessmentState.REPORT_GENERATION}),
    AssessmentState.REPORT_GENERATION: frozenset(
        {AssessmentState.COMPLETED, AssessmentState.PARTIALLY_COMPLETED}
    ),
}


def _build_transitions() -> dict[AssessmentState, frozenset[AssessmentState]]:
    transitions: dict[AssessmentState, frozenset[AssessmentState]] = {}
    for state in AssessmentState:
        if state in REOPENABLE_STATES:
            transitions[state] = frozenset(RUNNING_STATES)
            continue
        if state in TERMINAL_STATES:
            transitions[state] = frozenset()
            continue
        allowed = set(_FORWARD.get(state, frozenset()))
        allowed.add(AssessmentState.CANCELLED)
        allowed.add(AssessmentState.BLOCKED_BY_POLICY)
        allowed.add(AssessmentState.EXPIRED)
        if state in RUNNING_STATES:
            allowed.add(AssessmentState.FAILED)
            allowed.add(AssessmentState.PARTIALLY_COMPLETED)
        # Skipping agent analysis is legal; skipping evidence collection is not.
        if state is AssessmentState.EVALUATING:
            allowed.add(AssessmentState.REPORT_GENERATION)
        transitions[state] = frozenset(allowed)
    return transitions


TRANSITIONS = _build_transitions()


class LifecycleError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def can_transition(current: AssessmentState, target: AssessmentState) -> bool:
    return target in TRANSITIONS[current]


def assert_transition(current: AssessmentState, target: AssessmentState) -> None:
    if current is target:
        raise LifecycleError("transition_is_a_no_op")
    if current in TERMINAL_STATES and current not in REOPENABLE_STATES:
        raise LifecycleError("terminal_state_is_immutable")
    if not can_transition(current, target):
        raise LifecycleError("illegal_transition")


def is_terminal(state: AssessmentState) -> bool:
    return state in TERMINAL_STATES


#: The forward order of the happy path, used to advance a run through the phases it
#: has not visited. A step whose work was deduplicated still moves the run forward, so
#: the engine cannot end up trying an illegal jump from a phase it never entered.
PHASE_ORDER: tuple[AssessmentState, ...] = (
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


def phase_index(state: AssessmentState) -> int:
    # A reopened run sits before every phase, so replaying a step walks forward again.
    if state in REOPENABLE_STATES:
        return PHASE_ORDER.index(AssessmentState.QUEUED)
    try:
        return PHASE_ORDER.index(state)
    except ValueError as error:
        raise LifecycleError("state_is_not_on_the_happy_path") from error


def next_phase(state: AssessmentState) -> AssessmentState | None:
    if state in REOPENABLE_STATES:
        return AssessmentState.PLANNING
    index = phase_index(state)
    if index + 1 >= len(PHASE_ORDER):
        return None
    return PHASE_ORDER[index + 1]


def forward_path(current: AssessmentState, target: AssessmentState) -> tuple[AssessmentState, ...]:
    """The states to pass through to reach ``target``, shortest legal route first.

    Returns an empty tuple when the run is already at or past the target, so a second
    collector does not drag the lifecycle backwards.
    """
    if current is target or phase_index(current) >= phase_index(target):
        return ()
    path: list[AssessmentState] = []
    cursor = current
    while cursor is not target:
        if can_transition(cursor, target):
            path.append(target)
            break
        upcoming = next_phase(cursor)
        if upcoming is None:
            raise LifecycleError("no_forward_path")
        path.append(upcoming)
        cursor = upcoming
    return tuple(path)
