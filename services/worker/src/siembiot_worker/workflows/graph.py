"""The assessment step graph.

Progress is reported from real completed steps, never from a timer. Because the graph
is declared up front, a run knows how many steps it has before it starts one, and a
partially completed run can say exactly which evidence it does and does not have.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from siembiot_worker.workflows.lifecycle import AssessmentState


class StepState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"
    DEAD_LETTERED = "dead_lettered"


TERMINAL_STEP_STATES = frozenset(
    {
        StepState.SUCCEEDED,
        StepState.FAILED,
        StepState.SKIPPED,
        StepState.CANCELLED,
        StepState.DEAD_LETTERED,
    }
)


@dataclass(frozen=True)
class StepDefinition:
    """One unit of durable work."""

    name: str
    phase: AssessmentState
    depends_on: tuple[str, ...] = ()
    #: A step the assessment can finish without. A collector for a control the domain
    #: does not use must not fail the whole run, but scoring must.
    optional: bool = False
    max_attempts: int = 3
    deadline_seconds: float = 120.0

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.deadline_seconds <= 0:
            raise ValueError("deadline_seconds must be positive")


COLLECTION_STEPS: tuple[StepDefinition, ...] = (
    StepDefinition("collect.dns", AssessmentState.COLLECTING, optional=True),
    StepDefinition("collect.email", AssessmentState.COLLECTING, optional=True),
    StepDefinition("collect.tls", AssessmentState.COLLECTING, optional=True),
    StepDefinition("collect.http", AssessmentState.COLLECTING, optional=True),
    StepDefinition("collect.rdap", AssessmentState.COLLECTING, optional=True),
    StepDefinition("collect.ct", AssessmentState.COLLECTING, optional=True),
    # Skipped outright in a passive run. Longer deadline than the rest because its
    # duration is a port count multiplied by a timeout rather than one request.
    StepDefinition(
        "collect.ports", AssessmentState.COLLECTING, optional=True, deadline_seconds=120.0
    ),
)

ASSESSMENT_GRAPH: tuple[StepDefinition, ...] = (
    StepDefinition("plan", AssessmentState.PLANNING, deadline_seconds=30.0),
    *(
        StepDefinition(
            step.name,
            step.phase,
            depends_on=("plan",),
            optional=True,
            max_attempts=step.max_attempts,
            deadline_seconds=step.deadline_seconds,
        )
        for step in COLLECTION_STEPS
    ),
    # Attribution is the one collector that reads another's evidence rather than the
    # target. Depending on `collect.dns` means it describes the addresses this run
    # actually saw; resolving again could legitimately return a different answer --
    # round-robin, anycast, a short time-to-live -- and name a network belonging to an
    # address the rest of the assessment never observed.
    StepDefinition(
        "collect.asn",
        AssessmentState.COLLECTING,
        depends_on=("collect.dns",),
        optional=True,
        deadline_seconds=45.0,
    ),
    StepDefinition(
        "normalize",
        AssessmentState.NORMALIZING,
        depends_on=(*(step.name for step in COLLECTION_STEPS), "collect.asn"),
        deadline_seconds=60.0,
    ),
    StepDefinition("evaluate", AssessmentState.EVALUATING, depends_on=("normalize",)),
    StepDefinition("score", AssessmentState.EVALUATING, depends_on=("evaluate",)),
    # Every host somebody accepted into scope, assessed for what is true of a host
    # rather than of the zone. Optional, and after `score` on purpose: the score covers
    # the authorized domain under methodology 1.0.0, so a subdomain that cannot be
    # reached must not be able to change the number reported for the domain.
    StepDefinition(
        "assess.assets",
        AssessmentState.EVALUATING,
        depends_on=("score",),
        optional=True,
        deadline_seconds=300.0,
    ),
    # Both, not just the optional one: depending on `assess.assets` alone would let a
    # failed `normalize` skip scoring and still produce findings and a report, because
    # an optional step that was skipped does not block its dependants.
    StepDefinition("findings", AssessmentState.EVALUATING, depends_on=("score", "assess.assets")),
    StepDefinition(
        "agent_analysis",
        AssessmentState.AGENT_ANALYSIS,
        depends_on=("findings",),
        optional=True,
        max_attempts=1,
    ),
    StepDefinition(
        "report",
        AssessmentState.REPORT_GENERATION,
        depends_on=("findings",),
        deadline_seconds=180.0,
    ),
)


class GraphError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class StepGraph:
    steps: tuple[StepDefinition, ...]

    def __post_init__(self) -> None:
        names = [step.name for step in self.steps]
        if len(names) != len(set(names)):
            raise GraphError("duplicate_step_name")
        known = set(names)
        for step in self.steps:
            missing = set(step.depends_on) - known
            if missing:
                raise GraphError("unknown_dependency")
        self._assert_acyclic()

    def _assert_acyclic(self) -> None:
        colour: dict[str, int] = {}

        def visit(name: str) -> None:
            state = colour.get(name, 0)
            if state == 1:
                raise GraphError("cyclic_dependency")
            if state == 2:
                return
            colour[name] = 1
            for dependency in self.by_name(name).depends_on:
                visit(dependency)
            colour[name] = 2

        for step in self.steps:
            visit(step.name)

    def by_name(self, name: str) -> StepDefinition:
        for step in self.steps:
            if step.name == name:
                return step
        raise GraphError("unknown_step")

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(step.name for step in self.steps)

    def ready(self, states: dict[str, StepState]) -> tuple[StepDefinition, ...]:
        """Steps whose dependencies have all settled and which can start now.

        A dependency that failed or was dead-lettered still counts as settled when it
        was optional, so one unavailable collector cannot stall the whole assessment.
        """
        ready: list[StepDefinition] = []
        for step in self.steps:
            if states.get(step.name, StepState.PENDING) is not StepState.PENDING:
                continue
            if all(self._dependency_settled(name, states) for name in step.depends_on):
                ready.append(step)
        return tuple(ready)

    def _dependency_settled(self, name: str, states: dict[str, StepState]) -> bool:
        state = states.get(name, StepState.PENDING)
        if state is StepState.SUCCEEDED:
            return True
        # A dependency that did not produce a result only lets dependants run when it
        # was optional. Otherwise the failure cascades, which is what stops a run from
        # scoring evidence it never collected.
        if state in {StepState.FAILED, StepState.DEAD_LETTERED, StepState.SKIPPED}:
            return self.by_name(name).optional
        return False

    def blocked(self, states: dict[str, StepState]) -> tuple[StepDefinition, ...]:
        """Pending steps that can never run because a required dependency failed."""
        blocked: list[StepDefinition] = []
        for step in self.steps:
            if states.get(step.name, StepState.PENDING) is not StepState.PENDING:
                continue
            for name in step.depends_on:
                dependency_state = states.get(name, StepState.PENDING)
                if (
                    dependency_state
                    in {StepState.FAILED, StepState.DEAD_LETTERED, StepState.SKIPPED}
                    and not self.by_name(name).optional
                ):
                    blocked.append(step)
                    break
                if dependency_state is StepState.CANCELLED:
                    blocked.append(step)
                    break
        return tuple(blocked)

    def progress(self, states: dict[str, StepState]) -> Progress:
        settled = sum(
            1
            for step in self.steps
            if states.get(step.name, StepState.PENDING) in TERMINAL_STEP_STATES
        )
        succeeded = sum(1 for step in self.steps if states.get(step.name) is StepState.SUCCEEDED)
        failed = tuple(
            step.name
            for step in self.steps
            if states.get(step.name) in {StepState.FAILED, StepState.DEAD_LETTERED}
        )
        return Progress(
            total_steps=len(self.steps),
            settled_steps=settled,
            succeeded_steps=succeeded,
            failed_steps=failed,
        )

    def outcome(self, states: dict[str, StepState]) -> AssessmentState | None:
        """The terminal state this run has reached, or None if work remains."""
        if any(states.get(step.name) is StepState.CANCELLED for step in self.steps):
            return AssessmentState.CANCELLED
        remaining = self.ready(states)
        pending = [
            step
            for step in self.steps
            if states.get(step.name, StepState.PENDING) not in TERMINAL_STEP_STATES
        ]
        if remaining or (pending and not self.blocked(states)):
            return None
        required_failed = any(
            states.get(step.name) in {StepState.FAILED, StepState.DEAD_LETTERED}
            and not step.optional
            for step in self.steps
        )
        if required_failed:
            return AssessmentState.FAILED
        optional_failed = any(
            states.get(step.name) in {StepState.FAILED, StepState.DEAD_LETTERED}
            for step in self.steps
        )
        return AssessmentState.PARTIALLY_COMPLETED if optional_failed else AssessmentState.COMPLETED


@dataclass(frozen=True)
class Progress:
    """Known-step progress. Never a timer, never an estimate."""

    total_steps: int
    settled_steps: int
    succeeded_steps: int
    failed_steps: tuple[str, ...] = field(default_factory=tuple)

    @property
    def percentage(self) -> float:
        if self.total_steps == 0:
            return 0.0
        return round(100.0 * self.settled_steps / self.total_steps, 1)

    @property
    def complete(self) -> bool:
        return self.settled_steps == self.total_steps


DEFAULT_GRAPH = StepGraph(ASSESSMENT_GRAPH)
