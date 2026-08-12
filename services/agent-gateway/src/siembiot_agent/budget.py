"""What one run may spend before it is stopped.

Every limit here bounds something that is unbounded by default. A model asked to explain
findings can loop, and a loop that costs money and holds a database connection is the
failure that takes a platform down rather than one report.

Exhaustion is not an error. A run that reaches a limit returns what it has and records
that it was stopped, because half a narrative plus an honest note is more use than a
failed step -- and the deterministic report was never waiting on it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

TOKENS = "token_budget_exhausted"
CALLS = "tool_call_budget_exhausted"
TIME = "time_budget_exhausted"
COST = "cost_budget_exhausted"
OUTPUT = "output_too_large"


@dataclass
class RunBudget:
    """Deliberately small defaults. A run that needs more than this is not explaining an
    assessment, it is doing something nobody designed."""

    max_tokens: int = 20_000
    max_tool_calls: int = 20
    max_seconds: float = 60.0
    max_cost_units: float = 1.0
    max_output_bytes: int = 64_000
    max_retries: int = 1
    #: One run at a time per organization. Concurrency here would multiply provider cost
    #: against a tenant that never asked for it.
    max_concurrent_runs: int = 1

    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    tokens_used: int = 0
    tool_calls: int = 0
    cost_units: float = 0.0

    def exhausted(self, now: datetime | None = None) -> str | None:
        moment = now or datetime.now(UTC)
        if self.tokens_used >= self.max_tokens:
            return TOKENS
        if self.tool_calls >= self.max_tool_calls:
            return CALLS
        if moment - self.started_at >= timedelta(seconds=self.max_seconds):
            return TIME
        if self.cost_units >= self.max_cost_units:
            return COST
        return None

    def charge(self, *, tokens: int = 0, calls: int = 0, cost: float = 0.0) -> None:
        self.tokens_used += tokens
        self.tool_calls += calls
        self.cost_units += cost

    def output_refusal(self, payload: str) -> str | None:
        return OUTPUT if len(payload.encode("utf-8")) > self.max_output_bytes else None
