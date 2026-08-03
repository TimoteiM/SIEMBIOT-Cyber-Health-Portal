from __future__ import annotations

from datetime import UTC, datetime

import pytest
from siembiot_worker.adapters.runtime import (
    AdapterInvocation,
    AdapterRuntime,
    BudgetLedger,
    BudgetLimits,
    CircuitBreaker,
    retain_provider_disagreement,
)
from siembiot_worker.collection.broker import FixtureBrokerResult

from .test_contract import descriptor


def broker_result(
    *,
    allowed: bool = True,
    reason_code: str = "fixture",
    data: dict[str, object] | None = None,
) -> FixtureBrokerResult:
    return FixtureBrokerResult(
        allowed=allowed,
        reason_code=reason_code,
        fixture_timestamp=datetime(2026, 8, 3, 12, tzinfo=UTC),
        scenario_id="healthy",
        scenario_sha256="a" * 64,
        data=data or {},
    )


def invocation(capability: str = "dns.lookup", **changes: object) -> AdapterInvocation:
    values: dict[str, object] = {
        "capability": capability,
        "broker_result": broker_result(),
    }
    values.update(changes)
    return AdapterInvocation(**values)  # type: ignore[arg-type]


def test_request_cost_and_concurrency_budgets_are_deterministic() -> None:
    ledger = BudgetLedger(BudgetLimits(max_requests=2, max_cost_units=3, max_concurrency=1))
    first = ledger.reserve(cost_units=1)
    assert first.allowed
    concurrent = ledger.reserve(cost_units=1)
    assert not concurrent.allowed and concurrent.reason_code == "concurrency_budget_exhausted"
    first.release()
    second = ledger.reserve(cost_units=2)
    assert second.allowed
    second.release()
    assert ledger.requests_used == 2
    assert ledger.cost_units_used == 3
    assert ledger.reserve(cost_units=0).reason_code == "request_budget_exhausted"

    cost_limited = BudgetLedger(BudgetLimits(max_requests=2, max_cost_units=1, max_concurrency=1))
    assert cost_limited.reserve(cost_units=2).reason_code == "cost_budget_exhausted"


def test_runtime_denies_capability_mismatch_retry_and_cancellation() -> None:
    runtime = AdapterRuntime(BudgetLedger(BudgetLimits()))
    mismatch = runtime.execute(descriptor(), invocation("http.head"))
    retry = runtime.execute(descriptor(), invocation(retry_count=1))
    cancelled = runtime.execute(descriptor(), invocation(), cancelled=lambda: True)
    assert mismatch.reason_code == "capability_not_declared"
    assert retry.reason_code == "retry_not_declared"
    assert cancelled.reason_code == "cancelled"


def test_provider_unavailability_is_structured_and_opens_circuit() -> None:
    breaker = CircuitBreaker(failure_threshold=2, recovery_after_steps=2)
    runtime = AdapterRuntime(BudgetLedger(BudgetLimits(max_requests=10)), breaker=breaker)
    unavailable = invocation(
        broker_result=broker_result(allowed=False, reason_code="provider_unavailable")
    )
    first = runtime.execute(descriptor(), unavailable)
    second = runtime.execute(descriptor(), unavailable)
    opened = runtime.execute(descriptor(), invocation())
    assert first.status == second.status == "unavailable"
    assert opened.reason_code == "circuit_open"

    breaker.advance(steps=2)
    recovered = runtime.execute(
        descriptor(), invocation(broker_result=broker_result(data={"ok": True}))
    )
    assert recovered.status == "success"
    assert breaker.state == "closed"


def test_runtime_accepts_no_executable_callback_or_unsafe_error_text() -> None:
    runtime = AdapterRuntime(BudgetLedger(BudgetLimits()))
    outcome = runtime.execute(
        descriptor(), invocation(broker_result=broker_result(allowed=False, reason_code="timeout"))
    )
    assert outcome.status == "error"
    assert outcome.reason_code == "adapter_error"
    with pytest.raises(ValueError, match="invalid_broker_reason_code"):
        broker_result(allowed=False, reason_code="secret value must never escape")


def test_provider_disagreement_and_confidence_are_retained() -> None:
    runtime = AdapterRuntime(BudgetLedger(BudgetLimits(max_requests=4)))
    first = runtime.execute(
        descriptor(adapter_id="fixture-dns-a"),
        invocation(broker_result=broker_result(data={"secure": True}), confidence=0.9),
    )
    second = runtime.execute(
        descriptor(adapter_id="fixture-dns-b"),
        invocation(broker_result=broker_result(data={"secure": False}), confidence=0.8),
    )
    aggregate = retain_provider_disagreement((first, second))
    assert aggregate.disagreement
    assert aggregate.confidence == pytest.approx(0.8)
    assert [item.adapter_id for item in aggregate.provider_results] == [
        "fixture-dns-a",
        "fixture-dns-b",
    ]
