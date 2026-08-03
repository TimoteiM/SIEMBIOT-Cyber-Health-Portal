from __future__ import annotations

from typing import Any

import pytest
from siembiot_worker.adapters.runtime import (
    AdapterRuntime,
    BudgetLedger,
    BudgetLimits,
    CircuitBreaker,
    ProviderUnavailableError,
    retain_provider_disagreement,
)

from .test_contract import descriptor


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
    called = False

    def operation() -> dict[str, bool]:
        nonlocal called
        called = True
        return {"ok": True}

    mismatch = runtime.execute(descriptor(), "http.head", operation)
    retry = runtime.execute(descriptor(), "dns.lookup", operation, retry_count=1)
    cancelled = runtime.execute(descriptor(), "dns.lookup", operation, cancelled=lambda: True)
    assert mismatch.reason_code == "capability_not_declared"
    assert retry.reason_code == "retry_not_declared"
    assert cancelled.reason_code == "cancelled"
    assert not called


def test_provider_unavailability_is_structured_and_opens_circuit() -> None:
    breaker = CircuitBreaker(failure_threshold=2, recovery_after_steps=2)
    runtime = AdapterRuntime(BudgetLedger(BudgetLimits(max_requests=10)), breaker=breaker)

    def unavailable() -> dict[str, Any]:
        raise ProviderUnavailableError("fixture_provider_unavailable")

    first = runtime.execute(descriptor(), "dns.lookup", unavailable)
    second = runtime.execute(descriptor(), "dns.lookup", unavailable)
    opened = runtime.execute(descriptor(), "dns.lookup", lambda: {"unexpected": True})
    assert first.status == second.status == "unavailable"
    assert opened.reason_code == "circuit_open"

    breaker.advance(steps=2)
    recovered = runtime.execute(descriptor(), "dns.lookup", lambda: {"ok": True})
    assert recovered.status == "success"
    assert breaker.state == "closed"


def test_operation_runs_once_and_safe_errors_do_not_leak_exception_text() -> None:
    runtime = AdapterRuntime(BudgetLedger(BudgetLimits()))
    calls = 0

    def broken() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        raise RuntimeError("secret value must never escape")

    outcome = runtime.execute(descriptor(), "dns.lookup", broken)
    assert calls == 1
    assert outcome.status == "error"
    assert outcome.reason_code == "adapter_error"
    assert "secret" not in repr(outcome)


def test_provider_disagreement_and_confidence_are_retained() -> None:
    runtime = AdapterRuntime(BudgetLedger(BudgetLimits(max_requests=4)))
    first = runtime.execute(
        descriptor(adapter_id="fixture-dns-a"),
        "dns.lookup",
        lambda: {"secure": True},
        confidence=0.9,
    )
    second = runtime.execute(
        descriptor(adapter_id="fixture-dns-b"),
        "dns.lookup",
        lambda: {"secure": False},
        confidence=0.8,
    )
    aggregate = retain_provider_disagreement((first, second))
    assert aggregate.disagreement
    assert aggregate.confidence == pytest.approx(0.8)
    assert [item.adapter_id for item in aggregate.provider_results] == [
        "fixture-dns-a",
        "fixture-dns-b",
    ]
