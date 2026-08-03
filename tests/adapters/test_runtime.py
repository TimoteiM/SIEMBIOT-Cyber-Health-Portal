from __future__ import annotations

import pytest
from siembiot_worker.adapters.runtime import (
    AdapterInvocation,
    AdapterRuntime,
    BudgetLedger,
    BudgetLimits,
    CircuitBreaker,
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
    mismatch = runtime.execute(descriptor(), AdapterInvocation("http.head", "success", "fixture"))
    retry = runtime.execute(
        descriptor(), AdapterInvocation("dns.lookup", "success", "fixture", retry_count=1)
    )
    cancelled = runtime.execute(
        descriptor(),
        AdapterInvocation("dns.lookup", "success", "fixture"),
        cancelled=lambda: True,
    )
    assert mismatch.reason_code == "capability_not_declared"
    assert retry.reason_code == "retry_not_declared"
    assert cancelled.reason_code == "cancelled"


def test_provider_unavailability_is_structured_and_opens_circuit() -> None:
    breaker = CircuitBreaker(failure_threshold=2, recovery_after_steps=2)
    runtime = AdapterRuntime(BudgetLedger(BudgetLimits(max_requests=10)), breaker=breaker)
    unavailable = AdapterInvocation("dns.lookup", "unavailable", "fixture_provider_unavailable")
    first = runtime.execute(descriptor(), unavailable)
    second = runtime.execute(descriptor(), unavailable)
    opened = runtime.execute(descriptor(), AdapterInvocation("dns.lookup", "success", "fixture"))
    assert first.status == second.status == "unavailable"
    assert opened.reason_code == "circuit_open"

    breaker.advance(steps=2)
    recovered = runtime.execute(
        descriptor(),
        AdapterInvocation("dns.lookup", "success", "fixture", {"ok": True}),
    )
    assert recovered.status == "success"
    assert breaker.state == "closed"


def test_runtime_accepts_no_executable_callback_or_unsafe_error_text() -> None:
    runtime = AdapterRuntime(BudgetLedger(BudgetLimits()))
    outcome = runtime.execute(
        descriptor(), AdapterInvocation("dns.lookup", "error", "adapter_error")
    )
    assert outcome.status == "error"
    assert outcome.reason_code == "adapter_error"
    with pytest.raises(ValueError, match="invalid_adapter_reason_code"):
        AdapterInvocation("dns.lookup", "error", "secret value must never escape")


def test_provider_disagreement_and_confidence_are_retained() -> None:
    runtime = AdapterRuntime(BudgetLedger(BudgetLimits(max_requests=4)))
    first = runtime.execute(
        descriptor(adapter_id="fixture-dns-a"),
        AdapterInvocation("dns.lookup", "success", "fixture", {"secure": True}, confidence=0.9),
    )
    second = runtime.execute(
        descriptor(adapter_id="fixture-dns-b"),
        AdapterInvocation("dns.lookup", "success", "fixture", {"secure": False}, confidence=0.8),
    )
    aggregate = retain_provider_disagreement((first, second))
    assert aggregate.disagreement
    assert aggregate.confidence == pytest.approx(0.8)
    assert [item.adapter_id for item in aggregate.provider_results] == [
        "fixture-dns-a",
        "fixture-dns-b",
    ]
