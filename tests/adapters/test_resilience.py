from __future__ import annotations

from datetime import UTC, datetime

import pytest
from siembiot_worker.adapters.contract import (
    AdapterError,
    CachePolicy,
    CollectionResult,
    CollectionStatus,
    Provenance,
    RateLimitPolicy,
)
from siembiot_worker.adapters.resilience import (
    AdapterGuard,
    BreakerState,
    CircuitBreaker,
    CircuitBreakerPolicy,
    ProviderClaim,
    QuotaLedger,
    ResultCache,
    TokenBucketRateLimiter,
    summarize_claims,
)

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def current_state(breaker: CircuitBreaker) -> BreakerState:
    return breaker.state


def guard_state(guard: AdapterGuard) -> BreakerState:
    return guard.breaker_state


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def result(
    status: CollectionStatus = CollectionStatus.OK, reason: str | None = None
) -> CollectionResult:
    return CollectionResult(status, Provenance("dns_public", "1.0.0", NOW), {"value": 1}, reason)


# -- rate limiting -----------------------------------------------------------


def test_token_bucket_allows_burst_then_refills_over_time() -> None:
    clock = FakeClock()
    limiter = TokenBucketRateLimiter(RateLimitPolicy(2, 1.0, burst=2), clock)
    assert limiter.try_acquire() is True
    assert limiter.try_acquire() is True
    assert limiter.try_acquire() is False
    assert limiter.retry_after_seconds() == pytest.approx(0.5)
    clock.advance(0.5)
    assert limiter.try_acquire() is True


def test_minimum_interval_spaces_calls_even_when_tokens_remain() -> None:
    clock = FakeClock()
    limiter = TokenBucketRateLimiter(
        RateLimitPolicy(10, 1.0, burst=10, minimum_interval_seconds=0.2), clock
    )
    assert limiter.try_acquire() is True
    assert limiter.try_acquire() is False
    clock.advance(0.2)
    assert limiter.try_acquire() is True


# -- circuit breaker ---------------------------------------------------------


def test_breaker_opens_after_threshold_and_half_opens_after_reset() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker(CircuitBreakerPolicy(3, 60.0, 2), clock)
    for _ in range(3):
        breaker.record_failure()
    assert breaker.allows() is False
    assert current_state(breaker) == BreakerState.OPEN

    clock.advance(60.0)
    assert current_state(breaker) == BreakerState.HALF_OPEN
    assert breaker.allows() is True


def test_half_open_failure_reopens_immediately() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker(CircuitBreakerPolicy(2, 30.0, 2), clock)
    breaker.record_failure()
    breaker.record_failure()
    clock.advance(30.0)
    assert current_state(breaker) == BreakerState.HALF_OPEN
    breaker.record_failure()
    assert current_state(breaker) == BreakerState.OPEN


def test_half_open_closes_only_after_required_successes() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker(CircuitBreakerPolicy(2, 30.0, 2), clock)
    breaker.record_failure()
    breaker.record_failure()
    clock.advance(30.0)
    breaker.record_success()
    assert current_state(breaker) == BreakerState.HALF_OPEN
    breaker.record_success()
    assert current_state(breaker) == BreakerState.CLOSED


# -- quota -------------------------------------------------------------------


def test_quota_is_a_ceiling_not_a_target() -> None:
    ledger = QuotaLedger(limit=2)
    assert ledger.try_consume() is True
    assert ledger.try_consume() is True
    assert ledger.try_consume() is False
    assert ledger.exhausted is True
    assert ledger.remaining == 0
    assert ledger.denied == 1


def test_unlimited_quota_never_denies() -> None:
    ledger = QuotaLedger()
    assert all(ledger.try_consume() for _ in range(100))
    assert ledger.remaining is None
    assert ledger.exhausted is False


def test_quota_rejects_nonsensical_units() -> None:
    with pytest.raises(AdapterError):
        QuotaLedger().try_consume(0)


# -- guard -------------------------------------------------------------------


def build_guard(clock: FakeClock, *, limit: int | None = None) -> AdapterGuard:
    return AdapterGuard(
        rate_limiter=TokenBucketRateLimiter(RateLimitPolicy(1, 1.0, burst=1), clock),
        breaker=CircuitBreaker(CircuitBreakerPolicy(2, 10.0, 1), clock),
        quota=QuotaLedger(limit=limit),
    )


def test_guard_reports_the_specific_reason_it_refused() -> None:
    clock = FakeClock()
    guard = build_guard(clock)
    assert guard.acquire().permitted is True
    denied = guard.acquire()
    assert denied.permitted is False
    assert denied.reason_code == "rate_limited"
    assert denied.retry_after_seconds > 0


def test_rate_limited_call_does_not_consume_quota() -> None:
    clock = FakeClock()
    guard = build_guard(clock, limit=5)
    guard.acquire()
    guard.acquire()
    assert guard.quota.used == 1


def test_quota_exhaustion_is_reported_before_the_rate_limiter() -> None:
    clock = FakeClock()
    guard = build_guard(clock, limit=1)
    assert guard.acquire().permitted is True
    clock.advance(10.0)
    denied = guard.acquire()
    assert denied.reason_code == "quota_exhausted"


def test_repeated_errors_open_the_circuit_and_refuse_further_calls() -> None:
    clock = FakeClock()
    guard = build_guard(clock)
    for _ in range(2):
        guard.record(result(CollectionStatus.ERROR, "transport_error"))
    assert guard_state(guard) == BreakerState.OPEN
    assert guard.acquire().reason_code == "circuit_open"


def test_unavailable_counts_as_failure_but_not_applicable_does_not() -> None:
    clock = FakeClock()
    guard = build_guard(clock)
    guard.record(result(CollectionStatus.UNAVAILABLE, "provider_down"))
    guard.record(result(CollectionStatus.NOT_APPLICABLE, "no_mx"))
    assert guard_state(guard) == BreakerState.CLOSED


# -- cache -------------------------------------------------------------------


def test_cache_returns_entry_marked_from_cache_until_ttl_expires() -> None:
    clock = FakeClock()
    cache = ResultCache(CachePolicy(60), clock)
    cache.put("key", result())
    cached = cache.get("key")
    assert cached is not None
    assert cached.provenance.from_cache is True
    assert cached.payload == {"value": 1}

    clock.advance(60.0)
    assert cache.get("key") is None


def test_cache_is_disabled_when_terms_forbid_storage() -> None:
    clock = FakeClock()
    cache = ResultCache(CachePolicy(0, cacheable=False, provider_terms_permit_caching=False), clock)
    cache.put("key", result())
    assert cache.get("key") is None


def test_unusable_results_are_never_cached() -> None:
    clock = FakeClock()
    cache = ResultCache(CachePolicy(60), clock)
    cache.put("key", result(CollectionStatus.ERROR, "transport_error"))
    assert cache.get("key") is None


# -- provider disagreement ---------------------------------------------------


def test_agreeing_providers_produce_an_uncontested_summary() -> None:
    summary = summarize_claims(
        "example.test",
        (
            ProviderClaim("reputation_a", "clean", 0.9),
            ProviderClaim("reputation_b", "clean", 0.7),
        ),
    )
    assert summary.agreed is True
    assert summary.contested is False
    assert summary.majority_verdict == "clean"
    assert summary.dissenting_adapters == ()


def test_disagreement_is_preserved_rather_than_collapsed() -> None:
    summary = summarize_claims(
        "example.test",
        (
            ProviderClaim("reputation_a", "phishing", 0.8),
            ProviderClaim("reputation_b", "clean", 0.6),
            ProviderClaim("reputation_c", "clean", 0.5),
        ),
    )
    assert summary.contested is True
    assert summary.verdicts == ("clean", "phishing")
    assert summary.majority_verdict == "clean"
    assert summary.dissenting_adapters == ("reputation_a",)


def test_evenly_split_providers_yield_no_majority() -> None:
    summary = summarize_claims(
        "example.test",
        (
            ProviderClaim("reputation_a", "phishing", 0.8),
            ProviderClaim("reputation_b", "clean", 0.8),
        ),
    )
    assert summary.majority_verdict is None
    assert set(summary.dissenting_adapters) == {"reputation_a", "reputation_b"}


def test_claim_confidence_must_be_a_probability() -> None:
    with pytest.raises(AdapterError):
        ProviderClaim("reputation_a", "clean", 1.5)
