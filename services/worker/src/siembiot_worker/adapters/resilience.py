"""Rate limiting, circuit breaking, quota accounting, and caching for adapters.

All four are deterministic and clock-injected so the same inputs always produce the
same decisions in tests and in production.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from siembiot_worker.adapters.contract import (
    AdapterError,
    CachePolicy,
    CollectionResult,
    CollectionStatus,
    RateLimitPolicy,
)

Clock = Callable[[], float]


class TokenBucketRateLimiter:
    def __init__(self, policy: RateLimitPolicy, clock: Clock) -> None:
        self._policy = policy
        self._clock = clock
        self._capacity = float(policy.burst)
        self._tokens = float(policy.burst)
        self._refill_per_second = policy.max_requests / policy.per_seconds
        self._updated_at = clock()
        self._last_release: float | None = None
        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        with self._lock:
            now = self._clock()
            elapsed = max(0.0, now - self._updated_at)
            self._tokens = min(self._capacity, self._tokens + elapsed * self._refill_per_second)
            self._updated_at = now
            if self._policy.minimum_interval_seconds > 0 and self._last_release is not None:
                if now - self._last_release < self._policy.minimum_interval_seconds:
                    return False
            if self._tokens < 1.0:
                return False
            self._tokens -= 1.0
            self._last_release = now
            return True

    def retry_after_seconds(self) -> float:
        with self._lock:
            if self._tokens >= 1.0:
                return 0.0
            return (1.0 - self._tokens) / self._refill_per_second


class BreakerState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(frozen=True)
class CircuitBreakerPolicy:
    failure_threshold: int = 5
    reset_after_seconds: float = 60.0
    half_open_successes: int = 2

    def __post_init__(self) -> None:
        if self.failure_threshold < 1 or self.reset_after_seconds <= 0:
            raise AdapterError("invalid_breaker_policy")


class CircuitBreaker:
    def __init__(self, policy: CircuitBreakerPolicy, clock: Clock) -> None:
        self._policy = policy
        self._clock = clock
        self._failures = 0
        self._successes = 0
        self._opened_at: float | None = None
        self._lock = threading.Lock()

    @property
    def state(self) -> BreakerState:
        with self._lock:
            return self._state()

    def _state(self) -> BreakerState:
        if self._opened_at is None:
            return BreakerState.CLOSED
        if self._clock() - self._opened_at >= self._policy.reset_after_seconds:
            return BreakerState.HALF_OPEN
        return BreakerState.OPEN

    def allows(self) -> bool:
        with self._lock:
            return self._state() is not BreakerState.OPEN

    def record_success(self) -> None:
        with self._lock:
            if self._state() is BreakerState.HALF_OPEN:
                self._successes += 1
                if self._successes >= self._policy.half_open_successes:
                    self._reset()
                return
            self._failures = 0

    def record_failure(self) -> None:
        with self._lock:
            if self._state() is BreakerState.HALF_OPEN:
                self._opened_at = self._clock()
                self._successes = 0
                return
            self._failures += 1
            if self._failures >= self._policy.failure_threshold:
                self._opened_at = self._clock()
                self._successes = 0

    def _reset(self) -> None:
        self._failures = 0
        self._successes = 0
        self._opened_at = None


@dataclass
class QuotaLedger:
    """Per-adapter usage accounting; the budget is a ceiling, never a soft target."""

    limit: int | None = None
    used: int = 0
    denied: int = 0

    def try_consume(self, units: int = 1) -> bool:
        if units < 1:
            raise AdapterError("invalid_quota_units")
        if self.limit is not None and self.used + units > self.limit:
            self.denied += units
            return False
        self.used += units
        return True

    @property
    def remaining(self) -> int | None:
        return None if self.limit is None else max(0, self.limit - self.used)

    @property
    def exhausted(self) -> bool:
        return self.remaining == 0


@dataclass
class _CacheEntry:
    result: CollectionResult
    stored_at: float


class ResultCache:
    def __init__(self, policy: CachePolicy, clock: Clock) -> None:
        self._policy = policy
        self._clock = clock
        self._entries: dict[str, _CacheEntry] = {}

    def get(self, key: str) -> CollectionResult | None:
        if not self._policy.cacheable:
            return None
        entry = self._entries.get(key)
        if entry is None:
            return None
        if self._clock() - entry.stored_at >= self._policy.ttl_seconds:
            del self._entries[key]
            return None
        provenance = entry.result.provenance
        cached_provenance = type(provenance)(
            provenance.adapter_id,
            provenance.adapter_version,
            provenance.collected_at,
            provenance.observed_at,
            True,
            provenance.source_reference,
        )
        return type(entry.result)(
            entry.result.status,
            cached_provenance,
            entry.result.payload,
            entry.result.reason_code,
            entry.result.partial_reasons,
        )

    def put(self, key: str, result: CollectionResult) -> None:
        if not self._policy.cacheable or not result.usable:
            return
        self._entries[key] = _CacheEntry(result, self._clock())

    def invalidate(self, key: str) -> None:
        self._entries.pop(key, None)


@dataclass(frozen=True)
class GuardDecision:
    permitted: bool
    reason_code: str | None = None
    retry_after_seconds: float = 0.0


class AdapterGuard:
    """Combines quota, rate limit, and breaker into one decision per call."""

    def __init__(
        self,
        *,
        rate_limiter: TokenBucketRateLimiter,
        breaker: CircuitBreaker,
        quota: QuotaLedger,
    ) -> None:
        self._rate_limiter = rate_limiter
        self._breaker = breaker
        self._quota = quota

    @property
    def quota(self) -> QuotaLedger:
        return self._quota

    @property
    def breaker_state(self) -> BreakerState:
        return self._breaker.state

    def acquire(self) -> GuardDecision:
        if not self._breaker.allows():
            return GuardDecision(False, "circuit_open")
        if not self._quota.try_consume():
            return GuardDecision(False, "quota_exhausted")
        if not self._rate_limiter.try_acquire():
            self._quota.used -= 1
            return GuardDecision(False, "rate_limited", self._rate_limiter.retry_after_seconds())
        return GuardDecision(True)

    def record(self, result: CollectionResult) -> None:
        if result.status in {CollectionStatus.ERROR, CollectionStatus.UNAVAILABLE}:
            self._breaker.record_failure()
        else:
            self._breaker.record_success()


@dataclass(frozen=True)
class ProviderClaim:
    """One provider's answer about one subject, kept attributable."""

    adapter_id: str
    verdict: str
    confidence: float
    payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise AdapterError("invalid_confidence")


@dataclass(frozen=True)
class DisagreementSummary:
    """Providers that disagree stay visible; the platform never invents consensus."""

    subject: str
    claims: tuple[ProviderClaim, ...]
    verdicts: tuple[str, ...]
    agreed: bool
    majority_verdict: str | None
    dissenting_adapters: tuple[str, ...]

    @property
    def contested(self) -> bool:
        return not self.agreed


def summarize_claims(subject: str, claims: tuple[ProviderClaim, ...]) -> DisagreementSummary:
    if not claims:
        return DisagreementSummary(subject, (), (), True, None, ())
    ordered = tuple(sorted(claims, key=lambda claim: claim.adapter_id))
    verdicts = tuple(sorted({claim.verdict for claim in ordered}))
    if len(verdicts) == 1:
        return DisagreementSummary(subject, ordered, verdicts, True, verdicts[0], ())
    tally: dict[str, int] = {}
    for claim in ordered:
        tally[claim.verdict] = tally.get(claim.verdict, 0) + 1
    top = max(tally.values())
    leaders = sorted(verdict for verdict, count in tally.items() if count == top)
    majority = leaders[0] if len(leaders) == 1 else None
    dissenting = tuple(
        claim.adapter_id for claim in ordered if majority is None or claim.verdict != majority
    )
    return DisagreementSummary(subject, ordered, verdicts, False, majority, dissenting)
