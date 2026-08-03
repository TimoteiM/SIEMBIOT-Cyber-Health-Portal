from __future__ import annotations

import json
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal

from siembiot_worker.adapters.contracts import AdapterDescriptor


class ProviderUnavailableError(RuntimeError):
    def __init__(self, reason_code: str = "provider_unavailable") -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class BudgetLimits:
    max_requests: int = 100
    max_cost_units: int = 100
    max_concurrency: int = 4


class BudgetLease:
    def __init__(
        self, *, allowed: bool, reason_code: str, release_callback: Callable[[], None] | None
    ) -> None:
        self.allowed = allowed
        self.reason_code = reason_code
        self._release_callback = release_callback
        self._released = False

    def release(self) -> None:
        if not self._released and self._release_callback is not None:
            self._released = True
            self._release_callback()


class BudgetLedger:
    def __init__(self, limits: BudgetLimits) -> None:
        if min(limits.max_requests, limits.max_concurrency) <= 0 or limits.max_cost_units < 0:
            raise ValueError("invalid_budget")
        self._limits = limits
        self._lock = threading.Lock()
        self._requests_used = 0
        self._cost_units_used = 0
        self._active = 0

    @property
    def requests_used(self) -> int:
        return self._requests_used

    @property
    def cost_units_used(self) -> int:
        return self._cost_units_used

    def reserve(self, *, cost_units: int) -> BudgetLease:
        if cost_units < 0:
            raise ValueError("invalid_cost")
        with self._lock:
            if self._active >= self._limits.max_concurrency:
                return BudgetLease(
                    allowed=False,
                    reason_code="concurrency_budget_exhausted",
                    release_callback=None,
                )
            if self._requests_used >= self._limits.max_requests:
                return BudgetLease(
                    allowed=False,
                    reason_code="request_budget_exhausted",
                    release_callback=None,
                )
            if self._cost_units_used + cost_units > self._limits.max_cost_units:
                return BudgetLease(
                    allowed=False,
                    reason_code="cost_budget_exhausted",
                    release_callback=None,
                )
            self._requests_used += 1
            self._cost_units_used += cost_units
            self._active += 1
        return BudgetLease(allowed=True, reason_code="reserved", release_callback=self._release)

    def _release(self) -> None:
        with self._lock:
            self._active -= 1


class CircuitBreaker:
    def __init__(self, *, failure_threshold: int = 3, recovery_after_steps: int = 3) -> None:
        if failure_threshold <= 0 or recovery_after_steps <= 0:
            raise ValueError("invalid_circuit_policy")
        self._failure_threshold = failure_threshold
        self._recovery_after_steps = recovery_after_steps
        self._failures = 0
        self._step = 0
        self._reopen_at = 0
        self._state: Literal["closed", "open", "half_open"] = "closed"
        self._probe_active = False

    @property
    def state(self) -> Literal["closed", "open", "half_open"]:
        return self._state

    def advance(self, *, steps: int = 1) -> None:
        if steps < 0:
            raise ValueError("invalid_steps")
        self._step += steps

    def allow(self) -> bool:
        if self._state == "closed":
            return True
        if self._state == "open" and self._step >= self._reopen_at:
            self._state = "half_open"
            self._probe_active = False
        if self._state == "half_open" and not self._probe_active:
            self._probe_active = True
            return True
        return False

    def success(self) -> None:
        self._failures = 0
        self._state = "closed"
        self._probe_active = False

    def failure(self) -> None:
        self._failures += 1
        if self._state == "half_open" or self._failures >= self._failure_threshold:
            self._state = "open"
            self._reopen_at = self._step + self._recovery_after_steps
            self._probe_active = False


AdapterStatus = Literal["success", "unavailable", "denied", "cancelled", "error"]


@dataclass(frozen=True)
class AdapterOutcome:
    adapter_id: str
    status: AdapterStatus
    reason_code: str
    confidence: float
    data: Mapping[str, Any] = field(default_factory=dict, repr=False)


class AdapterRuntime:
    def __init__(self, ledger: BudgetLedger, *, breaker: CircuitBreaker | None = None) -> None:
        self._ledger = ledger
        self._breaker = breaker or CircuitBreaker()

    @staticmethod
    def _outcome(
        descriptor: AdapterDescriptor,
        status: AdapterStatus,
        reason: str,
        *,
        confidence: float = 0,
        data: Mapping[str, Any] | None = None,
    ) -> AdapterOutcome:
        return AdapterOutcome(
            descriptor.adapter_id,
            status,
            reason,
            confidence,
            MappingProxyType(dict(data or {})),
        )

    def execute(
        self,
        descriptor: AdapterDescriptor,
        capability: str,
        operation: Callable[[], Mapping[str, Any]],
        *,
        cost_units: int = 0,
        confidence: float = 1.0,
        retry_count: int = 0,
        cancelled: Callable[[], bool] | None = None,
    ) -> AdapterOutcome:
        if capability not in descriptor.capabilities:
            return self._outcome(descriptor, "denied", "capability_not_declared")
        if retry_count and not descriptor.retries_allowed:
            return self._outcome(descriptor, "denied", "retry_not_declared")
        if cancelled is not None and cancelled():
            return self._outcome(descriptor, "cancelled", "cancelled")
        if not self._breaker.allow():
            return self._outcome(descriptor, "unavailable", "circuit_open")
        lease = self._ledger.reserve(cost_units=cost_units)
        if not lease.allowed:
            return self._outcome(descriptor, "denied", lease.reason_code)
        try:
            result = operation()
            if cancelled is not None and cancelled():
                return self._outcome(descriptor, "cancelled", "cancelled")
        except ProviderUnavailableError as exc:
            self._breaker.failure()
            return self._outcome(descriptor, "unavailable", exc.reason_code)
        except Exception:
            self._breaker.failure()
            return self._outcome(descriptor, "error", "adapter_error")
        finally:
            lease.release()
        self._breaker.success()
        return self._outcome(descriptor, "success", "fixture", confidence=confidence, data=result)


@dataclass(frozen=True)
class ProviderAggregate:
    disagreement: bool
    confidence: float
    provider_results: tuple[AdapterOutcome, ...]


def retain_provider_disagreement(outcomes: tuple[AdapterOutcome, ...]) -> ProviderAggregate:
    ordered = tuple(sorted(outcomes, key=lambda item: item.adapter_id))
    successful = tuple(item for item in ordered if item.status == "success")
    representations = {
        json.dumps(dict(item.data), sort_keys=True, separators=(",", ":")) for item in successful
    }
    confidence = min((item.confidence for item in successful), default=0)
    return ProviderAggregate(len(representations) > 1, confidence, ordered)
