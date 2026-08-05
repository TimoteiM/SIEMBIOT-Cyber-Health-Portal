"""Live observation runtime.

This is the only place in the product that builds a broker over real sockets. Every
guarantee the fixture-backed tests rely on still applies here — address policy, redirect
revalidation, budgets, record-type allowlists — plus two the tests do not need:

* the mode allowlist, checked on every operation, so an unauthorized run cannot emit an
  authorization-gated operation class even if a collector asked for one;
* politeness limits, because a real third party is on the other end.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

from siembiot_worker.adapters.contract import RateLimitPolicy
from siembiot_worker.adapters.resilience import TokenBucketRateLimiter
from siembiot_worker.network_safety.collection_broker import (
    CollectionNetworkBroker,
    CollectionRequest,
)
from siembiot_worker.network_safety.collection_policy import OperationClass
from siembiot_worker.network_safety.dns_client import (
    BoundedDNSClient,
    DNSBudget,
    DnspythonTransport,
)
from siembiot_worker.network_safety.models import BrokerCheckpoint, NetworkBudget, PolicyDecision
from siembiot_worker.network_safety.resolver import SystemResolver
from siembiot_worker.network_safety.tls_client import SocketTLSConnector, TLSBudget, TLSInspector
from siembiot_worker.network_safety.transport import BoundedHTTPTransport
from siembiot_worker.observation.mode import AssessmentMode, allowed_operation_classes

#: Deliberately unhurried. A public-interest observatory has no reason to be fast, and
#: a slow, evenly spaced request is the difference between observing a site and
#: burdening it.
OBSERVATION_RATE_LIMIT = RateLimitPolicy(
    max_requests=2, per_seconds=1.0, burst=2, minimum_interval_seconds=0.25
)

OBSERVATION_NETWORK_BUDGET = NetworkBudget(
    connect_timeout_seconds=5.0,
    read_timeout_seconds=5.0,
    total_timeout_seconds=15.0,
    max_header_bytes=32_768,
    max_body_bytes=262_144,
    max_redirects=4,
    max_concurrency=2,
)


class ObservationHalted(RuntimeError):  # noqa: N818 - an operator stop, not a fault
    """Raised when an operator stops observation. Never swallowed."""


@dataclass
class KillSwitch:
    """An in-process emergency stop for runs that have no database behind them."""

    active: bool = False

    def halt(self) -> None:
        self.active = True


class ModeEnforcingPolicy:
    """Authorizes every broker checkpoint against the mode, limits and kill switch."""

    def __init__(
        self,
        mode: AssessmentMode,
        *,
        kill_switch: KillSwitch | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        rate_limit: RateLimitPolicy = OBSERVATION_RATE_LIMIT,
    ) -> None:
        self._mode = mode
        self._allowed = allowed_operation_classes(mode)
        self._kill_switch = kill_switch or KillSwitch()
        self._limiter = TokenBucketRateLimiter(rate_limit, clock)
        self._sleeper = sleeper
        self.decisions: list[dict[str, object]] = []

    def authorize(
        self, request: CollectionRequest, checkpoint: BrokerCheckpoint, target_host: str
    ) -> PolicyDecision:
        if self._kill_switch.active:
            return PolicyDecision(False, "emergency_control_active")
        if request.operation_class not in self._allowed:
            # Defence in depth: a collector should never ask for this, and if one does,
            # the request stops here rather than reaching the network.
            return PolicyDecision(False, "operation_class_requires_authorization")
        if checkpoint is BrokerCheckpoint.BEFORE_CONNECT:
            self._wait_for_capacity()
        return PolicyDecision(True, "allowed")

    def _wait_for_capacity(self) -> None:
        for _ in range(200):
            if self._limiter.try_acquire():
                return
            self._sleeper(max(0.05, self._limiter.retry_after_seconds()))
        raise ObservationHalted("rate_limiter_never_released")


@dataclass(frozen=True)
class ObservationRuntime:
    broker: CollectionNetworkBroker
    policy: ModeEnforcingPolicy
    mode: AssessmentMode

    def request(self, operation_class: OperationClass, host: str) -> CollectionRequest:
        """Build a request bound to this runtime's mode.

        ``organization_id`` and ``domain_id`` are stable synthetic identifiers for a
        passive run: there is no tenant, because nobody has claimed the domain. Nothing
        is written to a tenant's private evidence from an observation run.
        """
        return CollectionRequest(
            organization_id=OBSERVATORY_ORGANIZATION_ID,
            domain_id=OBSERVATORY_DOMAIN_ID,
            assessment_id=None,
            operation_class=operation_class,
            canonical_host=host,
            authorized_hosts=(host,),
        )


#: Reserved identifiers for public observation. They are not a tenant and never carry
#: tenant-private evidence; they exist so audit records have a stable subject.
OBSERVATORY_ORGANIZATION_ID = UUID("00000000-0000-4000-8000-000000000001")
OBSERVATORY_DOMAIN_ID = UUID("00000000-0000-4000-8000-000000000002")


def build_observation_runtime(
    *,
    mode: AssessmentMode = AssessmentMode.PASSIVE_OBSERVATION,
    kill_switch: KillSwitch | None = None,
    dns_budget: DNSBudget | None = None,
) -> ObservationRuntime:
    """Assemble a broker over live sockets, bounded and mode-limited."""
    policy = ModeEnforcingPolicy(mode, kill_switch=kill_switch)
    broker = CollectionNetworkBroker(
        resolver=SystemResolver(),
        transport=BoundedHTTPTransport(),
        policy=policy,
        dns_client=BoundedDNSClient(DnspythonTransport(), dns_budget or DNSBudget()),
        tls_inspector=TLSInspector(SocketTLSConnector(), TLSBudget()),
        budget=OBSERVATION_NETWORK_BUDGET,
        record_decision=policy.decisions.append,
    )
    return ObservationRuntime(broker=broker, policy=policy, mode=mode)
