from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Protocol

from siembiot_worker.network_safety.address_policy import authorize_resolved_addresses
from siembiot_worker.network_safety.models import (
    BrokerCheckpoint,
    BrokerResult,
    NetworkBudget,
    PolicyDecision,
    TransportResponse,
    VerificationFetchRequest,
)
from siembiot_worker.network_safety.transport import NetworkTransportError
from siembiot_worker.network_safety.url_policy import (
    DestinationPolicyError,
    VerificationDestination,
    authorize_redirect,
)


class Resolver(Protocol):
    def resolve(self, host: str) -> tuple[str, ...]: ...


class Transport(Protocol):
    def get(
        self,
        destination: VerificationDestination,
        address: str,
        budget: NetworkBudget,
        checkpoint: Callable[[BrokerCheckpoint], None],
    ) -> TransportResponse: ...


class PolicyAuthorizer(Protocol):
    def authorize(
        self,
        request: VerificationFetchRequest,
        checkpoint: BrokerCheckpoint,
        destination: VerificationDestination,
    ) -> PolicyDecision: ...


class _PolicyDeniedError(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class NetworkSafetyBroker:
    """The only purpose-specific route from an ownership check to the network."""

    def __init__(
        self,
        *,
        resolver: Resolver,
        transport: Transport,
        policy: PolicyAuthorizer,
        budget: NetworkBudget | None = None,
        record_decision: Callable[[dict[str, object]], None] | None = None,
    ) -> None:
        self._resolver = resolver
        self._transport = transport
        self._policy = policy
        self._budget = budget or NetworkBudget()
        self._record_decision = record_decision or (lambda _: None)
        self._capacity = threading.BoundedSemaphore(self._budget.max_concurrency)

    def fetch_https_verification(self, request: VerificationFetchRequest) -> BrokerResult:
        if not self._capacity.acquire(blocking=False):
            return self._finish(request, False, "concurrency_limit", 0, 0)
        redirects = 0
        address_count = 0
        try:
            destination = VerificationDestination.https(request.canonical_host)
            while True:
                self._authorize(request, BrokerCheckpoint.BEFORE_RESOLUTION, destination)
                try:
                    raw_addresses = self._resolver.resolve(destination.host)
                except OSError:
                    return self._finish(request, False, "no_addresses", redirects, 0)
                address_count = len(raw_addresses)
                decision = authorize_resolved_addresses(raw_addresses)
                if not decision.allowed:
                    return self._finish(
                        request, False, decision.reason_code, redirects, address_count
                    )
                self._authorize(request, BrokerCheckpoint.AFTER_RESOLUTION, destination)
                self._authorize(request, BrokerCheckpoint.BEFORE_CONNECT, destination)
                response = self._transport.get(
                    destination,
                    decision.addresses[0],
                    self._budget,
                    lambda checkpoint: self._authorize(request, checkpoint, destination),
                )
                if len(response.body) > self._budget.max_body_bytes:
                    return self._finish(
                        request, False, "response_too_large", redirects, address_count
                    )
                if response.status_code not in {301, 302, 303, 307, 308}:
                    return self._finish(
                        request,
                        True,
                        "allowed",
                        redirects,
                        address_count,
                        status=response.status_code,
                        body=response.body,
                    )
                if redirects >= self._budget.max_redirects:
                    return self._finish(request, False, "redirect_limit", redirects, address_count)
                self._authorize(request, BrokerCheckpoint.BEFORE_REDIRECT, destination)
                location = response.headers.get("location")
                if location is None:
                    return self._finish(
                        request, False, "destination_rejected", redirects, address_count
                    )
                destination = authorize_redirect(
                    destination,
                    location,
                    authorized_hosts=set(request.authorized_redirect_hosts),
                )
                redirects += 1
        except _PolicyDeniedError as exc:
            return self._finish(request, False, exc.reason, redirects, address_count)
        except DestinationPolicyError as exc:
            return self._finish(request, False, exc.reason, redirects, address_count)
        except NetworkTransportError as exc:
            return self._finish(request, False, exc.reason, redirects, address_count)
        finally:
            self._capacity.release()

    def _authorize(
        self,
        request: VerificationFetchRequest,
        checkpoint: BrokerCheckpoint,
        destination: VerificationDestination,
    ) -> None:
        decision = self._policy.authorize(request, checkpoint, destination)
        if not decision.allowed:
            raise _PolicyDeniedError(decision.reason_code)

    def _finish(
        self,
        request: VerificationFetchRequest,
        allowed: bool,
        reason: str,
        redirects: int,
        address_count: int,
        *,
        status: int | None = None,
        body: bytes = b"",
    ) -> BrokerResult:
        self._record_decision(
            {
                "allowed": allowed,
                "reason_code": reason,
                "operation_class": "https_verification",
                "canonical_host": request.canonical_host,
                "redirect_count": redirects,
                "address_count": address_count,
            }
        )
        return BrokerResult(allowed, reason, status, body if allowed else b"", redirects)
