"""The single network gate available to collectors.

Collectors receive this object and nothing else. Every operation re-authorizes the
tenant at each checkpoint, resolves immediately before connecting, pins the answered
address, and re-authorizes again after any redirect.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

from siembiot_worker.network_safety.address_policy import authorize_resolved_addresses
from siembiot_worker.network_safety.collection_policy import (
    CollectionDestination,
    OperationClass,
    authorize_collection_redirect,
    body_required,
)
from siembiot_worker.network_safety.dns_client import BoundedDNSClient, DNSQuery, DNSRecordSet
from siembiot_worker.network_safety.models import (
    BrokerCheckpoint,
    NetworkBudget,
    PolicyDecision,
    TransportResponse,
)
from siembiot_worker.network_safety.port_probe import (
    PROBE_CONNECT_TIMEOUT_SECONDS,
    PROBE_READ_TIMEOUT_SECONDS,
    PortConnector,
    PortObservation,
    decode_banner,
)
from siembiot_worker.network_safety.smtp_probe import (
    UNREACHABLE as SMTP_UNREACHABLE,
)
from siembiot_worker.network_safety.smtp_probe import (
    MailTransportObservation,
    MailTransportProber,
)
from siembiot_worker.network_safety.tls_client import (
    ProtocolProbeResult,
    TLSInspector,
    TLSObservation,
)
from siembiot_worker.network_safety.transport import NetworkTransportError, RequestDestination
from siembiot_worker.network_safety.url_policy import DestinationPolicyError


@dataclass(frozen=True)
class CollectionRequest:
    organization_id: UUID
    domain_id: UUID
    assessment_id: UUID | None
    operation_class: OperationClass
    canonical_host: str
    authorized_hosts: tuple[str, ...] = ()

    @property
    def redirect_hosts(self) -> frozenset[str]:
        return frozenset({self.canonical_host, *self.authorized_hosts})


@dataclass(frozen=True)
class HTTPCollectionResult:
    allowed: bool
    reason_code: str
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    raw_headers: tuple[tuple[str, str], ...] = ()
    body: bytes = field(default=b"", repr=False)
    redirect_count: int = 0
    redirect_chain: tuple[str, ...] = ()
    final_url: str | None = None


class CollectionPolicyAuthorizer(Protocol):
    def authorize(
        self,
        request: CollectionRequest,
        checkpoint: BrokerCheckpoint,
        target_host: str,
    ) -> PolicyDecision: ...


class CollectionTransport(Protocol):
    def get(
        self,
        destination: RequestDestination,
        address: str,
        budget: NetworkBudget,
        checkpoint: Callable[[BrokerCheckpoint], None],
        method: str = "GET",
        *,
        read_body: bool = True,
        extra_headers: Mapping[str, str] | None = None,
    ) -> TransportResponse: ...


class CollectionResolver(Protocol):
    def resolve(self, host: str) -> tuple[str, ...]: ...


class _PolicyDeniedError(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


COLLECTION_BUDGET = NetworkBudget(
    connect_timeout_seconds=3.0,
    read_timeout_seconds=3.0,
    total_timeout_seconds=8.0,
    max_header_bytes=32_768,
    max_body_bytes=262_144,
    max_redirects=4,
    max_concurrency=4,
)


class CollectionNetworkBroker:
    def __init__(
        self,
        *,
        resolver: CollectionResolver,
        transport: CollectionTransport,
        policy: CollectionPolicyAuthorizer,
        dns_client: BoundedDNSClient,
        tls_inspector: TLSInspector | None = None,
        prober: PortConnector | None = None,
        mail_prober: MailTransportProber | None = None,
        budget: NetworkBudget | None = None,
        record_decision: Callable[[dict[str, object]], None] | None = None,
    ) -> None:
        self._resolver = resolver
        self._transport = transport
        self._policy = policy
        self._dns = dns_client
        self._tls = tls_inspector
        self._prober = prober
        self._mail_prober = mail_prober
        self._budget = budget or COLLECTION_BUDGET
        self._record_decision = record_decision or (lambda _: None)
        self._capacity = threading.BoundedSemaphore(self._budget.max_concurrency)

    # -- DNS -----------------------------------------------------------------

    def query_dns(
        self,
        request: CollectionRequest,
        name: str,
        record_type: str,
        *,
        want_dnssec: bool = False,
    ) -> DNSRecordSet:
        decision = self._policy.authorize(request, BrokerCheckpoint.BEFORE_RESOLUTION, name)
        if not decision.allowed:
            self._record(request, False, decision.reason_code, name, 0, 0)
            return DNSRecordSet(DNSQuery(name, record_type.upper()), "error")
        answer = self._dns.query(name, record_type, want_dnssec=want_dnssec)
        self._record(request, True, answer.status, name, 0, len(answer.records))
        return answer

    # -- TLS -----------------------------------------------------------------

    def inspect_tls(
        self, request: CollectionRequest, *, probe_protocols: bool = False
    ) -> tuple[TLSObservation, tuple[ProtocolProbeResult, ...]]:
        if self._tls is None:
            return TLSObservation("error", verification_error="tls_inspector_unavailable"), ()
        if not self._capacity.acquire(blocking=False):
            return TLSObservation("error", verification_error="concurrency_limit"), ()
        host = request.canonical_host
        try:
            address = self._pin_address(request, host)
        except _PolicyDeniedError as exc:
            self._capacity.release()
            self._record(request, False, exc.reason, host, 0, 0)
            return TLSObservation("error", verification_error=exc.reason), ()
        try:
            observation = self._tls.inspect_certificate(address, 443, host)
            probes: tuple[ProtocolProbeResult, ...] = ()
            if probe_protocols and observation.is_conclusive:
                self._authorize(request, BrokerCheckpoint.BEFORE_CONNECT, host)
                probes = self._tls.probe_protocols(address, 443, host)
            self._record(request, True, observation.status, host, 0, 1)
            return observation, probes
        except _PolicyDeniedError as exc:
            self._record(request, False, exc.reason, host, 0, 0)
            return TLSObservation("error", verification_error=exc.reason), ()
        finally:
            self._capacity.release()

    # -- ports ---------------------------------------------------------------

    def probe_ports(
        self, request: CollectionRequest, ports: Sequence[int]
    ) -> tuple[PortObservation, ...]:
        """Probe a bounded set of ports on the request's host.

        The address is resolved and pinned once, then every port is probed against that
        same address. Resolving per port would let a name that changes mid-scan move the
        probe onto a host nobody authorized -- and it would also make the audit record
        ambiguous about what was actually touched.

        Refusals are returned as observations rather than raised. A run that could not
        probe is evidence about our reach, and swallowing it would leave the report
        claiming a clean surface it never looked at.
        """
        if request.operation_class is not OperationClass.PORT_PROBE:
            return tuple(PortObservation(port, "error") for port in ports)
        if self._prober is None:
            return tuple(PortObservation(port, "error") for port in ports)
        if not self._capacity.acquire(blocking=False):
            return tuple(PortObservation(port, "error") for port in ports)

        host = request.canonical_host
        try:
            address = self._pin_address(request, host)
        except _PolicyDeniedError as exc:
            self._capacity.release()
            self._record(request, False, exc.reason, host, 0, 0)
            return tuple(PortObservation(port, "error") for port in ports)

        observations: list[PortObservation] = []
        try:
            for port in ports:
                # Re-authorized per port, so an emergency control pulled halfway through
                # stops the scan rather than being noticed at the end of it.
                self._authorize(request, BrokerCheckpoint.BEFORE_CONNECT, host)
                state, raw = self._prober.probe(
                    address,
                    port,
                    min(self._budget.connect_timeout_seconds, PROBE_CONNECT_TIMEOUT_SECONDS),
                    min(self._budget.read_timeout_seconds, PROBE_READ_TIMEOUT_SECONDS),
                )
                observations.append(PortObservation(port, state, decode_banner(raw)))
        except _PolicyDeniedError as exc:
            self._record(request, False, exc.reason, host, 0, len(observations))
            # What was already observed is kept. Half a scan is evidence; discarding it
            # would report the same as never having looked.
            return tuple(observations)
        finally:
            self._capacity.release()

        self._record(request, True, "probed", host, 0, len(observations))
        return tuple(observations)

    # -- mail transport ------------------------------------------------------

    def probe_mail_transport(
        self, request: CollectionRequest, mail_host: str
    ) -> MailTransportObservation:
        """Ask one published MX host whether it offers STARTTLS.

        The mail host is deliberately not the request's host: a domain's mail very often
        runs on somebody else's machine, and requiring them to match would mean this only
        ever worked for organisations self-hosting their own mail -- which is to say, the
        ones least likely to be the interesting case.

        The address policy still applies to whatever the MX name resolves to. An MX
        record pointing into private space is refused like anything else, and reported as
        unreachable rather than raised, so one odd mail host cannot fail the assessment.
        """
        if request.operation_class is not OperationClass.SMTP_STARTTLS:
            return MailTransportObservation(mail_host, SMTP_UNREACHABLE)
        if self._mail_prober is None:
            return MailTransportObservation(mail_host, SMTP_UNREACHABLE)
        if not self._capacity.acquire(blocking=False):
            return MailTransportObservation(mail_host, SMTP_UNREACHABLE)

        try:
            address = self._pin_address(request, mail_host)
            observation = self._mail_prober.probe(address, mail_host)
        except _PolicyDeniedError as exc:
            self._record(request, False, exc.reason, mail_host, 0, 0)
            return MailTransportObservation(mail_host, SMTP_UNREACHABLE)
        finally:
            # Held across the connection, not just the resolution: the semaphore bounds
            # how many sockets this worker has open at once, and releasing before the
            # probe would make it bound nothing at all.
            self._capacity.release()

        self._record(request, True, observation.state, mail_host, 0, 1)
        return observation

    # -- HTTP ----------------------------------------------------------------

    def fetch(
        self,
        request: CollectionRequest,
        destination: CollectionDestination,
        *,
        method: str = "GET",
        follow_redirects: bool = True,
        credentials: Mapping[str, str] | None = None,
    ) -> HTTPCollectionResult:
        """Fetch a destination under the collection policy.

        `credentials` are request headers that authenticate us to a provider. They are
        sent only while the request is still aimed at the host they were issued for: a
        redirect that changes host drops them, so a provider that is compromised or
        merely misconfigured cannot forward our key to somebody else. Nothing records
        them -- the audit row carries the host, the reason and the counts, never the
        headers.
        """
        issued_for = destination.host
        if destination.operation_class is not request.operation_class:
            return HTTPCollectionResult(False, "operation_class_mismatch")
        if not self._capacity.acquire(blocking=False):
            return HTTPCollectionResult(False, "concurrency_limit")
        redirects = 0
        chain: list[str] = [destination.url]
        address_count = 0
        try:
            while True:
                address = self._pin_address(request, destination.host)
                address_count += 1
                response = self._transport.get(
                    destination,
                    address,
                    self._budget,
                    lambda checkpoint: self._authorize(request, checkpoint, destination.host),
                    method,
                    read_body=body_required(destination.operation_class),
                    extra_headers=credentials if destination.host == issued_for else None,
                )
                if len(response.body) > self._budget.max_body_bytes:
                    return self._finish(
                        request, False, "response_too_large", destination, redirects, chain
                    )
                redirecting = response.status_code in {301, 302, 303, 307, 308}
                if not redirecting or not follow_redirects:
                    return self._finish(
                        request,
                        True,
                        "allowed",
                        destination,
                        redirects,
                        chain,
                        response=response,
                    )
                if redirects >= self._budget.max_redirects:
                    return self._finish(
                        request, False, "redirect_limit", destination, redirects, chain
                    )
                location = response.headers.get("location")
                if location is None:
                    return self._finish(
                        request, False, "destination_rejected", destination, redirects, chain
                    )
                self._authorize(request, BrokerCheckpoint.BEFORE_REDIRECT, destination.host)
                destination = authorize_collection_redirect(
                    destination, location, authorized_hosts=request.redirect_hosts
                )
                chain.append(destination.url)
                redirects += 1
        except _PolicyDeniedError as exc:
            return self._finish(request, False, exc.reason, destination, redirects, chain)
        except DestinationPolicyError as exc:
            return self._finish(request, False, exc.reason, destination, redirects, chain)
        except NetworkTransportError as exc:
            return self._finish(request, False, exc.reason, destination, redirects, chain)
        finally:
            self._capacity.release()

    # -- internals -----------------------------------------------------------

    def _pin_address(self, request: CollectionRequest, host: str) -> str:
        self._authorize(request, BrokerCheckpoint.BEFORE_RESOLUTION, host)
        try:
            raw_addresses = self._resolver.resolve(host)
        except OSError as exc:
            raise _PolicyDeniedError("no_addresses") from exc
        decision = authorize_resolved_addresses(raw_addresses)
        if not decision.allowed:
            raise _PolicyDeniedError(decision.reason_code)
        self._authorize(request, BrokerCheckpoint.AFTER_RESOLUTION, host)
        self._authorize(request, BrokerCheckpoint.BEFORE_CONNECT, host)
        return decision.addresses[0]

    def _authorize(
        self, request: CollectionRequest, checkpoint: BrokerCheckpoint, target_host: str
    ) -> None:
        decision = self._policy.authorize(request, checkpoint, target_host)
        if not decision.allowed:
            raise _PolicyDeniedError(decision.reason_code)

    def _record(
        self,
        request: CollectionRequest,
        allowed: bool,
        reason: str,
        target_host: str,
        redirects: int,
        answer_count: int,
    ) -> None:
        self._record_decision(
            {
                "allowed": allowed,
                "reason_code": reason,
                "operation_class": str(request.operation_class),
                "organization_id": str(request.organization_id),
                "canonical_host": target_host,
                "redirect_count": redirects,
                "answer_count": answer_count,
            }
        )

    def _finish(
        self,
        request: CollectionRequest,
        allowed: bool,
        reason: str,
        destination: CollectionDestination,
        redirects: int,
        chain: list[str],
        *,
        response: TransportResponse | None = None,
    ) -> HTTPCollectionResult:
        self._record(request, allowed, reason, destination.host, redirects, 0)
        if not allowed or response is None:
            return HTTPCollectionResult(
                False, reason, redirect_count=redirects, redirect_chain=tuple(chain)
            )
        return HTTPCollectionResult(
            True,
            reason,
            response.status_code,
            dict(response.headers),
            response.raw_headers,
            response.body,
            redirects,
            tuple(chain),
            destination.url,
        )
