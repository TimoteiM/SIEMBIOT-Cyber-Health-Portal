from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from siembiot_worker.network_safety.collection_broker import (
    CollectionNetworkBroker,
    CollectionRequest,
    CollectionResolver,
)
from siembiot_worker.network_safety.collection_policy import OperationClass
from siembiot_worker.network_safety.dns_client import BoundedDNSClient, DNSQuery, DNSRecordSet
from siembiot_worker.network_safety.models import (
    BrokerCheckpoint,
    NetworkBudget,
    PolicyDecision,
    TransportResponse,
)
from siembiot_worker.network_safety.tls_client import TLSInspector
from siembiot_worker.network_safety.transport import RequestDestination

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
ORGANIZATION = uuid4()
DOMAIN = uuid4()
FROZEN_NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def frozen_clock() -> datetime:
    return FROZEN_NOW


class ZoneDNSTransport:
    """Serves DNS answers from the golden zone fixtures; never touches the network."""

    def __init__(self, zones: dict[str, dict[str, Any]]) -> None:
        self._zones = zones
        self.calls: list[tuple[str, str]] = []

    def query(
        self,
        name: str,
        record_type: str,
        *,
        lifetime: float,
        want_dnssec: bool,
        per_server_timeout: float = 2.0,
    ) -> DNSRecordSet:
        self.calls.append((name, record_type))
        query = DNSQuery(name, record_type)
        for zone, records in self._zones.items():
            entry = records.get(f"{name}:{record_type}")
            if entry is None and name == zone:
                entry = records.get(record_type)
            if entry is not None:
                return DNSRecordSet(
                    query,
                    entry["status"],
                    tuple(entry.get("records", ())),
                    entry.get("authenticated", False),
                    entry.get("ttl_seconds"),
                )
        return DNSRecordSet(query, "no_records")


class RouteTransport:
    """Serves HTTP responses keyed by method and URL."""

    def __init__(self, routes: dict[str, TransportResponse]) -> None:
        self.routes = routes
        self.calls: list[str] = []
        #: Whether the broker asked for a body on each call, so a test can assert
        #: it did not rather than trust that it did not.
        self.body_requested: list[bool] = []
        self.headers_sent: list[dict[str, str]] = []

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
    ) -> TransportResponse:
        self.body_requested.append(read_body)
        #: Recorded so a test can assert a credential was, or was not, sent on a hop.
        self.headers_sent.append(dict(extra_headers or {}))
        url = f"{destination.scheme}://{destination.host}{destination.request_target}"
        self.calls.append(url)
        checkpoint(BrokerCheckpoint.AFTER_HEADERS)
        response = self.routes.get(url)
        if response is None:
            return TransportResponse(404, {}, b"", ())
        return response


class PublicResolver:
    def __init__(self, address: str = "93.184.216.34") -> None:
        self.address = address
        self.queries: list[str] = []

    def resolve(self, host: str) -> tuple[str, ...]:
        self.queries.append(host)
        return (self.address,)


class AllowAllPolicy:
    def authorize(
        self, request: CollectionRequest, checkpoint: BrokerCheckpoint, target_host: str
    ) -> PolicyDecision:
        return PolicyDecision(True, "allowed")


def response(
    status: int, headers: dict[str, str] | None = None, body: bytes = b""
) -> TransportResponse:
    header_map = headers or {}
    return TransportResponse(status, dict(header_map), body, tuple(header_map.items()))


def multi_header_response(
    status: int, raw_headers: tuple[tuple[str, str], ...], body: bytes = b""
) -> TransportResponse:
    collapsed: dict[str, str] = {}
    for name, value in raw_headers:
        collapsed.setdefault(name, value)
    return TransportResponse(status, collapsed, body, raw_headers)


def load_zones() -> dict[str, dict[str, Any]]:
    document = json.loads((FIXTURES / "dns" / "zones.json").read_text(encoding="utf-8"))
    return {key: value for key, value in document.items() if not key.startswith("_")}


ZONES = load_zones()


def build_broker(
    *,
    routes: dict[str, TransportResponse] | None = None,
    tls_inspector: TLSInspector | None = None,
    resolver: CollectionResolver | None = None,
    dns_transport: ZoneDNSTransport | None = None,
) -> CollectionNetworkBroker:
    return CollectionNetworkBroker(
        resolver=resolver or PublicResolver(),
        transport=RouteTransport(routes or {}),
        policy=AllowAllPolicy(),
        dns_client=BoundedDNSClient(dns_transport or ZoneDNSTransport(ZONES)),
        tls_inspector=tls_inspector,
    )


def request_for(
    host: str, operation_class: OperationClass = OperationClass.DNS_QUERY
) -> CollectionRequest:
    return CollectionRequest(ORGANIZATION, DOMAIN, None, operation_class, host, (host,))
