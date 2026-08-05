from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

import pytest
from siembiot_worker.network_safety.collection_broker import (
    CollectionNetworkBroker,
    CollectionRequest,
)
from siembiot_worker.network_safety.collection_policy import (
    CollectionDestination,
    OperationClass,
    authorize_collection_redirect,
    http_destination,
    https_destination,
    provider_destination,
)
from siembiot_worker.network_safety.dns_client import (
    BoundedDNSClient,
    DNSBudget,
    DNSQuery,
    DNSRecordSet,
)
from siembiot_worker.network_safety.models import (
    BrokerCheckpoint,
    NetworkBudget,
    PolicyDecision,
    TransportResponse,
)
from siembiot_worker.network_safety.transport import RequestDestination
from siembiot_worker.network_safety.url_policy import DestinationPolicyError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "network" / "destinations.json"
DESTINATIONS = json.loads(FIXTURES.read_text(encoding="utf-8"))
ORGANIZATION = uuid4()
DOMAIN = uuid4()
HOST = "example.test"


def collection_request(
    operation_class: OperationClass = OperationClass.HTTP_SURFACE,
    authorized_hosts: tuple[str, ...] = (),
) -> CollectionRequest:
    return CollectionRequest(ORGANIZATION, DOMAIN, None, operation_class, HOST, authorized_hosts)


class StaticResolver:
    def __init__(self, answers: list[tuple[str, ...]]) -> None:
        self.answers = answers
        self.queries: list[str] = []

    def resolve(self, host: str) -> tuple[str, ...]:
        self.queries.append(host)
        return self.answers.pop(0) if self.answers else ("93.184.216.34",)


class SequenceTransport:
    def __init__(self, responses: list[TransportResponse]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, str]] = []

    def get(
        self,
        destination: RequestDestination,
        address: str,
        budget: NetworkBudget,
        checkpoint: Callable[[BrokerCheckpoint], None],
        method: str = "GET",
    ) -> TransportResponse:
        self.calls.append((destination.host, destination.request_target, address))
        checkpoint(BrokerCheckpoint.AFTER_HEADERS)
        return self.responses.pop(0)


class AllowPolicy:
    def __init__(self, deny_at: BrokerCheckpoint | None = None) -> None:
        self.deny_at = deny_at
        self.checkpoints: list[BrokerCheckpoint] = []

    def authorize(
        self, request: CollectionRequest, checkpoint: BrokerCheckpoint, target_host: str
    ) -> PolicyDecision:
        self.checkpoints.append(checkpoint)
        if checkpoint == self.deny_at:
            return PolicyDecision(False, "emergency_control_active")
        return PolicyDecision(True, "allowed")


class FixtureDNSTransport:
    def __init__(self, answers: dict[tuple[str, str], DNSRecordSet]) -> None:
        self.answers = answers
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
        return self.answers.get(
            (name, record_type), DNSRecordSet(DNSQuery(name, record_type), "no_records")
        )


def build_broker(
    *,
    resolver: StaticResolver | None = None,
    transport: SequenceTransport | None = None,
    policy: AllowPolicy | None = None,
    dns_answers: dict[tuple[str, str], DNSRecordSet] | None = None,
    dns_budget: DNSBudget | None = None,
) -> tuple[CollectionNetworkBroker, list[dict[str, object]]]:
    decisions: list[dict[str, object]] = []
    broker = CollectionNetworkBroker(
        resolver=resolver or StaticResolver([]),
        transport=transport or SequenceTransport([]),
        policy=policy or AllowPolicy(),
        dns_client=BoundedDNSClient(FixtureDNSTransport(dns_answers or {}), dns_budget),
        record_decision=decisions.append,
    )
    return broker, decisions


def response(
    status: int, headers: dict[str, str] | None = None, body: bytes = b""
) -> TransportResponse:
    return TransportResponse(status, headers or {}, body, tuple((headers or {}).items()))


# -- destination policy ------------------------------------------------------


@pytest.mark.parametrize("path", ["/../etc/passwd", "//evil", "/a\\b", "/x y"])
def test_unsafe_provider_paths_are_rejected(path: str) -> None:
    with pytest.raises(DestinationPolicyError):
        provider_destination(OperationClass.RDAP_QUERY, "rdap.example.test", path)


def test_fixed_path_operation_classes_cannot_be_redirected_elsewhere() -> None:
    destination = https_destination(OperationClass.EMAIL_POLICY_FETCH, "mta-sts.example.test")
    with pytest.raises(DestinationPolicyError) as error:
        authorize_collection_redirect(
            destination,
            "https://mta-sts.example.test/other.txt",
            authorized_hosts=frozenset({"mta-sts.example.test"}),
        )
    assert error.value.reason == "forbidden_path"


def test_redirect_to_unauthorized_host_is_rejected() -> None:
    destination = http_destination(OperationClass.HTTP_SURFACE, HOST)
    with pytest.raises(DestinationPolicyError) as error:
        authorize_collection_redirect(
            destination, "https://evil.test/", authorized_hosts=frozenset({HOST})
        )
    assert error.value.reason == "redirect_not_authorized"


def test_https_to_http_redirect_downgrade_is_rejected() -> None:
    destination = https_destination(OperationClass.HTTP_SURFACE, HOST)
    with pytest.raises(DestinationPolicyError) as error:
        authorize_collection_redirect(
            destination, "http://example.test/", authorized_hosts=frozenset({HOST})
        )
    assert error.value.reason == "tls_downgrade"


@pytest.mark.parametrize(
    "location",
    [
        "https://user:pass@example.test/",
        "file:///etc/passwd",
        "gopher://example.test/",
        "https://example.test:8443/",
        "https://EXAMPLE.test/",
    ],
)
def test_hostile_redirect_targets_are_rejected(location: str) -> None:
    destination = https_destination(OperationClass.HTTP_SURFACE, HOST)
    with pytest.raises(DestinationPolicyError):
        authorize_collection_redirect(
            destination, location, authorized_hosts=frozenset({HOST, "example.test"})
        )


def test_destination_cannot_be_built_for_ip_literal_or_wrong_port() -> None:
    with pytest.raises(DestinationPolicyError):
        https_destination(OperationClass.HTTP_SURFACE, "93.184.216.34")
    with pytest.raises(DestinationPolicyError):
        CollectionDestination(OperationClass.HTTP_SURFACE, "https", HOST, 8443, "/")


# -- broker HTTP -------------------------------------------------------------


def test_operation_class_mismatch_is_refused_before_any_network_use() -> None:
    resolver = StaticResolver([])
    broker, _ = build_broker(resolver=resolver)
    result = broker.fetch(
        collection_request(OperationClass.HTTP_SURFACE),
        https_destination(OperationClass.EMAIL_POLICY_FETCH, "mta-sts.example.test"),
    )
    assert result.allowed is False
    assert result.reason_code == "operation_class_mismatch"
    assert resolver.queries == []


@pytest.mark.parametrize("address", DESTINATIONS["forbidden"])
def test_forbidden_resolved_addresses_are_never_connected(address: str) -> None:
    transport = SequenceTransport([])
    broker, decisions = build_broker(resolver=StaticResolver([(address,)]), transport=transport)
    result = broker.fetch(collection_request(), http_destination(OperationClass.HTTP_SURFACE, HOST))
    assert result.allowed is False
    assert result.reason_code == "forbidden_address"
    assert transport.calls == []
    assert decisions[-1]["allowed"] is False


@pytest.mark.parametrize("address", DESTINATIONS["noncanonical"])
def test_noncanonical_resolver_answers_are_rejected(address: str) -> None:
    transport = SequenceTransport([])
    broker, _ = build_broker(resolver=StaticResolver([(address,)]), transport=transport)
    result = broker.fetch(collection_request(), http_destination(OperationClass.HTTP_SURFACE, HOST))
    assert result.allowed is False
    assert result.reason_code == "invalid_address"
    assert transport.calls == []


def test_split_horizon_answer_with_one_private_address_is_rejected() -> None:
    transport = SequenceTransport([])
    broker, _ = build_broker(
        resolver=StaticResolver([("93.184.216.34", "127.0.0.1")]), transport=transport
    )
    result = broker.fetch(collection_request(), http_destination(OperationClass.HTTP_SURFACE, HOST))
    assert result.reason_code == "mixed_dns_answers"
    assert transport.calls == []


def test_redirect_rebinding_reresolves_and_rejects_private_second_hop() -> None:
    resolver = StaticResolver([("93.184.216.34",), ("169.254.169.254",)])
    transport = SequenceTransport([response(302, {"location": "https://example.test/next"})])
    broker, _ = build_broker(resolver=resolver, transport=transport)
    result = broker.fetch(
        collection_request(authorized_hosts=(HOST,)),
        http_destination(OperationClass.HTTP_SURFACE, HOST),
    )
    assert result.allowed is False
    assert result.reason_code == "forbidden_address"
    assert resolver.queries == [HOST, HOST]
    assert len(transport.calls) == 1


def test_redirect_chain_is_bounded_and_recorded() -> None:
    resolver = StaticResolver([("93.184.216.34",)] * 8)
    transport = SequenceTransport(
        [response(302, {"location": f"https://example.test/hop{index}"}) for index in range(8)]
    )
    broker, _ = build_broker(resolver=resolver, transport=transport)
    result = broker.fetch(
        collection_request(authorized_hosts=(HOST,)),
        http_destination(OperationClass.HTTP_SURFACE, HOST),
    )
    assert result.allowed is False
    assert result.reason_code == "redirect_limit"
    assert result.redirect_count == 4


def test_successful_fetch_returns_headers_body_and_chain() -> None:
    resolver = StaticResolver([("93.184.216.34",), ("93.184.216.34",)])
    transport = SequenceTransport(
        [
            response(301, {"location": "https://example.test/"}),
            response(200, {"strict-transport-security": "max-age=63072000"}, b"ok"),
        ]
    )
    broker, decisions = build_broker(resolver=resolver, transport=transport)
    result = broker.fetch(
        collection_request(authorized_hosts=(HOST,)),
        http_destination(OperationClass.HTTP_SURFACE, HOST),
    )
    assert result.allowed is True
    assert result.status_code == 200
    assert result.body == b"ok"
    assert result.redirect_chain == ("http://example.test/", "https://example.test/")
    assert result.final_url == "https://example.test/"
    assert decisions[-1]["allowed"] is True


@pytest.mark.parametrize(
    "checkpoint",
    [
        BrokerCheckpoint.BEFORE_RESOLUTION,
        BrokerCheckpoint.AFTER_RESOLUTION,
        BrokerCheckpoint.BEFORE_CONNECT,
        BrokerCheckpoint.AFTER_HEADERS,
    ],
)
def test_policy_denial_at_every_checkpoint_stops_collection(
    checkpoint: BrokerCheckpoint,
) -> None:
    broker, _ = build_broker(
        resolver=StaticResolver([("93.184.216.34",)]),
        transport=SequenceTransport([response(200, {}, b"ok")]),
        policy=AllowPolicy(deny_at=checkpoint),
    )
    result = broker.fetch(collection_request(), http_destination(OperationClass.HTTP_SURFACE, HOST))
    assert result.allowed is False
    assert result.reason_code == "emergency_control_active"


# -- broker DNS --------------------------------------------------------------


def test_dns_query_is_denied_when_policy_rejects_the_tenant() -> None:
    transport = FixtureDNSTransport({})
    broker = CollectionNetworkBroker(
        resolver=StaticResolver([]),
        transport=SequenceTransport([]),
        policy=AllowPolicy(deny_at=BrokerCheckpoint.BEFORE_RESOLUTION),
        dns_client=BoundedDNSClient(transport),
    )
    answer = broker.query_dns(collection_request(OperationClass.DNS_QUERY), HOST, "TXT")
    assert answer.status == "error"
    assert transport.calls == []


def test_dns_record_type_allowlist_blocks_zone_transfer_style_queries() -> None:
    transport = FixtureDNSTransport({})
    client = BoundedDNSClient(transport)
    for record_type in ("AXFR", "IXFR", "ANY", "NULL"):
        answer = client.query(HOST, record_type)
        assert answer.status == "forbidden_record_type"
    assert transport.calls == []


def test_dns_query_budget_is_enforced() -> None:
    transport = FixtureDNSTransport({})
    client = BoundedDNSClient(transport, DNSBudget(max_queries=2))
    assert client.query(HOST, "A").status == "no_records"
    assert client.query(HOST, "AAAA").status == "no_records"
    assert client.query(HOST, "MX").status == "budget_exhausted"
    assert len(transport.calls) == 2


def test_oversized_dns_answers_are_rejected_rather_than_truncated() -> None:
    query = DNSQuery(HOST, "TXT")
    oversized = DNSRecordSet(query, "answered", ("x" * 5000,))
    client = BoundedDNSClient(FixtureDNSTransport({(HOST, "TXT"): oversized}))
    assert client.query(HOST, "TXT").status == "too_large"

    many = DNSRecordSet(query, "answered", tuple(f"v{index}" for index in range(200)))
    client = BoundedDNSClient(FixtureDNSTransport({(HOST, "TXT"): many}))
    assert client.query(HOST, "TXT").status == "too_large"


@pytest.mark.parametrize(
    "name", ["EXAMPLE.test", "example.test.", "", "..", "127.0.0.1", "example .test"]
)
def test_noncanonical_dns_names_are_rejected(name: str) -> None:
    transport = FixtureDNSTransport({})
    assert BoundedDNSClient(transport).query(name, "A").status == "invalid_name"
    assert transport.calls == []


def test_underscore_policy_names_are_accepted() -> None:
    name = "_dmarc.example.test"
    answer = DNSRecordSet(DNSQuery(name, "TXT"), "answered", ("v=DMARC1; p=none",))
    client = BoundedDNSClient(FixtureDNSTransport({(name, "TXT"): answer}))
    assert client.query(name, "TXT").records == ("v=DMARC1; p=none",)


def test_unknown_dns_outcomes_are_not_silently_treated_as_absence() -> None:
    query = DNSQuery(HOST, "TXT")
    for status in ("timeout", "refused", "error"):
        client = BoundedDNSClient(FixtureDNSTransport({(HOST, "TXT"): DNSRecordSet(query, status)}))
        answer = client.query(HOST, "TXT")
        assert answer.is_conclusive is False
        assert answer.records == ()
