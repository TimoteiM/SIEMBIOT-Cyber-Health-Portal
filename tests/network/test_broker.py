from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

from siembiot_worker.network_safety.broker import NetworkSafetyBroker
from siembiot_worker.network_safety.models import (
    BrokerCheckpoint,
    NetworkBudget,
    PolicyDecision,
    TransportResponse,
    VerificationFetchRequest,
)
from siembiot_worker.network_safety.url_policy import VerificationDestination


class SequenceResolver:
    def __init__(self, answers: list[tuple[str, ...]]) -> None:
        self.answers = answers
        self.queries: list[str] = []

    def resolve(self, host: str) -> tuple[str, ...]:
        self.queries.append(host)
        return self.answers.pop(0)


class SequenceTransport:
    def __init__(self, responses: list[TransportResponse]) -> None:
        self.responses = responses
        self.calls: list[tuple[VerificationDestination, str]] = []

    def get(
        self,
        destination: VerificationDestination,
        address: str,
        budget: NetworkBudget,
        checkpoint: Callable[[BrokerCheckpoint], None],
    ) -> TransportResponse:
        self.calls.append((destination, address))
        checkpoint(BrokerCheckpoint.AFTER_HEADERS)
        checkpoint(BrokerCheckpoint.BODY_CHUNK)
        return self.responses.pop(0)


class RecordingPolicy:
    def __init__(self, deny_at: BrokerCheckpoint | None = None) -> None:
        self.deny_at = deny_at
        self.checkpoints: list[BrokerCheckpoint] = []

    def authorize(
        self,
        request: VerificationFetchRequest,
        checkpoint: BrokerCheckpoint,
        destination: VerificationDestination,
    ) -> PolicyDecision:
        self.checkpoints.append(checkpoint)
        if checkpoint == self.deny_at:
            return PolicyDecision(False, "emergency_control_active")
        return PolicyDecision(True, "allowed")


def request() -> VerificationFetchRequest:
    return VerificationFetchRequest(
        organization_id=uuid4(),
        domain_id=uuid4(),
        challenge_id=uuid4(),
        canonical_host="example.com",
        authorized_redirect_hosts=("example.com",),
    )


def test_broker_reauthorizes_and_connects_only_to_validated_address() -> None:
    resolver = SequenceResolver([("8.8.8.8",)])
    transport = SequenceTransport([TransportResponse(200, {}, b"verification-value")])
    policy = RecordingPolicy()
    records: list[dict[str, object]] = []
    broker = NetworkSafetyBroker(
        resolver=resolver,
        transport=transport,
        policy=policy,
        record_decision=records.append,
    )
    result = broker.fetch_https_verification(request())
    assert result.allowed
    assert result.status_code == 200
    assert result.body == b"verification-value"
    assert resolver.queries == ["example.com"]
    assert transport.calls[0][0].host_header == "example.com"
    assert transport.calls[0][1] == "8.8.8.8"
    assert policy.checkpoints == [
        BrokerCheckpoint.BEFORE_RESOLUTION,
        BrokerCheckpoint.AFTER_RESOLUTION,
        BrokerCheckpoint.BEFORE_CONNECT,
        BrokerCheckpoint.AFTER_HEADERS,
        BrokerCheckpoint.BODY_CHUNK,
    ]
    assert records == [
        {
            "allowed": True,
            "reason_code": "allowed",
            "operation_class": "https_verification",
            "canonical_host": "example.com",
            "redirect_count": 0,
            "address_count": 1,
        }
    ]


def test_mixed_dns_answers_block_before_transport_and_redact_addresses() -> None:
    resolver = SequenceResolver([("8.8.8.8", "127.0.0.1")])
    transport = SequenceTransport([])
    records: list[dict[str, object]] = []
    result = NetworkSafetyBroker(
        resolver=resolver,
        transport=transport,
        policy=RecordingPolicy(),
        record_decision=records.append,
    ).fetch_https_verification(request())
    assert not result.allowed
    assert result.reason_code == "mixed_dns_answers"
    assert transport.calls == []
    assert "127.0.0.1" not in repr(records)
    assert "8.8.8.8" not in repr(records)


def test_emergency_control_cancels_cooperative_inflight_read() -> None:
    policy = RecordingPolicy(deny_at=BrokerCheckpoint.BODY_CHUNK)
    transport = SequenceTransport([TransportResponse(200, {}, b"must-not-return")])
    result = NetworkSafetyBroker(
        resolver=SequenceResolver([("8.8.8.8",)]),
        transport=transport,
        policy=policy,
    ).fetch_https_verification(request())
    assert not result.allowed
    assert result.reason_code == "emergency_control_active"
    assert result.body == b""


def test_broker_enforces_body_and_redirect_budgets_even_for_transport_adapters() -> None:
    too_large = NetworkSafetyBroker(
        resolver=SequenceResolver([("8.8.8.8",)]),
        transport=SequenceTransport([TransportResponse(200, {}, b"x" * 17)]),
        policy=RecordingPolicy(),
        budget=NetworkBudget(max_body_bytes=16),
    ).fetch_https_verification(request())
    assert not too_large.allowed
    assert too_large.reason_code == "response_too_large"

    redirects = [
        TransportResponse(
            302,
            {"location": "https://example.com/.well-known/siembiot-verification.txt"},
            b"",
        ),
        TransportResponse(
            302,
            {"location": "https://example.com/.well-known/siembiot-verification.txt"},
            b"",
        ),
    ]
    redirected = NetworkSafetyBroker(
        resolver=SequenceResolver([("8.8.8.8",), ("8.8.8.8",)]),
        transport=SequenceTransport(redirects),
        policy=RecordingPolicy(),
        budget=NetworkBudget(max_redirects=1),
    ).fetch_https_verification(request())
    assert not redirected.allowed
    assert redirected.reason_code == "redirect_limit"
