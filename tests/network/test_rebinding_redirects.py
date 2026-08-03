from __future__ import annotations

from siembiot_worker.network_safety.broker import NetworkSafetyBroker
from siembiot_worker.network_safety.models import NetworkBudget, TransportResponse
from test_broker import RecordingPolicy, SequenceResolver, SequenceTransport, request


def test_redirect_reresolves_and_blocks_dns_rebinding() -> None:
    resolver = SequenceResolver([("8.8.8.8",), ("127.0.0.1",)])
    transport = SequenceTransport(
        [
            TransportResponse(
                302,
                {"location": "https://example.com/.well-known/tyche-verification.txt"},
                b"",
            )
        ]
    )
    result = NetworkSafetyBroker(
        resolver=resolver, transport=transport, policy=RecordingPolicy()
    ).fetch_https_verification(request())
    assert not result.allowed
    assert result.reason_code == "forbidden_address"
    assert resolver.queries == ["example.com", "example.com"]
    assert len(transport.calls) == 1


def test_cross_domain_redirect_needs_exact_request_authorization() -> None:
    redirect = TransportResponse(
        302,
        {"location": "https://child.example.com/.well-known/tyche-verification.txt"},
        b"",
    )
    result = NetworkSafetyBroker(
        resolver=SequenceResolver([("8.8.8.8",)]),
        transport=SequenceTransport([redirect]),
        policy=RecordingPolicy(),
        budget=NetworkBudget(max_redirects=2),
    ).fetch_https_verification(request())
    assert not result.allowed
    assert result.reason_code == "redirect_not_authorized"
