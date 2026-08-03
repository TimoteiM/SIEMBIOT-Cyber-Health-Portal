from __future__ import annotations

from collections.abc import Callable

import pytest
from siembiot_worker.network_safety.models import BrokerCheckpoint, NetworkBudget
from siembiot_worker.network_safety.transport import (
    BoundedHTTPTransport,
    NetworkTransportError,
)
from siembiot_worker.network_safety.url_policy import VerificationDestination


class FakeStream:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.sent = b""
        self.timeouts: list[float] = []
        self.closed = False

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def sendall(self, value: bytes) -> None:
        self.sent += value

    def recv(self, _: int) -> bytes:
        return self.chunks.pop(0) if self.chunks else b""

    def close(self) -> None:
        self.closed = True


class FakeConnector:
    def __init__(self, stream: FakeStream) -> None:
        self.stream = stream
        self.calls: list[tuple[str, int, str | None, float]] = []

    def connect(
        self, address: str, port: int, server_hostname: str | None, timeout: float
    ) -> FakeStream:
        self.calls.append((address, port, server_hostname, timeout))
        return self.stream


def checkpoints() -> tuple[list[BrokerCheckpoint], Callable[[BrokerCheckpoint], None]]:
    seen: list[BrokerCheckpoint] = []
    return seen, seen.append


def test_transport_pins_address_while_preserving_host_and_tls_sni() -> None:
    stream = FakeStream([b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\ntoken"])
    connector = FakeConnector(stream)
    seen, checkpoint = checkpoints()
    response = BoundedHTTPTransport(connector=connector).get(
        VerificationDestination.https("example.com"),
        "8.8.8.8",
        NetworkBudget(),
        checkpoint,
    )
    assert connector.calls == [("8.8.8.8", 443, "example.com", 2.0)]
    assert b"Host: example.com\r\n" in stream.sent
    assert b"Connection: close\r\n" in stream.sent
    assert response.body == b"token"
    assert seen == [BrokerCheckpoint.AFTER_HEADERS, BrokerCheckpoint.BODY_CHUNK]
    assert stream.closed


def test_transport_enforces_header_and_body_size() -> None:
    header_stream = FakeStream([b"HTTP/1.1 200 OK\r\nX-Large: " + b"x" * 40])
    with pytest.raises(NetworkTransportError, match="headers_too_large"):
        BoundedHTTPTransport(connector=FakeConnector(header_stream)).get(
            VerificationDestination.https("example.com"),
            "8.8.8.8",
            NetworkBudget(max_header_bytes=32),
            lambda _: None,
        )

    body_stream = FakeStream([b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n"])
    with pytest.raises(NetworkTransportError, match="response_too_large"):
        BoundedHTTPTransport(connector=FakeConnector(body_stream)).get(
            VerificationDestination.https("example.com"),
            "8.8.8.8",
            NetworkBudget(max_body_bytes=16),
            lambda _: None,
        )


def test_transport_rejects_malformed_or_unsupported_response_framing() -> None:
    for response in (
        b"not-http\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nBadHeader\r\n\r\n",
    ):
        with pytest.raises(NetworkTransportError):
            BoundedHTTPTransport(connector=FakeConnector(FakeStream([response]))).get(
                VerificationDestination.https("example.com"),
                "8.8.8.8",
                NetworkBudget(),
                lambda _: None,
            )


def test_transport_enforces_total_timeout_budget() -> None:
    ticks = iter((0.0, 2.0))
    transport = BoundedHTTPTransport(
        connector=FakeConnector(FakeStream([b"HTTP/1.1 200 OK\r\n\r\n"])),
        clock=lambda: next(ticks),
    )
    with pytest.raises(NetworkTransportError, match="timeout"):
        transport.get(
            VerificationDestination.https("example.com"),
            "8.8.8.8",
            NetworkBudget(total_timeout_seconds=1.0),
            lambda _: None,
        )
