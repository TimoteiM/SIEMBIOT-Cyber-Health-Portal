"""HTTP message framing.

Chunked transfer encoding is deliberately supported: it is ubiquitous on real sites, so
refusing it would mean the observatory could read almost nothing. What must still be
refused is ambiguity — a message whose end two parties could disagree about — and any
framing that would let a response escape the size budget.
"""

from __future__ import annotations

import pytest
from siembiot_worker.network_safety.models import NetworkBudget
from siembiot_worker.network_safety.transport import BoundedHTTPTransport, NetworkTransportError
from siembiot_worker.network_safety.url_policy import VerificationDestination

CRLF = "\r\n"


class FakeStream:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = list(chunks)
        self.sent = b""

    def settimeout(self, value: float) -> None:
        del value

    def sendall(self, value: bytes) -> None:
        self.sent += value

    def recv(self, size: int) -> bytes:
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) <= size:
            return chunk
        self.chunks.insert(0, chunk[size:])
        return chunk[:size]

    def close(self) -> None:
        self.chunks.clear()


class FakeConnector:
    def __init__(self, stream: FakeStream) -> None:
        self.stream = stream

    def connect(
        self, address: str, port: int, server_hostname: str | None, timeout: float
    ) -> FakeStream:
        del address, port, server_hostname, timeout
        return self.stream


def response(*parts: str) -> bytes:
    """Build a raw HTTP response from parts joined by CRLF."""
    return CRLF.join(parts).encode("ascii")


def fetch(raw: bytes, budget: NetworkBudget | None = None) -> bytes:
    transport = BoundedHTTPTransport(connector=FakeConnector(FakeStream([raw])))
    return transport.get(
        VerificationDestination.https("example.com"),
        "8.8.8.8",
        budget or NetworkBudget(),
        lambda _: None,
    ).body


def chunked(*chunks: str, terminator: bool = True) -> bytes:
    parts = ["HTTP/1.1 200 OK", "Transfer-Encoding: chunked", ""]
    for chunk in chunks:
        parts.extend([format(len(chunk), "x"), chunk])
    if terminator:
        parts.extend(["0", "", ""])
    return response(*parts)


# -- what must still be refused ----------------------------------------------


def test_both_framings_at_once_is_refused_as_ambiguous() -> None:
    """Content-Length plus Transfer-Encoding is the request-smuggling shape.

    Two parties can disagree about where the message ends, so the transport refuses
    rather than picking an interpretation.
    """
    raw = response(
        "HTTP/1.1 200 OK",
        "Content-Length: 3",
        "Transfer-Encoding: chunked",
        "",
        "3",
        "abc",
        "0",
        "",
        "",
    )
    with pytest.raises(NetworkTransportError, match="ambiguous_framing"):
        fetch(raw)


def test_a_transfer_encoding_the_transport_does_not_implement_is_refused() -> None:
    raw = response("HTTP/1.1 200 OK", "Transfer-Encoding: gzip", "", "body")
    with pytest.raises(NetworkTransportError, match="unsupported_framing"):
        fetch(raw)


def test_a_malformed_status_line_is_refused() -> None:
    with pytest.raises(NetworkTransportError, match="malformed_response"):
        fetch(response("not-http", "", ""))


def test_a_malformed_header_line_is_refused() -> None:
    with pytest.raises(NetworkTransportError, match="malformed_response"):
        fetch(response("HTTP/1.1 200 OK", "BadHeader", "", ""))


# -- chunked decoding --------------------------------------------------------


def test_a_chunked_response_is_decoded() -> None:
    assert fetch(chunked("hello", " world")) == b"hello world"


def test_an_empty_chunked_response_is_decoded() -> None:
    assert fetch(chunked()) == b""


def test_chunk_extensions_are_ignored_rather_than_misparsed() -> None:
    raw = response(
        "HTTP/1.1 200 OK", "Transfer-Encoding: chunked", "", "5;name=value", "hello", "0", "", ""
    )
    assert fetch(raw) == b"hello"


def test_a_chunked_body_still_obeys_the_size_budget() -> None:
    with pytest.raises(NetworkTransportError, match="response_too_large"):
        fetch(chunked("x" * 64), NetworkBudget(max_body_bytes=16))


def test_a_malformed_chunk_size_is_refused() -> None:
    raw = response("HTTP/1.1 200 OK", "Transfer-Encoding: chunked", "", "zz", "abc", "")
    with pytest.raises(NetworkTransportError, match="malformed_response"):
        fetch(raw)


def test_a_truncated_chunked_body_is_refused_rather_than_returned_short() -> None:
    """A short read must never silently become a smaller body."""
    raw = response("HTTP/1.1 200 OK", "Transfer-Encoding: chunked", "", "10", "short")
    with pytest.raises(NetworkTransportError, match="truncated_response"):
        fetch(raw)


def test_a_chunk_not_terminated_by_crlf_is_refused() -> None:
    raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n"
    with pytest.raises(NetworkTransportError, match="malformed_response"):
        fetch(raw)
