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


# -- repeated header fields --------------------------------------------------
#
# These exist because the transport once refused any repeated header except Set-Cookie,
# and that rule made the product unusable against a large part of its own audience.
# `apavil.ro` sends three `Link` headers, as every WordPress site does; both HTTP and
# HTTPS were refused, the page was recorded unreachable, and the assessment finished at
# 5.6% coverage with no score. Nothing errored -- it simply reported that a working
# municipal website could not be reached.


def test_a_repeated_list_header_is_read_rather_than_refused() -> None:
    """RFC 9110: a list-valued field may be sent as several lines.

    Three `Link` headers is the shape that broke a real Romanian municipal site.
    """
    raw = response(
        "HTTP/1.1 200 OK",
        "Content-Length: 2",
        'Link: <https://example.com/wp-json/>; rel="https://api.w.org/"',
        'Link: <https://example.com/>; rel="shortlink"',
        "Link: <https://example.com/feed>; rel=alternate",
        "",
        "ok",
    )
    assert fetch(raw) == b"ok"


def test_every_value_of_a_repeated_header_is_kept() -> None:
    """Keeping only the first would silently drop cookies, which the checks read.

    A page setting a session cookie without `Secure` and a second cookie with it must
    not be able to hide the first behind the second.
    """
    transport = BoundedHTTPTransport(
        connector=FakeConnector(
            FakeStream(
                [
                    response(
                        "HTTP/1.1 200 OK",
                        "Content-Length: 2",
                        "Set-Cookie: a=1; Path=/",
                        "Set-Cookie: b=2; Secure",
                        "",
                        "ok",
                    )
                ]
            )
        )
    )
    result = transport.get(
        VerificationDestination.https("example.com"), "8.8.8.8", NetworkBudget(), lambda _: None
    )
    cookies = [value for name, value in result.raw_headers if name == "set-cookie"]
    assert cookies == ["a=1; Path=/", "b=2; Secure"]


@pytest.mark.parametrize(
    ("header", "first", "second"),
    [
        ("Content-Length", "2", "9"),
        ("Transfer-Encoding", "chunked", "identity"),
        ("Location", "https://a.example.com/", "https://b.example.com/"),
    ],
)
def test_a_repeated_singleton_header_is_still_refused(header: str, first: str, second: str) -> None:
    """The narrower rule that replaced the broad one.

    Two content lengths let two parties disagree about where the message ends; two
    locations let them disagree about where the client goes next. Neither is a list, and
    neither has a safe interpretation, so both are still refused.
    """
    raw = response(
        "HTTP/1.1 200 OK",
        f"{header}: {first}",
        f"{header}: {second}",
        "",
        "ok",
    )
    with pytest.raises(NetworkTransportError) as caught:
        fetch(raw)
    assert caught.value.reason == "duplicate_header"


def test_a_page_larger_than_the_budget_still_yields_its_headers() -> None:
    """The bug an institution saw as "site unreachable".

    tarom.ro answers in under a second and redirects to www. Its home page is larger than
    the body budget, so the whole response -- headers included -- was thrown away and the
    site was reported as one nobody could reach. Four checks disappeared with it.

    The HTTP surface checks read the status line, the redirect chain, the security headers
    and the cookies. None of them reads the page, so it is no longer fetched at all.
    """
    oversized = "x" * (NetworkBudget().max_body_bytes + 5_000)
    raw = response(
        "HTTP/1.1 200 OK",
        "Strict-Transport-Security: max-age=63072000",
        f"Content-Length: {len(oversized)}",
        "",
        oversized,
    )

    with pytest.raises(NetworkTransportError, match="response_too_large"):
        fetch(raw)

    transport = BoundedHTTPTransport(connector=FakeConnector(FakeStream([raw])))
    result = transport.get(
        VerificationDestination.https("example.com"),
        "8.8.8.8",
        NetworkBudget(),
        lambda _: None,
        read_body=False,
    )
    assert result.status_code == 200
    assert result.headers["strict-transport-security"] == "max-age=63072000"
    assert result.body == b""


def test_a_body_nobody_asked_for_is_not_read_off_the_socket() -> None:
    """Not merely discarded after the fact.

    Reading it and then dropping it would leave the transfer, the memory and the time
    exactly where they were -- the point is that the bytes never cross the boundary.
    """
    body = "y" * 3_000
    stream = FakeStream(
        [
            response(
                "HTTP/1.1 200 OK",
                f"Content-Length: {len(body)}",
                "",
                body,
            )
        ]
    )
    transport = BoundedHTTPTransport(connector=FakeConnector(stream))
    transport.get(
        VerificationDestination.https("example.com"),
        "8.8.8.8",
        NetworkBudget(),
        lambda _: None,
        read_body=False,
    )
    # Whatever arrived alongside the headers in the first packet is unavoidable; what
    # matters is that nothing further was pulled from the socket.
    assert stream.chunks == []


def get_with(headers: dict[str, str]) -> bytes:
    """Issue a request carrying caller headers, and return the bytes actually sent."""
    raw = response("HTTP/1.1 200 OK", "Content-Length: 0", "", "")
    stream = FakeStream([raw])
    BoundedHTTPTransport(connector=FakeConnector(stream)).get(
        VerificationDestination.https("example.com"),
        "8.8.8.8",
        NetworkBudget(),
        lambda _: None,
        extra_headers=headers,
    )
    return stream.sent


def test_a_caller_header_is_sent() -> None:
    assert b"X-Api-Key: secret" in get_with({"X-Api-Key": "secret"})


@pytest.mark.parametrize(
    "headers",
    [
        {"X-Api-Key": "secret\r\nX-Injected: yes"},
        {"X-Api-Key": "secret\nX-Injected: yes"},
        {"X-Api\r\nX-Injected": "yes"},
        {"X-Api:Key": "secret"},
        {"": "secret"},
        {"X-Api-Key": "secrét"},
        {"X-Api-Kéy": "secret"},
    ],
)
def test_a_header_cannot_smuggle_a_second_header(headers: dict[str, str]) -> None:
    """These values are provider credentials.

    An injected newline here would not merely corrupt a request -- it would let a crafted
    key append headers of its own choosing to an authenticated call. There is no correct
    way to escape a newline in a header, so a credential containing one is rejected
    rather than cleaned up.
    """
    with pytest.raises(NetworkTransportError, match="malformed_header"):
        get_with(headers)


@pytest.mark.parametrize("name", ["Host", "host", "Connection", "Content-Length", "User-Agent"])
def test_a_caller_cannot_restate_a_header_the_transport_owns(name: str) -> None:
    """Two `Host` lines is a request-smuggling primitive, and a second `Connection` would
    let a caller hold a socket open past the budget."""
    with pytest.raises(NetworkTransportError, match="reserved_header"):
        get_with({name: "anything"})
