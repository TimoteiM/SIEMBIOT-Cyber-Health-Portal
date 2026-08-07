from __future__ import annotations

import socket
import ssl
import time
from collections.abc import Callable
from typing import Protocol

from siembiot_worker.network_safety.models import (
    BrokerCheckpoint,
    NetworkBudget,
    TransportResponse,
)


class NetworkTransportError(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


SAFE_METHODS = frozenset({"GET", "HEAD"})

#: Headers that must appear exactly once, and where a second value is refused.
#:
#: This used to be the other way round -- an allowlist of `{"set-cookie"}`, with every
#: other repeat refused as `duplicate_header`. The reasoning was request smuggling, which
#: is real, but the rule was far wider than the danger and it made the product unusable
#: against a large part of its own audience: `apavil.ro` sends three `Link` headers, as
#: every WordPress site does, so both HTTP and HTTPS were refused, the page was recorded
#: as unreachable, and the run finished at 5.6% coverage with no score. Nothing errored.
#: The assessment simply reported that a working municipal website could not be reached.
#:
#: RFC 9110 is explicit that list-valued fields may be sent as several lines and mean the
#: concatenation. So the refusal now covers only the fields where two values genuinely
#: change what the message *is*: where it ends, and where it sends the client next.
#: Disagreeing framing is additionally caught as `ambiguous_framing` below, so the
#: smuggling protection is unchanged.
SINGLETON_HEADERS = frozenset({"content-length", "transfer-encoding", "location"})
#: Slack for chunk size lines and trailers when bounding raw bytes read.
MAX_CHUNK_OVERHEAD_BYTES = 16_384


class RequestDestination(Protocol):
    """Read-only structural view of an already-authorized destination."""

    @property
    def scheme(self) -> str: ...

    @property
    def host(self) -> str: ...

    @property
    def port(self) -> int: ...

    @property
    def host_header(self) -> str: ...

    @property
    def request_target(self) -> str: ...


class Stream(Protocol):
    def settimeout(self, value: float) -> None: ...
    def sendall(self, value: bytes) -> None: ...
    def recv(self, size: int) -> bytes: ...
    def close(self) -> None: ...


class Connector(Protocol):
    def connect(
        self, address: str, port: int, server_hostname: str | None, timeout: float
    ) -> Stream: ...


class SocketConnector:
    def connect(
        self, address: str, port: int, server_hostname: str | None, timeout: float
    ) -> Stream:
        raw = socket.create_connection((address, port), timeout=timeout)
        if server_hostname is None:
            return raw
        try:
            return ssl.create_default_context().wrap_socket(raw, server_hostname=server_hostname)
        except Exception:
            raw.close()
            raise


class BoundedHTTPTransport:
    def __init__(
        self,
        connector: Connector | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._connector = connector or SocketConnector()
        self._clock = clock

    def get(
        self,
        destination: RequestDestination,
        address: str,
        budget: NetworkBudget,
        checkpoint: Callable[[BrokerCheckpoint], None],
        method: str = "GET",
    ) -> TransportResponse:
        if method not in SAFE_METHODS:
            raise NetworkTransportError("forbidden_method")
        stream: Stream | None = None
        deadline = self._clock() + budget.total_timeout_seconds
        try:
            stream = self._connector.connect(
                address,
                destination.port,
                destination.host if destination.scheme == "https" else None,
                min(budget.connect_timeout_seconds, budget.total_timeout_seconds),
            )
            request = (
                f"{method} {destination.request_target} HTTP/1.1\r\n"
                f"Host: {destination.host_header}\r\n"
                "Accept: text/plain\r\n"
                "User-Agent: SIEMBIOT-Ownership-Verifier/1\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            stream.sendall(request)
            head, initial_body = self._read_headers(
                stream, budget.max_header_bytes, budget, deadline
            )
            status, headers, raw_headers = self._parse_headers(head)
            checkpoint(BrokerCheckpoint.AFTER_HEADERS)
            if method == "HEAD":
                return TransportResponse(status, headers, b"", raw_headers)
            body = self._read_body(stream, headers, initial_body, budget, checkpoint, deadline)
            return TransportResponse(status, headers, body, raw_headers)
        except NetworkTransportError:
            raise
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise NetworkTransportError("transport_error") from exc
        finally:
            if stream is not None:
                stream.close()

    def _set_read_timeout(self, stream: Stream, budget: NetworkBudget, deadline: float) -> None:
        remaining = deadline - self._clock()
        if remaining <= 0:
            raise NetworkTransportError("timeout")
        stream.settimeout(min(budget.read_timeout_seconds, remaining))

    def _read_headers(
        self,
        stream: Stream,
        maximum: int,
        budget: NetworkBudget,
        deadline: float,
    ) -> tuple[bytes, bytes]:
        received = bytearray()
        while b"\r\n\r\n" not in received:
            self._set_read_timeout(stream, budget, deadline)
            chunk = stream.recv(min(4096, maximum + 1 - len(received)))
            if not chunk:
                raise NetworkTransportError("malformed_response")
            received.extend(chunk)
            if len(received) > maximum:
                raise NetworkTransportError("headers_too_large")
        head, body = bytes(received).split(b"\r\n\r\n", 1)
        return head, body

    @staticmethod
    def _parse_headers(head: bytes) -> tuple[int, dict[str, str], tuple[tuple[str, str], ...]]:
        try:
            lines = head.decode("iso-8859-1").split("\r\n")
            version, raw_status, _ = lines[0].split(" ", 2)
            status = int(raw_status)
        except (UnicodeDecodeError, ValueError, IndexError) as exc:
            raise NetworkTransportError("malformed_response") from exc
        if version not in {"HTTP/1.0", "HTTP/1.1"} or not 100 <= status <= 599:
            raise NetworkTransportError("malformed_response")
        headers: dict[str, str] = {}
        raw_headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            if ":" not in line:
                raise NetworkTransportError("malformed_response")
            name, value = line.split(":", 1)
            if not name or name.strip() != name:
                raise NetworkTransportError("malformed_response")
            lowered = name.lower()
            if lowered in headers and lowered in SINGLETON_HEADERS:
                raise NetworkTransportError("duplicate_header")
            raw_headers.append((lowered, value.strip()))
            headers.setdefault(lowered, value.strip())
        encoding = headers.get("transfer-encoding")
        if encoding is not None:
            # Both framings at once is the request-smuggling shape: two parties can
            # disagree about where the message ends. Refuse rather than pick a side.
            if "content-length" in headers:
                raise NetworkTransportError("ambiguous_framing")
            if encoding.strip().lower() != "chunked":
                raise NetworkTransportError("unsupported_framing")
        return status, headers, tuple(raw_headers)

    def _read_body(
        self,
        stream: Stream,
        headers: dict[str, str],
        initial: bytes,
        budget: NetworkBudget,
        checkpoint: Callable[[BrokerCheckpoint], None],
        deadline: float,
    ) -> bytes:
        if headers.get("transfer-encoding", "").strip().lower() == "chunked":
            return self._read_chunked_body(stream, initial, budget, checkpoint, deadline)

        content_length: int | None = None
        if "content-length" in headers:
            try:
                content_length = int(headers["content-length"])
            except ValueError as exc:
                raise NetworkTransportError("malformed_response") from exc
            if content_length < 0:
                raise NetworkTransportError("malformed_response")
            if content_length > budget.max_body_bytes:
                raise NetworkTransportError("response_too_large")
        body = bytearray(initial)
        if len(body) > budget.max_body_bytes:
            raise NetworkTransportError("response_too_large")
        if body:
            checkpoint(BrokerCheckpoint.BODY_CHUNK)
        while content_length is None or len(body) < content_length:
            self._set_read_timeout(stream, budget, deadline)
            chunk = stream.recv(min(4096, budget.max_body_bytes + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > budget.max_body_bytes:
                raise NetworkTransportError("response_too_large")
            checkpoint(BrokerCheckpoint.BODY_CHUNK)
        if content_length is not None and len(body) != content_length:
            raise NetworkTransportError("truncated_response")
        return bytes(body)

    def _read_chunked_body(
        self,
        stream: Stream,
        initial: bytes,
        budget: NetworkBudget,
        checkpoint: Callable[[BrokerCheckpoint], None],
        deadline: float,
    ) -> bytes:
        """Decode chunked transfer encoding under the same byte cap as any other body.

        Chunked framing is ubiquitous on real sites, so refusing it outright would mean
        observing almost nothing. The bound that matters is unchanged: the decoded body
        may not exceed the budget, and neither may the raw bytes read to produce it.
        """
        buffer = bytearray(initial)
        body = bytearray()
        raw_read = len(initial)

        def fill() -> bool:
            nonlocal raw_read
            self._set_read_timeout(stream, budget, deadline)
            chunk = stream.recv(4096)
            if not chunk:
                return False
            raw_read += len(chunk)
            # A hostile peer could otherwise stream unbounded chunk headers that decode
            # to almost nothing, so the raw byte count is capped too.
            if raw_read > budget.max_body_bytes * 2 + MAX_CHUNK_OVERHEAD_BYTES:
                raise NetworkTransportError("response_too_large")
            buffer.extend(chunk)
            return True

        while True:
            while b"\r\n" not in buffer:
                if not fill():
                    raise NetworkTransportError("truncated_response")
            line, _, rest = bytes(buffer).partition(b"\r\n")
            buffer[:] = rest
            # Chunk extensions after ";" are permitted by the protocol and ignored here.
            size_token = line.split(b";", 1)[0].strip()
            try:
                size = int(size_token, 16)
            except ValueError as exc:
                raise NetworkTransportError("malformed_response") from exc
            if size < 0:
                raise NetworkTransportError("malformed_response")
            if size == 0:
                break
            if len(body) + size > budget.max_body_bytes:
                raise NetworkTransportError("response_too_large")
            while len(buffer) < size + 2:
                if not fill():
                    raise NetworkTransportError("truncated_response")
            body.extend(buffer[:size])
            if bytes(buffer[size : size + 2]) != b"\r\n":
                raise NetworkTransportError("malformed_response")
            buffer[:] = buffer[size + 2 :]
            checkpoint(BrokerCheckpoint.BODY_CHUNK)

        return bytes(body)
