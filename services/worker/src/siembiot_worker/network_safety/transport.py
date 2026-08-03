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
from siembiot_worker.network_safety.url_policy import VerificationDestination


class NetworkTransportError(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


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
        destination: VerificationDestination,
        address: str,
        budget: NetworkBudget,
        checkpoint: Callable[[BrokerCheckpoint], None],
    ) -> TransportResponse:
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
                f"GET {destination.path} HTTP/1.1\r\n"
                f"Host: {destination.host_header}\r\n"
                "Accept: text/plain\r\n"
                "User-Agent: SIEMBIOT-Ownership-Verifier/1\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            stream.sendall(request)
            head, initial_body = self._read_headers(
                stream, budget.max_header_bytes, budget, deadline
            )
            status, headers = self._parse_headers(head)
            checkpoint(BrokerCheckpoint.AFTER_HEADERS)
            body = self._read_body(
                stream, headers, initial_body, budget, checkpoint, deadline
            )
            return TransportResponse(status, headers, body)
        except NetworkTransportError:
            raise
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise NetworkTransportError("transport_error") from exc
        finally:
            if stream is not None:
                stream.close()

    def _set_read_timeout(
        self, stream: Stream, budget: NetworkBudget, deadline: float
    ) -> None:
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
    def _parse_headers(head: bytes) -> tuple[int, dict[str, str]]:
        try:
            lines = head.decode("iso-8859-1").split("\r\n")
            version, raw_status, _ = lines[0].split(" ", 2)
            status = int(raw_status)
        except (UnicodeDecodeError, ValueError, IndexError) as exc:
            raise NetworkTransportError("malformed_response") from exc
        if version not in {"HTTP/1.0", "HTTP/1.1"} or not 100 <= status <= 599:
            raise NetworkTransportError("malformed_response")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                raise NetworkTransportError("malformed_response")
            name, value = line.split(":", 1)
            if not name or name.strip() != name:
                raise NetworkTransportError("malformed_response")
            lowered = name.lower()
            if lowered in headers:
                raise NetworkTransportError("duplicate_header")
            headers[lowered] = value.strip()
        if "transfer-encoding" in headers:
            raise NetworkTransportError("unsupported_framing")
        return status, headers

    def _read_body(
        self,
        stream: Stream,
        headers: dict[str, str],
        initial: bytes,
        budget: NetworkBudget,
        checkpoint: Callable[[BrokerCheckpoint], None],
        deadline: float,
    ) -> bytes:
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
