"""Safe TLS observation.

Handshakes only. No application data is ever sent, no renegotiation is attempted,
and no cipher/protocol is offered that the platform would not itself use to fetch.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from typing import Literal, Protocol

TLSStatus = Literal[
    "handshake_ok",
    "verification_failed",
    "handshake_failed",
    "timeout",
    "connection_refused",
    "error",
]

PROTOCOL_PROBES: tuple[str, ...] = ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
_PROBE_VERSIONS: dict[str, ssl.TLSVersion] = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


@dataclass(frozen=True)
class TLSBudget:
    connect_timeout_seconds: float = 3.0
    handshake_timeout_seconds: float = 3.0
    max_certificate_bytes: int = 65_536
    max_chain_length: int = 10


@dataclass(frozen=True)
class TLSObservation:
    status: TLSStatus
    negotiated_version: str | None = None
    negotiated_cipher: str | None = None
    trusted: bool = False
    hostname_verified: bool = False
    verification_error: str | None = None
    certificate_chain: tuple[bytes, ...] = field(default=(), repr=False)

    @property
    def is_conclusive(self) -> bool:
        return self.status in {"handshake_ok", "verification_failed", "handshake_failed"}


class TLSConnector(Protocol):
    def handshake(
        self,
        address: str,
        port: int,
        server_hostname: str,
        *,
        verify: bool,
        budget: TLSBudget,
        minimum_version: ssl.TLSVersion | None = None,
        maximum_version: ssl.TLSVersion | None = None,
    ) -> TLSObservation: ...


class SocketTLSConnector:
    """Live handshake connector. Address is already authorized and pinned by the broker."""

    def handshake(
        self,
        address: str,
        port: int,
        server_hostname: str,
        *,
        verify: bool,
        budget: TLSBudget,
        minimum_version: ssl.TLSVersion | None = None,
        maximum_version: ssl.TLSVersion | None = None,
    ) -> TLSObservation:
        context = ssl.create_default_context()
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        if minimum_version is not None:
            context.minimum_version = minimum_version
        if maximum_version is not None:
            context.maximum_version = maximum_version
        raw: socket.socket | None = None
        try:
            raw = socket.create_connection((address, port), timeout=budget.connect_timeout_seconds)
            raw.settimeout(budget.handshake_timeout_seconds)
            with context.wrap_socket(raw, server_hostname=server_hostname) as tls:
                raw = None
                chain = self._chain(tls, budget)
                cipher = tls.cipher()
                return TLSObservation(
                    "handshake_ok",
                    tls.version(),
                    cipher[0] if cipher else None,
                    trusted=verify,
                    hostname_verified=verify,
                    certificate_chain=chain,
                )
        except ssl.SSLCertVerificationError as exc:
            return TLSObservation("verification_failed", verification_error=exc.verify_message)
        except ssl.SSLError as exc:
            return TLSObservation("handshake_failed", verification_error=exc.reason)
        except TimeoutError:
            return TLSObservation("timeout")
        except ConnectionRefusedError:
            return TLSObservation("connection_refused")
        except OSError:
            return TLSObservation("error")
        finally:
            if raw is not None:
                raw.close()

    @staticmethod
    def _chain(tls: ssl.SSLSocket, budget: TLSBudget) -> tuple[bytes, ...]:
        try:
            raw_chain = tls.get_unverified_chain() or []
        except (AttributeError, ValueError):
            leaf = tls.getpeercert(binary_form=True)
            raw_chain = [leaf] if leaf else []
        chain: list[bytes] = []
        for certificate in raw_chain[: budget.max_chain_length]:
            der = certificate if isinstance(certificate, bytes) else bytes(certificate)
            if len(der) > budget.max_certificate_bytes:
                break
            chain.append(der)
        return tuple(chain)


@dataclass(frozen=True)
class ProtocolProbeResult:
    version: str
    supported: bool
    status: TLSStatus


class TLSInspector:
    """Observe certificate and protocol posture with a bounded number of handshakes."""

    def __init__(self, connector: TLSConnector, budget: TLSBudget | None = None) -> None:
        self._connector = connector
        self._budget = budget or TLSBudget()

    def inspect_certificate(self, address: str, port: int, server_hostname: str) -> TLSObservation:
        verified = self._connector.handshake(
            address, port, server_hostname, verify=True, budget=self._budget
        )
        if verified.status == "handshake_ok":
            return verified
        if not verified.is_conclusive:
            return verified
        observed = self._connector.handshake(
            address, port, server_hostname, verify=False, budget=self._budget
        )
        if observed.status != "handshake_ok":
            return verified
        return TLSObservation(
            verified.status,
            observed.negotiated_version,
            observed.negotiated_cipher,
            trusted=False,
            hostname_verified=False,
            verification_error=verified.verification_error,
            certificate_chain=observed.certificate_chain,
        )

    def probe_protocols(
        self,
        address: str,
        port: int,
        server_hostname: str,
        versions: tuple[str, ...] = PROTOCOL_PROBES,
    ) -> tuple[ProtocolProbeResult, ...]:
        results: list[ProtocolProbeResult] = []
        for version in versions:
            pinned = _PROBE_VERSIONS.get(version)
            if pinned is None:
                continue
            observation = self._connector.handshake(
                address,
                port,
                server_hostname,
                verify=False,
                budget=self._budget,
                minimum_version=pinned,
                maximum_version=pinned,
            )
            supported = (
                observation.status == "handshake_ok" and observation.negotiated_version == version
            )
            results.append(ProtocolProbeResult(version, supported, observation.status))
        return tuple(results)
