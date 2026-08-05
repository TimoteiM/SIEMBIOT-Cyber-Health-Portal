from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from siembiot_worker.network_safety.host_policy import HostPolicyError, canonical_host

VERIFICATION_PATH = "/.well-known/tyche-verification.txt"


class DestinationPolicyError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _canonical_host(host: str) -> str:
    try:
        return canonical_host(host)
    except HostPolicyError as exc:
        raise DestinationPolicyError(exc.reason) from exc


@dataclass(frozen=True)
class VerificationDestination:
    scheme: str
    host: str
    port: int
    path: str = VERIFICATION_PATH

    def __post_init__(self) -> None:
        if self.scheme not in {"http", "https"}:
            raise DestinationPolicyError("unsupported_scheme")
        _canonical_host(self.host)
        expected_port = 443 if self.scheme == "https" else 80
        if self.port != expected_port:
            raise DestinationPolicyError("forbidden_port")
        if self.path != VERIFICATION_PATH:
            raise DestinationPolicyError("forbidden_path")

    @classmethod
    def https(cls, canonical_host: str) -> VerificationDestination:
        return cls("https", _canonical_host(canonical_host), 443)

    @classmethod
    def http_upgrade(cls, canonical_host: str) -> VerificationDestination:
        return cls("http", _canonical_host(canonical_host), 80)

    @property
    def host_header(self) -> str:
        return self.host

    @property
    def request_target(self) -> str:
        return self.path

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}{self.path}"


def authorize_redirect(
    current: VerificationDestination,
    location: str,
    *,
    authorized_hosts: set[str],
) -> VerificationDestination:
    parsed = urlsplit(urljoin(current.url, location))
    if parsed.username is not None or parsed.password is not None:
        raise DestinationPolicyError("credentials")
    if parsed.fragment:
        raise DestinationPolicyError("fragment")
    if parsed.query:
        raise DestinationPolicyError("query")
    if parsed.scheme not in {"http", "https"}:
        raise DestinationPolicyError("unsupported_scheme")
    if current.scheme == "https" and parsed.scheme == "http":
        raise DestinationPolicyError("tls_downgrade")
    if parsed.path != VERIFICATION_PATH:
        raise DestinationPolicyError("forbidden_path")
    if any(character.isupper() for character in parsed.netloc):
        raise DestinationPolicyError("noncanonical_host")
    host = parsed.hostname
    if host is None:
        raise DestinationPolicyError("noncanonical_host")
    canonical_host = _canonical_host(host)
    try:
        port = parsed.port
    except ValueError as exc:
        raise DestinationPolicyError("forbidden_port") from exc
    expected_port = 443 if parsed.scheme == "https" else 80
    if port not in {None, expected_port}:
        raise DestinationPolicyError("forbidden_port")
    if canonical_host not in authorized_hosts:
        raise DestinationPolicyError("redirect_not_authorized")
    return VerificationDestination(parsed.scheme, canonical_host, expected_port)
