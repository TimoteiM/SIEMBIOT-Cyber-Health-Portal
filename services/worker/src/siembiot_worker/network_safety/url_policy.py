from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import idna

VERIFICATION_PATH = "/.well-known/tyche-verification.txt"


class DestinationPolicyError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _canonical_host(host: str) -> str:
    if not host or host != host.lower() or host.endswith("."):
        raise DestinationPolicyError("noncanonical_host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise DestinationPolicyError("ip_literal")
    try:
        encoded = idna.encode(host, uts46=True, std3_rules=True, transitional=False).decode("ascii")
    except idna.IDNAError as exc:
        raise DestinationPolicyError("noncanonical_host") from exc
    if encoded != host:
        raise DestinationPolicyError("noncanonical_host")
    return host


def canonical_host(host: str) -> str:
    """Validate an already-canonical DNS host without resolving it."""

    return _canonical_host(host)


SERVICE_LABEL = re.compile(r"^_[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def canonical_dns_name(name: str) -> str:
    """Validate a DNS owner name, including underscore-prefixed service labels."""

    if not name or name != name.lower() or name.endswith(".") or len(name) > 253:
        raise DestinationPolicyError("noncanonical_dns_name")
    labels = name.split(".")
    if any(not label for label in labels):
        raise DestinationPolicyError("noncanonical_dns_name")
    try:
        for label in labels:
            if label.startswith("_"):
                if SERVICE_LABEL.fullmatch(label) is None:
                    raise DestinationPolicyError("noncanonical_dns_name")
            elif (
                idna.encode(label, uts46=True, std3_rules=True, transitional=False).decode("ascii")
                != label
            ):
                raise DestinationPolicyError("noncanonical_dns_name")
    except idna.IDNAError as exc:
        raise DestinationPolicyError("noncanonical_dns_name") from exc
    return name


COLLECTION_PATHS = frozenset({"/", "/.well-known/security.txt"})


@dataclass(frozen=True)
class CollectionDestination:
    scheme: str
    host: str
    path: str

    def __post_init__(self) -> None:
        if self.scheme not in {"http", "https"}:
            raise DestinationPolicyError("unsupported_scheme")
        _canonical_host(self.host)
        if self.path not in COLLECTION_PATHS:
            raise DestinationPolicyError("forbidden_path")

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}{self.path}"


def authorize_collection_redirect(
    current: CollectionDestination,
    location: str,
    *,
    authorized_hosts: set[str],
) -> CollectionDestination:
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
    if parsed.path not in COLLECTION_PATHS:
        raise DestinationPolicyError("forbidden_path")
    if any(character.isupper() for character in parsed.netloc):
        raise DestinationPolicyError("noncanonical_host")
    host = parsed.hostname
    if host is None:
        raise DestinationPolicyError("noncanonical_host")
    canonical = _canonical_host(host)
    try:
        port = parsed.port
    except ValueError as exc:
        raise DestinationPolicyError("forbidden_port") from exc
    expected_port = 443 if parsed.scheme == "https" else 80
    if port not in {None, expected_port}:
        raise DestinationPolicyError("forbidden_port")
    if canonical not in authorized_hosts:
        raise DestinationPolicyError("redirect_not_authorized")
    return CollectionDestination(parsed.scheme, canonical, parsed.path)


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
