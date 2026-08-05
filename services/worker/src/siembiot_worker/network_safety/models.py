from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal
from uuid import UUID

NetworkReason = Literal[
    "allowed",
    "no_addresses",
    "invalid_address",
    "forbidden_address",
    "mixed_dns_answers",
    "emergency_control_active",
    "response_too_large",
    "headers_too_large",
    "redirect_limit",
    "redirect_not_authorized",
    "destination_rejected",
    "transport_error",
    "concurrency_limit",
]


@dataclass(frozen=True)
class AddressDecision:
    allowed: bool
    reason_code: NetworkReason
    addresses: tuple[str, ...]


class BrokerCheckpoint(StrEnum):
    BEFORE_RESOLUTION = "before_resolution"
    AFTER_RESOLUTION = "after_resolution"
    BEFORE_CONNECT = "before_connect"
    AFTER_HEADERS = "after_headers"
    BODY_CHUNK = "body_chunk"
    BEFORE_REDIRECT = "before_redirect"


@dataclass(frozen=True)
class NetworkBudget:
    connect_timeout_seconds: float = 2.0
    read_timeout_seconds: float = 2.0
    total_timeout_seconds: float = 5.0
    max_header_bytes: int = 8_192
    max_body_bytes: int = 4_096
    max_redirects: int = 2
    max_concurrency: int = 2


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason_code: str


@dataclass(frozen=True)
class TransportResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes
    raw_headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class VerificationFetchRequest:
    organization_id: UUID
    domain_id: UUID
    challenge_id: UUID
    canonical_host: str
    authorized_redirect_hosts: tuple[str, ...]


@dataclass(frozen=True)
class BrokerResult:
    allowed: bool
    reason_code: str
    status_code: int | None = None
    body: bytes = field(default=b"", repr=False)
    redirect_count: int = 0
