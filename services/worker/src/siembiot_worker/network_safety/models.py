from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

NetworkReason = Literal[
    "allowed",
    "no_addresses",
    "invalid_address",
    "forbidden_address",
    "mixed_dns_answers",
]


@dataclass(frozen=True)
class AddressDecision:
    allowed: bool
    reason_code: NetworkReason
    addresses: tuple[str, ...]
