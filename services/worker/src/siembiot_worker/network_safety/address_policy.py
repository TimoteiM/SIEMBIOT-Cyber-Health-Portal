from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from siembiot_worker.network_safety.models import AddressDecision, NetworkReason


class AddressPolicyError(ValueError):
    pass


def parse_canonical_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not value or value != value.strip() or "%" in value:
        raise AddressPolicyError("noncanonical_address")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise AddressPolicyError("noncanonical_address") from exc
    if isinstance(parsed, ipaddress.IPv4Address) and value != str(parsed):
        raise AddressPolicyError("noncanonical_address")
    return parsed


def _is_forbidden(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return True
    return (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or not address.is_global
    )


def authorize_resolved_addresses(values: Iterable[str]) -> AddressDecision:
    raw = tuple(values)
    if not raw:
        return AddressDecision(False, "no_addresses", ())
    parsed: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        parsed = [parse_canonical_ip(value) for value in raw]
    except AddressPolicyError:
        return AddressDecision(False, "invalid_address", ())
    forbidden = [_is_forbidden(address) for address in parsed]
    if any(forbidden):
        reason: NetworkReason = "mixed_dns_answers" if not all(forbidden) else "forbidden_address"
        return AddressDecision(False, reason, ())
    canonical = tuple(dict.fromkeys(str(address) for address in parsed))
    return AddressDecision(True, "allowed", canonical)
