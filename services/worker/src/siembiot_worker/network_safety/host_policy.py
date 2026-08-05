from __future__ import annotations

import ipaddress

import idna


class HostPolicyError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def canonical_host(host: str) -> str:
    """Accept only an already-canonical, non-literal, A-label host name."""
    if not host or host != host.lower() or host.endswith("."):
        raise HostPolicyError("noncanonical_host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise HostPolicyError("ip_literal")
    try:
        encoded = idna.encode(host, uts46=True, std3_rules=True, transitional=False).decode("ascii")
    except idna.IDNAError as exc:
        raise HostPolicyError("noncanonical_host") from exc
    if encoded != host:
        raise HostPolicyError("noncanonical_host")
    return host


def canonical_dns_name(name: str) -> str:
    """Canonicalize a DNS owner name, allowing the underscore labels used by policy records."""
    if not name or name != name.lower() or name.endswith("."):
        raise HostPolicyError("noncanonical_host")
    labels = name.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        raise HostPolicyError("noncanonical_host")
    underscore_labels = [label for label in labels if label.startswith("_")]
    remainder = ".".join(label for label in labels if not label.startswith("_"))
    for label in underscore_labels:
        body = label[1:]
        if not body or not all(character.isalnum() or character == "-" for character in body):
            raise HostPolicyError("noncanonical_host")
    canonical_host(remainder)
    return name
