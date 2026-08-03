from __future__ import annotations

import socket
from collections.abc import Callable

SocketAddress = tuple[str, int] | tuple[str, int, int, int]
DNSAnswer = tuple[int, int, int, str, SocketAddress]
Lookup = Callable[[str, int, int, int], list[DNSAnswer]]


class SystemResolver:
    """Resolve every address for a host; authorization happens in the broker."""

    def __init__(self, lookup: Lookup | None = None) -> None:
        self._lookup = lookup

    def resolve(self, host: str) -> tuple[str, ...]:
        if self._lookup is None:
            answers = socket.getaddrinfo(host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
            addresses = (str(answer[4][0]) for answer in answers)
        else:
            injected_answers = self._lookup(host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
            addresses = (str(answer[4][0]) for answer in injected_answers)
        return tuple(dict.fromkeys(addresses))
