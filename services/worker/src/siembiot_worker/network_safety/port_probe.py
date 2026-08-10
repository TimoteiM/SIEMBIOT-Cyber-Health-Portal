"""Asking a host whether a port answers.

Every other collector in this product reads something the target already publishes. This
one asks a question, which is why it runs only under a signed authorization -- and why
the way it asks is as constrained as what it asks.

**A full TCP connect, never a half-open scan.** A SYN scan needs raw sockets and leaves
the target with a connection it never saw completed, which is both harder to log and
harder to explain afterwards. A completed connection appears in the customer's own logs
exactly as any client's would, and an authorized assessment they cannot see in their logs
is one they cannot audit.

**Nothing is ever sent.** The prober connects, optionally reads whatever the service
announces of its own accord, and closes. Services that identify themselves -- SSH, SMTP,
FTP, Redis -- do so unprompted, so a banner is still an observation rather than an
interaction. Sending a probe string would make this an attempt to elicit behaviour, and
the difference matters legally as much as technically.

**Bounded in every direction.** One connection at a time, a short connect timeout, a
shorter read timeout, and a banner capped at a few hundred bytes. A scanner that can be
pointed at somebody's infrastructure and left running is a denial-of-service tool with a
report attached.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Protocol

#: How much of a service's own announcement is kept. Enough to recognise "SSH-2.0-..."
#: or an SMTP greeting; far too little to be a data collection mechanism.
MAX_BANNER_BYTES = 256

#: States a probe can end in, kept distinct because they mean different things to the
#: person reading the report. `filtered` is a firewall doing its job; `closed` is a host
#: that answered and said no; `open` is a service. Collapsing the first two into "not
#: open" would hide the difference between protected and simply absent.
OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"
ERROR = "error"


@dataclass(frozen=True)
class PortObservation:
    port: int
    state: str
    #: Only ever what the service said first. Absent unless it announced itself.
    banner: str | None = None

    @property
    def is_open(self) -> bool:
        return self.state == OPEN


class PortConnector(Protocol):
    """The socket layer, injected so tests never open a real connection."""

    def probe(
        self, address: str, port: int, connect_timeout: float, read_timeout: float
    ) -> tuple[str, bytes]:
        """Return the state and whatever the service announced, if anything."""


class SocketPortConnector:
    def probe(
        self, address: str, port: int, connect_timeout: float, read_timeout: float
    ) -> tuple[str, bytes]:
        stream = socket.socket(
            socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM
        )
        stream.settimeout(connect_timeout)
        try:
            stream.connect((address, port))
        except TimeoutError:
            # No answer at all, which is what a packet filter looks like from here.
            return FILTERED, b""
        except ConnectionRefusedError:
            # The host answered and refused: reachable, nothing listening.
            return CLOSED, b""
        except OSError:
            return ERROR, b""

        try:
            stream.settimeout(read_timeout)
            try:
                # No request is written first. Anything read here is what the service
                # volunteered on connect.
                return OPEN, stream.recv(MAX_BANNER_BYTES)
            except (TimeoutError, OSError):
                return OPEN, b""
        finally:
            stream.close()


def decode_banner(raw: bytes) -> str | None:
    """The printable first line of what a service announced.

    One line, because a banner is an identifier rather than a document, and printable
    only: a binary protocol's first bytes are not a message and rendering them as one
    puts control characters into a report somebody opens in a terminal.
    """
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace").splitlines()
    if not text:
        return None
    cleaned = "".join(character for character in text[0] if character.isprintable()).strip()
    return cleaned or None
