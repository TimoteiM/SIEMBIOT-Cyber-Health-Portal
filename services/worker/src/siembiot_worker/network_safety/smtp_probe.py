"""Whether mail to a domain can be encrypted on the way in.

A domain's MX record is a published invitation to connect on port 25 and speak SMTP:
that is the only thing it is for, and every mail server on the internet accepts that
invitation daily. So this is passive by the same test as the HTTP collector, which also
sends a request and is passive because a web server published itself to be fetched.

**The conversation stops at STARTTLS.** Greeting, `EHLO`, `STARTTLS`, handshake, `QUIT`.
Never `MAIL FROM`, never `RCPT TO`. Those would be probing what the server accepts and
who it will relay for, which is a question about somebody's mail policy rather than an
observation of their transport security -- and it is the line between reading a public
capability and testing a system.

What comes back is one fact worth having: mail arriving at this domain can, or cannot, be
encrypted in transit. A domain publishing DMARC and MTA-STS while its mail server refuses
STARTTLS has policy without transport, and no amount of DNS records fixes that.
"""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass
from typing import Protocol

#: Enough of a greeting and a capability list to find STARTTLS; far less than a message.
MAX_SMTP_BYTES = 4_096

SMTP_PORT = 25
SMTP_CONNECT_TIMEOUT_SECONDS = 3.0
SMTP_READ_TIMEOUT_SECONDS = 3.0

#: The name this client gives for itself. A real hostname rather than something clever:
#: an operator reading their mail logs should be able to tell who connected and why.
EHLO_NAME = "siembiot-observatory.invalid"

_STARTTLS = re.compile(r"^250[ -]STARTTLS\b", re.IGNORECASE | re.MULTILINE)

OFFERED = "offered"
NOT_OFFERED = "not_offered"
UNREACHABLE = "unreachable"
HANDSHAKE_FAILED = "handshake_failed"


@dataclass(frozen=True)
class MailTransportObservation:
    host: str
    state: str
    #: Present only where the handshake completed.
    tls_version: str | None = None
    certificate_matches_host: bool | None = None
    #: What the server called itself in its greeting, where it offered one.
    greeting: str | None = None


class MailTransportProber(Protocol):
    def probe(self, address: str, host: str) -> MailTransportObservation: ...


class SocketMailTransportProber:
    def probe(self, address: str, host: str) -> MailTransportObservation:
        try:
            stream = socket.create_connection(
                (address, SMTP_PORT), timeout=SMTP_CONNECT_TIMEOUT_SECONDS
            )
        except OSError:
            # Port 25 is very often blocked outbound by hosting providers, so this says
            # as much about where the assessment runs from as about the target. The
            # collector reports it as inconclusive rather than as a finding.
            return MailTransportObservation(host, UNREACHABLE)

        try:
            stream.settimeout(SMTP_READ_TIMEOUT_SECONDS)
            greeting = _read(stream)
            if not greeting.startswith("220"):
                return MailTransportObservation(host, UNREACHABLE, greeting=_first_line(greeting))

            stream.sendall(f"EHLO {EHLO_NAME}\r\n".encode("ascii"))
            capabilities = _read(stream)
            if not _STARTTLS.search(capabilities):
                _quit(stream)
                return MailTransportObservation(host, NOT_OFFERED, greeting=_first_line(greeting))

            stream.sendall(b"STARTTLS\r\n")
            if not _read(stream).startswith("220"):
                _quit(stream)
                return MailTransportObservation(
                    host, HANDSHAKE_FAILED, greeting=_first_line(greeting)
                )

            return _handshake(stream, host, greeting)
        except (OSError, UnicodeDecodeError):
            return MailTransportObservation(host, UNREACHABLE)
        finally:
            try:
                stream.close()
            except OSError:
                pass


def _handshake(stream: socket.socket, host: str, greeting: str) -> MailTransportObservation:
    """Complete TLS and report what it produced.

    Verification is attempted first and the result recorded either way. A mail server
    with a certificate that does not match its name still encrypts the connection, which
    is worth more than plaintext and less than a correct certificate -- and reporting
    only "encrypted" would lose that distinction entirely.
    """
    context = ssl.create_default_context()
    try:
        with context.wrap_socket(stream, server_hostname=host) as secure:
            return MailTransportObservation(
                host,
                OFFERED,
                tls_version=secure.version(),
                certificate_matches_host=True,
                greeting=_first_line(greeting),
            )
    except ssl.SSLCertVerificationError:
        pass
    except (ssl.SSLError, OSError):
        return MailTransportObservation(host, HANDSHAKE_FAILED, greeting=_first_line(greeting))
    return MailTransportObservation(
        host, OFFERED, certificate_matches_host=False, greeting=_first_line(greeting)
    )


def _read(stream: socket.socket) -> str:
    return stream.recv(MAX_SMTP_BYTES).decode("utf-8", errors="replace")


def _quit(stream: socket.socket) -> None:
    """Say goodbye properly. A dropped connection is an error line in somebody's log."""
    try:
        stream.sendall(b"QUIT\r\n")
    except OSError:
        pass


def _first_line(text: str) -> str | None:
    line = text.splitlines()[0].strip() if text.strip() else ""
    return "".join(character for character in line if character.isprintable())[:200] or None
