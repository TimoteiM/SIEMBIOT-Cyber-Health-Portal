"""The mail transport check, and the line it must not cross.

Two properties matter here and they pull against each other. The check has to be worth
having -- a domain whose mail server refuses STARTTLS should learn it, and a domain with
perfect DNS records and a plaintext mail server is exactly the case no other check in
this methodology can see. And it has to stay passive, which means the conversation stops
before anything that asks the server what it will accept or who it will relay for.

The first is tested by the scoring path; the second is tested by reading what was
actually put on the wire, because a prober that quietly said one word too many would
still pass every test written about its return value.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import cast

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from siembiot_worker.adapters.contract import CollectionResult  # noqa: E402
from siembiot_worker.collectors.mail_transport import (  # noqa: E402
    MAX_MAIL_HOSTS,
    MailTransportCollector,
)
from siembiot_worker.network_safety.collection_broker import (  # noqa: E402
    CollectionNetworkBroker,
    CollectionRequest,
)
from siembiot_worker.network_safety.collection_policy import OperationClass  # noqa: E402
from siembiot_worker.network_safety.smtp_probe import (  # noqa: E402
    HANDSHAKE_FAILED,
    NOT_OFFERED,
    OFFERED,
    UNREACHABLE,
    MailTransportObservation,
    SocketMailTransportProber,
)
from siembiot_worker.observation.mode import PASSIVE_OPERATION_CLASSES  # noqa: E402
from siembiot_worker.workflows.handlers import AssessmentContext, _mail_hosts  # noqa: E402

DOMAIN = "apavil.ro"


class StubBroker:
    """Records which hosts were probed and answers with a scripted state per host."""

    def __init__(self, states: dict[str, str]) -> None:
        self.states = states
        self.probed: list[str] = []

    def probe_mail_transport(self, request: object, mail_host: str) -> MailTransportObservation:
        del request
        self.probed.append(mail_host)
        state = self.states.get(mail_host, UNREACHABLE)
        return MailTransportObservation(
            mail_host,
            state,
            tls_version="TLSv1.3" if state == OFFERED else None,
            certificate_matches_host=True if state == OFFERED else None,
        )


class _Request:
    canonical_host = DOMAIN


def collect(states: dict[str, str], hosts: tuple[str, ...]) -> tuple[CollectionResult, StubBroker]:
    broker = StubBroker(states)
    collector = MailTransportCollector(cast(CollectionNetworkBroker, broker))
    return collector.collect(cast(CollectionRequest, _Request()), hosts), broker


# -- the boundary --------------------------------------------------------------------


class FakeSocket:
    """A mail server that offers everything, so nothing constrains what the prober says."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self._replies = [b"220 mail.apavil.ro ESMTP\r\n", b"250-mail\r\n250 STARTTLS\r\n"]

    def settimeout(self, _: float) -> None: ...

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, _: int) -> bytes:
        return self._replies.pop(0) if self._replies else b""

    def close(self) -> None: ...


def test_the_prober_never_offers_a_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """The whole passive classification rests on this.

    `MAIL FROM` and `RCPT TO` ask what the server accepts and who it will relay for.
    Those are questions about somebody's mail policy rather than observations of their
    transport security, and sending either would make this an active probe regardless of
    what the docstrings claim. Asserted against the bytes on the wire: a prober that said
    one word too many would still return the same observation.
    """
    fake = FakeSocket()
    monkeypatch.setattr(
        "siembiot_worker.network_safety.smtp_probe.socket.create_connection",
        lambda *args, **kwargs: fake,
    )

    SocketMailTransportProber().probe("192.0.2.1", "mail.apavil.ro")

    wire = b"".join(fake.sent).upper()
    assert b"MAIL FROM" not in wire
    assert b"RCPT TO" not in wire
    assert b"DATA" not in wire
    assert b"VRFY" not in wire
    assert b"EXPN" not in wire
    # And what it does send: a greeting under a name an operator can look up, then the
    # upgrade request. Nothing else.
    assert wire.startswith(b"EHLO ")
    assert b"STARTTLS" in wire


def test_mail_transport_is_passive() -> None:
    """Not merely allowed in a passive run -- listed in the passive set, which is the
    thing the broker and the step handler both consult."""
    assert OperationClass.SMTP_STARTTLS in PASSIVE_OPERATION_CLASSES


# -- what gets scored ----------------------------------------------------------------


def test_one_server_without_starttls_fails_the_domain() -> None:
    """A sender that cannot reach the first server will use the next one. Scoring "some
    of them encrypt" as a pass would describe a domain that is protected only when the
    routing happens to be convenient."""
    result, _ = collect(
        {"mx1.apavil.ro": OFFERED, "mx2.apavil.ro": NOT_OFFERED},
        ("mx1.apavil.ro", "mx2.apavil.ro"),
    )

    assert result.payload["starttls_everywhere"] is False
    assert result.payload["starttls_refused"] == 1


def test_every_server_offering_starttls_passes() -> None:
    result, _ = collect(
        {"mx1.apavil.ro": OFFERED, "mx2.apavil.ro": OFFERED},
        ("mx1.apavil.ro", "mx2.apavil.ro"),
    )

    assert result.payload["starttls_everywhere"] is True
    assert result.payload["hosts_checked"] == 2


def test_unreachable_hosts_do_not_count_against_the_domain() -> None:
    """Port 25 outbound is blocked by a great many hosting providers. A domain scored
    down because of where our worker happens to run would be a finding manufactured out
    of our own network conditions, and the operator would find nothing to fix."""
    result, _ = collect(
        {"mx1.apavil.ro": OFFERED, "mx2.apavil.ro": UNREACHABLE},
        ("mx1.apavil.ro", "mx2.apavil.ro"),
    )

    assert result.payload["starttls_everywhere"] is True
    assert result.payload["hosts_checked"] == 1
    assert result.payload["unreachable"] == 1


def test_no_reachable_host_is_not_applicable_rather_than_a_failure() -> None:
    """Every host unreachable says where the assessment ran from, not what the servers
    do. `not_applicable` keeps the coverage denominator; reporting it as no encryption
    would put a finding in front of somebody that is not true of their domain."""
    result, _ = collect({}, ("mx1.apavil.ro",))

    assert result.reason_code == "mail_hosts_unreachable"
    assert not result.usable


def test_a_domain_with_no_mail_is_not_failing_at_mail_security() -> None:
    result, broker = collect({}, ())

    assert result.reason_code == "no_mail_hosts"
    assert broker.probed == []


def test_a_broken_handshake_is_not_encryption() -> None:
    """A server that advertises STARTTLS and then cannot complete it leaves the sender
    choosing between plaintext and not delivering. Counting the advertisement would score
    the promise rather than the capability."""
    result, _ = collect({"mx1.apavil.ro": HANDSHAKE_FAILED}, ("mx1.apavil.ro",))

    assert result.payload["starttls_everywhere"] is False
    assert result.payload["starttls_broken"] == 1


def test_the_number_of_hosts_probed_is_bounded() -> None:
    """A domain can publish a long MX list, and each host costs an SMTP timeout."""
    hosts = tuple(f"mx{index}.apavil.ro" for index in range(MAX_MAIL_HOSTS + 5))
    _, broker = collect({host: OFFERED for host in hosts}, hosts)

    assert len(broker.probed) == MAX_MAIL_HOSTS


def test_hosts_are_probed_in_preference_order() -> None:
    """Where the list is longer than the bound, the ones checked should be the ones that
    actually receive mail rather than whichever the resolver listed first."""
    assert _mail_hosts(
        _context_with_email(
            _Observed(
                {
                    "mx": {
                        "hosts": [
                            {"preference": 30, "exchange": "backup.apavil.ro"},
                            {"preference": 10, "exchange": "primary.apavil.ro"},
                            {"preference": 20, "exchange": "secondary.apavil.ro"},
                        ]
                    }
                }
            )
        )
    ) == ("primary.apavil.ro", "secondary.apavil.ro", "backup.apavil.ro")


def test_a_failed_email_step_yields_no_mail_hosts() -> None:
    """Rather than an empty MX list read off an unusable payload, which the collector
    would report as "this domain receives no mail" -- a different statement, and a wrong
    one."""
    assert _mail_hosts(_context_with_email(_Observed({}, usable=False))) == ()
    assert _mail_hosts(_context_with_email(None)) == ()


class _Observed:
    def __init__(self, payload: dict[str, object], usable: bool = True) -> None:
        self.payload = payload
        self.usable = usable


def _context_with_email(email: object) -> AssessmentContext:
    class _Context:
        collection = {"email": email} if email is not None else {}

    return cast(AssessmentContext, _Context())
