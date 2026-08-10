"""Probing ports: the first operation that asks a host something.

Every other collector reads what a target already publishes. This one opens a connection
to a port nobody advertised, so most of this file is about the conditions under which it
refuses to, and only a little of it about it working.

The tests never open a real socket. What is being checked is the boundary the broker
enforces around the socket, and a test that reached the network would be checking
somebody else's firewall instead.
"""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "collectors"))

from siembiot_worker.network_safety.collection_broker import (  # noqa: E402
    CollectionNetworkBroker,
    CollectionRequest,
)
from siembiot_worker.network_safety.collection_policy import OperationClass  # noqa: E402
from siembiot_worker.network_safety.dns_client import BoundedDNSClient  # noqa: E402
from siembiot_worker.network_safety.models import (  # noqa: E402
    BrokerCheckpoint,
    NetworkBudget,
    PolicyDecision,
)
from siembiot_worker.network_safety.port_probe import (  # noqa: E402
    CLOSED,
    FILTERED,
    OPEN,
    decode_banner,
)
from siembiot_worker.observation.mode import (  # noqa: E402
    AssessmentMode,
    allowed_operation_classes,
)

HOST = "authorized.example.test"
PUBLIC_ADDRESS = "93.184.216.34"


class RecordingProber:
    """Answers from a script and records exactly which ports were touched."""

    def __init__(self, answers: dict[int, tuple[str, bytes]] | None = None) -> None:
        self.answers = answers or {}
        self.probed: list[tuple[str, int]] = []

    def probe(
        self, address: str, port: int, connect_timeout: float, read_timeout: float
    ) -> tuple[str, bytes]:
        del connect_timeout, read_timeout
        self.probed.append((address, port))
        return self.answers.get(port, (CLOSED, b""))


class FixedResolver:
    def __init__(self, addresses: list[str]) -> None:
        self.addresses = addresses

    def resolve(self, host: str) -> tuple[str, ...]:
        del host
        return tuple(self.addresses)


class AllowAll:
    def authorize(
        self, request: CollectionRequest, checkpoint: BrokerCheckpoint, host: str
    ) -> PolicyDecision:
        del request, checkpoint, host
        return PolicyDecision(True, "allowed")


class RefuseAt:
    """An emergency control pulled part-way through, which is the interesting case."""

    def __init__(self, after: int) -> None:
        self.after = after
        self.connects = 0

    def authorize(
        self, request: CollectionRequest, checkpoint: BrokerCheckpoint, host: str
    ) -> PolicyDecision:
        del request, host
        if checkpoint is not BrokerCheckpoint.BEFORE_CONNECT:
            return PolicyDecision(True, "allowed")
        self.connects += 1
        if self.connects > self.after:
            return PolicyDecision(False, "emergency_control_active")
        return PolicyDecision(True, "allowed")


def broker(
    prober: RecordingProber | None = None,
    *,
    addresses: list[str] | None = None,
    policy: object | None = None,
) -> CollectionNetworkBroker:
    return CollectionNetworkBroker(
        resolver=FixedResolver(addresses or [PUBLIC_ADDRESS]),
        transport=object(),  # type: ignore[arg-type]
        policy=policy or AllowAll(),  # type: ignore[arg-type]
        dns_client=BoundedDNSClient(object(), None),  # type: ignore[arg-type]
        prober=prober or RecordingProber(),
        budget=NetworkBudget(max_concurrency=2),
    )


def request_for(operation_class: OperationClass = OperationClass.PORT_PROBE) -> CollectionRequest:
    return CollectionRequest(uuid4(), uuid4(), uuid4(), operation_class, HOST, (HOST,))


# -- when it refuses ---------------------------------------------------------


def test_probing_is_not_available_to_a_passive_run() -> None:
    """The whole reason this is authorized-only.

    Passive observation reads what a domain publishes to everyone. Opening a connection
    to a port nobody advertised is a question, and asking it is only ours to do because
    somebody with authority over the domain signed for it.
    """
    passive = allowed_operation_classes(AssessmentMode.PASSIVE_OBSERVATION)
    authorized = allowed_operation_classes(AssessmentMode.AUTHORIZED_ASSESSMENT)
    assert OperationClass.PORT_PROBE not in passive
    assert OperationClass.PORT_PROBE in authorized


def test_a_request_of_the_wrong_operation_class_probes_nothing() -> None:
    """Defence at the broker as well as at the mode, because the mode is a policy object
    somebody could assemble wrongly and this is a socket."""
    prober = RecordingProber()
    results = broker(prober).probe_ports(request_for(OperationClass.HTTP_SURFACE), [22, 3389])

    assert prober.probed == []
    assert {result.state for result in results} == {"error"}


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.1",
        "169.254.169.254",
        "::1",
        # Documentation ranges, refused as well -- found while writing this test, which
        # had used one as its "public" address on the assumption it would be allowed.
        # It means a demonstration cannot accidentally probe a documentation address and
        # come back looking like it worked.
        "203.0.113.10",
        "198.51.100.5",
    ],
)
def test_a_host_resolving_to_a_private_address_is_never_probed(address: str) -> None:
    """The port scanner is the sharpest instrument in this product, and it is exactly
    the one that must not be pointable at internal infrastructure.

    `169.254.169.254` is in the list on purpose: it is the cloud metadata service, and a
    domain that resolves there turns an assessment into credential theft.
    """
    prober = RecordingProber()
    results = broker(prober, addresses=[address]).probe_ports(request_for(), [22, 3389])

    assert prober.probed == [], f"{address} was connected to"
    assert {result.state for result in results} == {"error"}


def test_an_emergency_control_stops_a_scan_part_way_through() -> None:
    """Checked before every port rather than once at the start.

    A kill switch pulled during a scan has to stop the scan. Authorizing once and then
    working through a list means the control takes effect whenever the list happens to
    end, which on a slow host is minutes later.
    """
    # Three, not two: pinning the address authorizes a BEFORE_CONNECT of its own before
    # any port is touched, so the first allowance is spent on resolution.
    prober = RecordingProber()
    results = broker(prober, policy=RefuseAt(after=3)).probe_ports(
        request_for(), [22, 80, 443, 3389, 5432]
    )

    assert len(prober.probed) == 2, "the scan continued after the control was pulled"
    # What was already observed is kept: half a scan is evidence, and discarding it
    # would report the same as never having looked.
    assert [result.port for result in results] == [22, 80]


def test_the_address_is_pinned_once_for_the_whole_scan() -> None:
    """A name that changes mid-scan must not move the probe onto another host.

    It would also make the audit record ambiguous about what was actually touched, which
    for this operation is the record that matters most.
    """
    prober = RecordingProber()
    broker(prober, addresses=[PUBLIC_ADDRESS, "8.8.8.8"]).probe_ports(request_for(), [22, 80, 443])

    assert {address for address, _ in prober.probed} == {PUBLIC_ADDRESS}


# -- what it observes --------------------------------------------------------


def test_open_closed_and_filtered_stay_distinct() -> None:
    """Three different facts about the reader's infrastructure.

    `filtered` is a firewall doing its job, `closed` is a host that answered and said no,
    `open` is a service. Collapsing the first two into "not open" hides the difference
    between protected and simply absent.
    """
    prober = RecordingProber(
        {22: (OPEN, b"SSH-2.0-OpenSSH_9.6\r\n"), 3389: (FILTERED, b""), 80: (CLOSED, b"")}
    )
    results = {
        item.port: item for item in broker(prober).probe_ports(request_for(), [22, 80, 3389])
    }

    assert results[22].state == OPEN
    assert results[80].state == CLOSED
    assert results[3389].state == FILTERED
    assert results[22].banner == "SSH-2.0-OpenSSH_9.6"


def test_nothing_is_sent_to_the_target() -> None:
    """The prober has no way to write, and that is structural rather than a convention.

    Reading what a service announces of its own accord is an observation. Sending a probe
    string to elicit behaviour is an interaction, and the difference matters legally as
    much as technically.
    """
    from siembiot_worker.network_safety import port_probe

    source = Path(port_probe.__file__).read_text(encoding="utf-8")
    for writing in ("sendall", "\n        stream.send(", "\n    stream.write("):
        assert writing not in source, f"the prober can write to the target: {writing!r}"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"", None),
        (b"\x00\x01\x02", None),
        (b"SSH-2.0-OpenSSH_9.6\r\nmore", "SSH-2.0-OpenSSH_9.6"),
        (b"220 mail.example.test ESMTP\r\n", "220 mail.example.test ESMTP"),
    ],
)
def test_a_banner_is_one_printable_line_or_nothing(raw: bytes, expected: str | None) -> None:
    """A binary protocol's first bytes are not a message, and rendering them as one puts
    control characters into a report somebody opens in a terminal."""
    assert decode_banner(raw) == expected


def test_a_banner_is_bounded() -> None:
    """Enough to recognise a service, far too little to be a data collection mechanism."""
    from siembiot_worker.network_safety.port_probe import MAX_BANNER_BYTES

    assert MAX_BANNER_BYTES <= 1024
