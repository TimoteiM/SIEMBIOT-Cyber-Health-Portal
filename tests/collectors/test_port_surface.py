"""The exposed service inventory.

What this collector produces is meant to be read by somebody who runs a town hall, not
by somebody who runs a network. So the tests care as much about what the payload says as
about whether the scan worked: an open port that nobody can act on is not a finding.
"""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from siembiot_worker.adapters.contract import CollectionResult, CollectionStatus  # noqa: E402
from siembiot_worker.collectors.port_surface import (  # noqa: E402
    EXPOSURE_ORDER,
    PORT_DESCRIPTOR,
    PortSurfaceCollector,
    load_port_catalog,
)
from siembiot_worker.network_safety.collection_broker import CollectionRequest  # noqa: E402
from siembiot_worker.network_safety.collection_policy import OperationClass  # noqa: E402
from siembiot_worker.network_safety.port_probe import (  # noqa: E402
    CLOSED,
    FILTERED,
    OPEN,
    PROBE_CONNECT_TIMEOUT_SECONDS,
    PROBE_READ_TIMEOUT_SECONDS,
    PortObservation,
)

HOST = "authorized.example.test"


class ScriptedBroker:
    """Returns port observations from a script; opens nothing."""

    def __init__(self, states: dict[int, str], banners: dict[int, str] | None = None) -> None:
        self.states = states
        self.banners = banners or {}

    def probe_ports(
        self, request: CollectionRequest, ports: list[int]
    ) -> tuple[PortObservation, ...]:
        del request
        return tuple(
            PortObservation(port, self.states.get(port, CLOSED), self.banners.get(port))
            for port in ports
        )


def collect(states: dict[int, str], banners: dict[int, str] | None = None) -> CollectionResult:
    collector = PortSurfaceCollector(ScriptedBroker(states, banners))  # type: ignore[arg-type]
    request = CollectionRequest(uuid4(), uuid4(), uuid4(), OperationClass.PORT_PROBE, HOST, (HOST,))
    return collector.collect(request)


# -- the catalogue -----------------------------------------------------------


def test_a_scan_fits_inside_the_timeout_the_adapter_declares() -> None:
    """The one collector whose duration is a multiplication.

    Port count times the per-port timeout has to fit the thirty seconds the adapter
    contract allows. Asserting it here means growing the catalogue cannot quietly push a
    scan past the contract it declares -- it fails a test instead of timing out against
    somebody's firewall.
    """
    ports = load_port_catalog()
    worst_case = len(ports) * (PROBE_CONNECT_TIMEOUT_SECONDS + PROBE_READ_TIMEOUT_SECONDS)
    assert worst_case <= PORT_DESCRIPTOR.timeout_seconds


def test_every_port_explains_itself_in_both_languages() -> None:
    """ "Port 3389 is open" is not something a town clerk can act on."""
    for definition in load_port_catalog():
        # A title names the thing and a rationale explains it, so only the second reads
        # as a sentence. Requiring both to end in a full stop was this test being wrong
        # about the catalogue rather than the catalogue being wrong.
        for title in (definition.title_ro, definition.title_en):
            assert title.strip(), definition.port
            assert not title.strip().endswith("."), f"{definition.port}: a title is not a sentence"
        for rationale in (definition.rationale_ro, definition.rationale_en):
            assert rationale.strip().endswith("."), f"{definition.port}: should be a sentence"


def test_the_catalogue_covers_the_exposures_that_end_in_ransomware() -> None:
    """Remote access and databases are the two classes that actually cost an
    organisation everything. A catalogue without them would be an inventory of trivia."""
    ports = load_port_catalog()
    by_exposure = {
        exposure: [p for p in ports if p.exposure == exposure] for exposure in EXPOSURE_ORDER
    }
    assert {p.port for p in by_exposure["remote_access"]} >= {3389, 445, 5900}
    assert {p.port for p in by_exposure["database"]} >= {3306, 5432, 27017, 6379}


def test_the_inventory_is_never_publishable() -> None:
    """A list of a customer's open ports is the single most useful thing this product
    could hand an attacker. It is tenant data and must never reach the observatory."""
    from siembiot_worker.adapters.contract import DataClassification

    assert PORT_DESCRIPTOR.data_classification is DataClassification.TENANT_CONFIDENTIAL


def test_a_scan_is_never_cached() -> None:
    """Every other collector's answer stays true for a while. This one describes a
    network at one moment, and a cached scan is a stale claim wearing fresh evidence."""
    assert PORT_DESCRIPTOR.cache.ttl_seconds == 0


# -- what a scan reports -----------------------------------------------------


def test_open_ports_are_summarised_by_the_worst_exposure() -> None:
    """So a host can be described in one word without the reader ranking the list."""
    result = collect({443: OPEN, 3389: OPEN, 80: OPEN})

    assert result.status is CollectionStatus.OK
    assert result.payload["worst_exposure"] == "remote_access"
    assert result.payload["open_count"] == 3
    assert result.payload["open_by_exposure"]["remote_access"] == 1
    assert result.payload["open_by_exposure"]["infrastructure"] == 2


def test_a_host_with_only_ordinary_services_says_so() -> None:
    result = collect({80: OPEN, 443: OPEN})
    assert result.payload["worst_exposure"] == "infrastructure"


def test_a_host_with_nothing_open_is_a_result_not_a_failure() -> None:
    result = collect({})
    assert result.status is CollectionStatus.OK
    assert result.payload["open_count"] == 0
    assert result.payload["worst_exposure"] is None


def test_a_scan_that_reached_nothing_is_not_reported_as_a_clean_surface() -> None:
    """The failure that would matter most.

    If every probe errored, our packets never arrived. Recording that as "nothing open"
    would tell an institution its surface is clean on the strength of a scan that never
    happened.
    """
    result = collect(dict.fromkeys((port.port for port in load_port_catalog()), "error"))

    assert result.status is not CollectionStatus.OK
    assert result.reason_code == "probe_refused"


def test_filtered_is_kept_apart_from_closed() -> None:
    """A firewall doing its job and a service that simply is not there are different
    facts about an institution, and only one of them is reassuring."""
    result = collect({3389: FILTERED, 5900: CLOSED})

    assert result.payload["filtered_count"] == 1
    states = {item["port"]: item["state"] for item in result.payload["ports"]}
    assert states[3389] == FILTERED
    assert states[5900] == CLOSED


def test_a_banner_is_carried_only_where_the_service_offered_one() -> None:
    result = collect({22: OPEN, 443: OPEN}, {22: "SSH-2.0-OpenSSH_9.6"})
    banners = {item["port"]: item["banner"] for item in result.payload["ports"]}

    assert banners[22] == "SSH-2.0-OpenSSH_9.6"
    assert banners[443] is None


@pytest.mark.parametrize("port", [3389, 445, 6379, 27017])
def test_the_services_that_matter_carry_a_severity_worth_acting_on(port: int) -> None:
    """RDP, SMB, Redis and MongoDB open to the internet are how organisations lose
    everything. If any of them were informational the report would be politely wrong."""
    definition = next(item for item in load_port_catalog() if item.port == port)
    assert definition.severity == "critical"
