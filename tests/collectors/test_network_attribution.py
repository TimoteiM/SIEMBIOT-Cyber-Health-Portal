"""Who operates the addresses a domain resolves to.

The value of this collector is a sentence an institution cannot write for itself: the
website is on a network belonging to *this* company, in *this* country. So the tests care
about the name coming out, and about the two ways it silently did not.
"""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from siembiot_worker.adapters.contract import (  # noqa: E402
    CollectionResult,
    CollectionStatus,
)
from siembiot_worker.collectors.network_attribution import (  # noqa: E402
    MAX_ADDRESSES,
    NetworkAttributionCollector,
    parse_asn_name,
    parse_origin,
    reverse_query_name,
)
from siembiot_worker.network_safety.collection_broker import CollectionRequest  # noqa: E402
from siembiot_worker.network_safety.collection_policy import OperationClass  # noqa: E402
from siembiot_worker.network_safety.dns_client import DNSQuery, DNSRecordSet  # noqa: E402
from siembiot_worker.network_safety.host_policy import (  # noqa: E402
    HostPolicyError,
    canonical_dns_name,
)

HOST = "apavil.ro"


class ScriptedDNS:
    """Answers TXT lookups from a script and records every name asked for."""

    def __init__(self, answers: dict[str, str]) -> None:
        self.answers = answers
        self.asked: list[str] = []

    def query_dns(
        self, request: CollectionRequest, name: str, record_type: str, **kwargs: object
    ) -> DNSRecordSet:
        del request, kwargs
        self.asked.append(name)
        record = self.answers.get(name)
        query = DNSQuery(name, record_type)
        return DNSRecordSet(
            query, "answered" if record else "nxdomain", (record,) if record else ()
        )


ORIGIN = "109.247.2.5.origin.asn.cymru.com"
ASN = "as8708.asn.cymru.com"
ANSWERS = {
    ORIGIN: '"8708 | 5.2.128.0/17 | RO | ripencc | 1998-03-11"',
    ASN: '"8708 | RO | ripencc | 1998-03-11 | DIGI-RO - DIGI ROMANIA S.A., RO"',
}


def collect(
    answers: dict[str, str], addresses: tuple[str, ...] = ("5.2.247.109",)
) -> tuple[CollectionResult, ScriptedDNS]:
    broker = ScriptedDNS(answers)
    request = CollectionRequest(uuid4(), uuid4(), uuid4(), OperationClass.DNS_QUERY, HOST, (HOST,))
    result = NetworkAttributionCollector(broker).collect(request, addresses)  # type: ignore[arg-type]
    return result, broker


# -- the names it asks for ---------------------------------------------------


def test_every_name_it_queries_is_canonical() -> None:
    """The bug that made every network come back unnamed.

    The AS lookup was written `AS8708.asn.cymru.com`, which reads correctly and is not a
    canonical host. The DNS client refuses a non-canonical name rather than quietly
    normalising it, so the query returned nothing and every operator was reported as
    unknown -- with the ASN right there beside it, which made it look like the naming
    service was down.
    """
    _, broker = collect(ANSWERS)
    assert broker.asked, "no lookups were made"
    for name in broker.asked:
        try:
            canonical_dns_name(name)
        except HostPolicyError as exc:  # pragma: no cover - the assertion is the point
            pytest.fail(f"{name} is not canonical: {exc.reason}")


def test_an_address_becomes_the_reversed_query_name() -> None:
    assert reverse_query_name("5.2.247.109") == ORIGIN
    assert (
        reverse_query_name(
            "2001:db8::1",
        )
        is not None
    )
    assert reverse_query_name("not-an-address") is None
    assert reverse_query_name("") is None


def test_the_number_of_addresses_looked_up_is_bounded() -> None:
    """A domain behind a large CDN resolves to dozens, and the answer for the first few
    is the same network. The rest is a longer list saying the same thing at somebody
    else's expense."""
    addresses = tuple(f"5.2.247.{n}" for n in range(1, MAX_ADDRESSES + 10))
    _, broker = collect(ANSWERS, addresses)

    origin_lookups = [name for name in broker.asked if name.endswith("origin.asn.cymru.com")]
    assert len(origin_lookups) == MAX_ADDRESSES


# -- what it reports ---------------------------------------------------------


def test_the_operator_is_named_not_just_numbered() -> None:
    """An ASN is not an answer anybody can act on; a company name is."""
    result, _ = collect(ANSWERS)

    assert result.status is CollectionStatus.OK
    assert result.payload["operators"] == ["DIGI-RO - DIGI ROMANIA S.A., RO"]
    assert result.payload["countries"] == ["RO"]
    assert result.payload["addresses"][0]["asn"] == "8708"


def test_a_domain_that_resolves_to_nothing_is_not_an_error() -> None:
    """The DNS collector has already said why, and saying it again under a second name
    puts one problem in front of the reader twice."""
    result, broker = collect(ANSWERS, ())

    assert result.status is CollectionStatus.NOT_APPLICABLE
    assert result.reason_code == "no_addresses_observed"
    assert broker.asked == []


def test_an_unreachable_attribution_service_does_not_fault_the_domain() -> None:
    """Nothing here measures the target. Failing to name somebody else's network is a
    gap in our knowledge, not a fault in theirs, and it must not drag a run to
    partially completed and send the reader hunting for a problem."""
    result, _ = collect({})

    assert result.status is CollectionStatus.NOT_APPLICABLE
    assert result.reason_code == "attribution_unavailable"


def test_a_prefix_announced_by_several_networks_keeps_the_others() -> None:
    """Two answers to "who announces this" is itself worth seeing."""
    parsed = parse_origin('"8708 12345 | 5.2.128.0/17 | RO | ripencc | 1998-03-11"')
    assert parsed is not None
    assert parsed["asn"] == "8708"
    assert parsed["also_announced_by"] == "12345"


@pytest.mark.parametrize("record", ['"malformed"', '""', '"| | |"', '"8708"'])
def test_a_malformed_answer_yields_nothing_rather_than_a_wrong_name(record: str) -> None:
    assert parse_origin(record) is None or parse_asn_name(record) is None
