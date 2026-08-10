"""Who actually operates the addresses a domain resolves to (pillar D).

An institution generally knows its website exists and often does not know who runs the
machine it is on. That matters twice over: the self-assessment asks whether suppliers
with access to systems are inventoried, and this is the one part of that question the
platform can answer for itself; and a service that has quietly moved onto a personal VPS
looks identical from the outside until somebody names the network.

Answered entirely over DNS, through Team Cymru's origin lookup, so it is passive by the
same definition as everything else in a public observation: a query to a public resolver
about a public fact. Nothing is asked of the target.

It reads the addresses the DNS collector already observed rather than resolving again. A
second resolution can legitimately return a different answer -- round-robin, anycast,
a short time-to-live -- and attribution describing an address the rest of the assessment
never saw would be a fact about neither.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from siembiot_worker.adapters.contract import (
    AdapterDescriptor,
    AdapterGroup,
    CachePolicy,
    CollectionResult,
    CostUnit,
    DataClassification,
    RateLimitPolicy,
)
from siembiot_worker.collectors.base import Clock, Collector, utc_now
from siembiot_worker.network_safety.collection_broker import (
    CollectionNetworkBroker,
    CollectionRequest,
)

#: Team Cymru answer these over DNS as a public service. Reversed-octet queries under
#: `origin` give the announcing network for an address; `asn` gives that network a name.
ORIGIN_ZONE_V4 = "origin.asn.cymru.com"
ORIGIN_ZONE_V6 = "origin6.asn.cymru.com"
ASN_ZONE = "asn.cymru.com"

#: How many addresses one host's attribution will look up. A domain behind a large CDN
#: can resolve to dozens; the answer for the first few is the same network, and the
#: remainder is a longer list saying the same thing at somebody else's expense.
MAX_ADDRESSES = 4

ATTRIBUTION_DESCRIPTOR = AdapterDescriptor(
    adapter_id="network_attribution",
    version="1.0.0",
    group=AdapterGroup.DNS_RDAP,
    title="Announcing network attribution",
    capabilities=frozenset({"network.attribution"}),
    data_classification=DataClassification.PUBLIC_OBSERVATION,
    terms_notes=(
        "Team Cymru publish IP-to-ASN mapping over DNS as a free service for network "
        "operators and researchers. Queries are bounded per assessment and ask only "
        "about addresses the domain already resolves to publicly."
    ),
    terms_url="https://team-cymru.com/community-services/ip-asn-mapping/",
    required_secrets=frozenset(),
    timeout_seconds=15.0,
    rate_limit=RateLimitPolicy(4, 1.0, burst=2, minimum_interval_seconds=0.2),
    cost_unit=CostUnit.NONE,
    cache=CachePolicy(86_400),
    supports_fixtures=True,
)


def reverse_query_name(address: str) -> str | None:
    """The Cymru query name for an address, or None if it is not one.

    IPv4 reverses the octets; IPv6 reverses the nibbles of the expanded form. Anything
    that does not parse is not queried at all: the addresses arrive from an earlier
    collector, and a malformed one is a bug worth failing quietly on rather than a
    string to concatenate into a DNS name.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv4Address):
        return f"{'.'.join(reversed(parsed.exploded.split('.')))}.{ORIGIN_ZONE_V4}"
    nibbles = parsed.exploded.replace(":", "")
    return f"{'.'.join(reversed(nibbles))}.{ORIGIN_ZONE_V6}"


def parse_origin(record: str) -> dict[str, str] | None:
    """`15169 | 8.8.8.0/24 | US | arin | 1992-12-01`.

    The first field can carry several autonomous systems where a prefix is announced by
    more than one; the first is taken and the rest recorded, because "who announces this"
    having two answers is itself worth seeing.
    """
    parts = [part.strip() for part in record.strip().strip('"').split("|")]
    if len(parts) < 4 or not parts[0]:
        return None
    autonomous_systems = parts[0].split()
    return {
        "asn": autonomous_systems[0],
        "also_announced_by": " ".join(autonomous_systems[1:]),
        "prefix": parts[1],
        "country": parts[2],
        "registry": parts[3],
    }


def parse_asn_name(record: str) -> str | None:
    """`15169 | US | arin | 1992-12-01 | GOOGLE, US` -- the operator is the last field."""
    parts = [part.strip() for part in record.strip().strip('"').split("|")]
    return parts[-1] if len(parts) >= 5 and parts[-1] else None


class NetworkAttributionCollector(Collector):
    descriptor = ATTRIBUTION_DESCRIPTOR

    def __init__(self, broker: CollectionNetworkBroker, clock: Clock | None = None) -> None:
        super().__init__(broker, clock or utc_now)

    def collect(
        self, request: CollectionRequest, addresses: tuple[str, ...] = ()
    ) -> CollectionResult:
        if not addresses:
            # Nothing resolved, so there is nothing to attribute. Not a failure: the DNS
            # collector has already reported why, and repeating it here would put the
            # same problem in front of the reader twice under two different names.
            return self.not_applicable("no_addresses_observed", {"host": request.canonical_host})

        attributed: list[dict[str, Any]] = []
        for address in addresses[:MAX_ADDRESSES]:
            name = reverse_query_name(address)
            if name is None:
                continue
            answer = self._broker.query_dns(request, name, "TXT")
            origin = parse_origin(answer.records[0]) if answer.records else None
            if origin is None:
                attributed.append({"address": address, "resolved": False})
                continue
            attributed.append({"address": address, "resolved": True, **origin})

        if not any(item.get("resolved") for item in attributed):
            # Every lookup failed, which says the attribution service was unreachable
            # rather than that these addresses belong to nobody.
            #
            # `not_applicable` rather than `unavailable`, so a third party being down
            # does not drag the run to `partially_completed` and send the reader looking
            # for a problem with their domain. Nothing here measures the target: this
            # names somebody else's network, and failing to name it is a gap in our
            # knowledge rather than a fault in theirs.
            return self.not_applicable(
                "attribution_unavailable",
                {"host": request.canonical_host, "addresses": attributed},
            )

        names = self._operator_names(
            request, {item["asn"] for item in attributed if item.get("resolved")}
        )
        for item in attributed:
            if item.get("resolved"):
                item["operator"] = names.get(item["asn"])

        operators = sorted({item["operator"] for item in attributed if item.get("operator")})
        return self.ok(
            {
                "host": request.canonical_host,
                "addresses": attributed,
                "operators": operators,
                # More than one announcing network is ordinary for a large site and
                # surprising for a small one, so the count is carried rather than left
                # for the reader to derive from the list.
                "operator_count": len(operators),
                "countries": sorted(
                    {item["country"] for item in attributed if item.get("country")}
                ),
            },
            source=request.canonical_host,
        )

    def _operator_names(
        self, request: CollectionRequest, autonomous_systems: set[str]
    ) -> dict[str, str]:
        names: dict[str, str] = {}
        for asn in sorted(autonomous_systems)[:MAX_ADDRESSES]:
            # Lowercase: DNS is case-insensitive, but the host policy refuses a
            # non-canonical name rather than quietly normalising it, and "AS8708"
            # is not canonical. Written as "AS…" it looked right and returned
            # nothing, so every network came back without an operator name.
            answer = self._broker.query_dns(request, f"as{asn}.{ASN_ZONE}", "TXT")
            if answer.records:
                operator = parse_asn_name(answer.records[0])
                if operator:
                    names[asn] = operator
        return names
