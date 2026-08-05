"""Domain and DNS resilience collection (pillar A).

Observations only. Nameserver diversity, DNSSEC state, and CAA posture are reported
as measured facts with their inconclusive cases named, never inferred from silence.
"""

from __future__ import annotations

import re
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
from siembiot_worker.collectors.base import Collector, inconclusive_reasons, record_set_payload
from siembiot_worker.network_safety.collection_broker import CollectionRequest
from siembiot_worker.network_safety.dns_client import DNSRecordSet

WILDCARD_PROBE_LABEL = "siembiot-wildcard-probe"
_CAA_PATTERN = re.compile(r'^(?P<flags>\d+)\s+(?P<tag>[a-z0-9]+)\s+"(?P<value>[^"]*)"$')

DNS_DESCRIPTOR = AdapterDescriptor(
    adapter_id="dns_resilience",
    version="1.0.0",
    group=AdapterGroup.DNS_RDAP,
    title="Domain and DNS resilience collector",
    capabilities=frozenset(
        {
            "dns.delegation",
            "dns.dnssec",
            "dns.caa",
            "dns.addresses",
            "dns.wildcard",
        }
    ),
    data_classification=DataClassification.PUBLIC_OBSERVATION,
    terms_notes="Public DNS data obtained through the configured recursive resolver.",
    terms_url=None,
    required_secrets=frozenset(),
    timeout_seconds=5.0,
    rate_limit=RateLimitPolicy(20, 1.0, burst=10),
    cost_unit=CostUnit.NONE,
    cache=CachePolicy(300),
    supports_fixtures=True,
)


def parse_caa(records: tuple[str, ...]) -> dict[str, Any]:
    """Split CAA records into recognized tags and the ones we refuse to guess at."""
    issue: list[str] = []
    issuewild: list[str] = []
    iodef: list[str] = []
    unparsed: list[str] = []
    for record in records:
        match = _CAA_PATTERN.match(record.strip())
        if match is None:
            unparsed.append(record)
            continue
        tag = match.group("tag").lower()
        value = match.group("value")
        if tag == "issue":
            issue.append(value)
        elif tag == "issuewild":
            issuewild.append(value)
        elif tag == "iodef":
            iodef.append(value)
        else:
            unparsed.append(record)
    return {
        "issue": issue,
        "issuewild": issuewild,
        "iodef": iodef,
        "unparsed": unparsed,
        "present": bool(issue or issuewild or iodef),
    }


def nameserver_diversity(nameservers: tuple[str, ...]) -> dict[str, Any]:
    """Describe delegation breadth without asserting a single point of failure."""
    normalized = sorted({item.rstrip(".").lower() for item in nameservers if item.strip()})
    parents = sorted(
        {".".join(item.split(".")[-2:]) for item in normalized if item.count(".") >= 1}
    )
    return {
        "nameservers": normalized,
        "nameserver_count": len(normalized),
        "distinct_parent_domains": parents,
        "distinct_parent_count": len(parents),
        "single_parent_domain": len(parents) == 1 and len(normalized) > 0,
    }


class DNSResilienceCollector(Collector):
    descriptor = DNS_DESCRIPTOR

    def collect(self, request: CollectionRequest) -> CollectionResult:
        host = request.canonical_host
        answers: dict[str, DNSRecordSet] = {
            "soa": self._broker.query_dns(request, host, "SOA"),
            "ns": self._broker.query_dns(request, host, "NS"),
            "a": self._broker.query_dns(request, host, "A"),
            "aaaa": self._broker.query_dns(request, host, "AAAA"),
            "caa": self._broker.query_dns(request, host, "CAA"),
            "dnskey": self._broker.query_dns(request, host, "DNSKEY", want_dnssec=True),
            "ds": self._broker.query_dns(request, host, "DS", want_dnssec=True),
        }
        wildcard = self._broker.query_dns(request, f"{WILDCARD_PROBE_LABEL}.{host}", "A")
        answers["wildcard_probe"] = wildcard

        if not answers["soa"].is_conclusive and not answers["ns"].is_conclusive:
            return self.unavailable(
                "dns_unreachable",
                {key: record_set_payload(value) for key, value in answers.items()},
            )

        payload: dict[str, Any] = {
            "host": host,
            "lookups": {key: record_set_payload(value) for key, value in answers.items()},
            "delegation": nameserver_diversity(answers["ns"].records),
            "caa": parse_caa(answers["caa"].records) if answers["caa"].is_answered else None,
            "dnssec": {
                "dnskey_present": answers["dnskey"].is_answered,
                "ds_present": answers["ds"].is_answered,
                "resolver_authenticated": answers["soa"].authenticated,
                "state": self._dnssec_state(answers),
            },
            "addresses": {
                "ipv4": list(answers["a"].records),
                "ipv6": list(answers["aaaa"].records),
                "ipv6_present": answers["aaaa"].is_answered,
            },
            "wildcard": {
                "probe_name": f"{WILDCARD_PROBE_LABEL}.{host}",
                "resolves": wildcard.is_answered,
                "conclusive": wildcard.is_conclusive,
            },
        }
        reasons = inconclusive_reasons(answers)
        if reasons:
            return self.partial(payload, reasons, source=host)
        return self.ok(payload, source=host)

    @staticmethod
    def _dnssec_state(answers: dict[str, DNSRecordSet]) -> str:
        dnskey, delegation_signer = answers["dnskey"], answers["ds"]
        if not dnskey.is_conclusive or not delegation_signer.is_conclusive:
            return "unknown"
        if delegation_signer.is_answered and dnskey.is_answered:
            return "signed_and_delegated"
        if dnskey.is_answered:
            return "signed_without_delegation"
        return "unsigned"
