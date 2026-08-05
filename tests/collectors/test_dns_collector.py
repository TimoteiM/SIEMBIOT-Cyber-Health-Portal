from __future__ import annotations

from collector_support import build_broker, frozen_clock, request_for
from siembiot_worker.adapters.contract import CollectionResult, CollectionStatus
from siembiot_worker.collectors.dns_records import (
    DNSResilienceCollector,
    nameserver_diversity,
    parse_caa,
)


def collect(host: str) -> CollectionResult:
    collector = DNSResilienceCollector(build_broker(), frozen_clock)
    return collector.collect(request_for(host))


def test_well_configured_zone_is_collected_completely() -> None:
    result = collect("strong.example.test")
    assert result.status is CollectionStatus.OK
    payload = result.payload
    assert payload["dnssec"]["state"] == "signed_and_delegated"
    assert payload["delegation"]["distinct_parent_count"] == 2
    assert payload["delegation"]["single_parent_domain"] is False
    assert payload["caa"]["issue"] == ["letsencrypt.org"]
    assert payload["addresses"]["ipv6_present"] is True
    assert payload["wildcard"]["resolves"] is False


def test_weak_zone_records_absence_without_inventing_failure() -> None:
    result = collect("weak.example.test")
    assert result.status is CollectionStatus.OK
    payload = result.payload
    assert payload["dnssec"]["state"] == "unsigned"
    assert payload["caa"] is None
    assert payload["delegation"]["single_parent_domain"] is True
    assert payload["addresses"]["ipv6_present"] is False
    assert payload["wildcard"]["resolves"] is True


def test_unreachable_dns_is_unavailable_not_a_failing_score() -> None:
    result = collect("unknown.example.test")
    assert result.status is CollectionStatus.UNAVAILABLE
    assert result.reason_code == "dns_unreachable"
    assert result.usable is False


def test_partial_lookup_failure_names_the_inconclusive_lookup() -> None:
    result = collect("hostile.example.test")
    assert result.status is CollectionStatus.PARTIAL
    assert "dnskey_error" in result.partial_reasons
    assert result.payload["dnssec"]["state"] == "unknown"


def test_malformed_caa_records_are_isolated_not_silently_dropped() -> None:
    result = collect("hostile.example.test")
    caa = result.payload["caa"]
    assert caa["issue"] == ["ca.test"]
    assert caa["unparsed"] == ["not a caa record at all"]


def test_every_lookup_reports_its_own_conclusiveness() -> None:
    result = collect("hostile.example.test")
    lookups = result.payload["lookups"]
    assert lookups["dnskey"]["conclusive"] is False
    assert lookups["ds"]["conclusive"] is True
    assert lookups["ds"]["records"] == []


# -- pure parsers ------------------------------------------------------------


def test_caa_parser_recognizes_all_defined_tags() -> None:
    parsed = parse_caa(
        (
            '0 issue "ca.test"',
            '0 issuewild ";"',
            '0 iodef "mailto:a@b.test"',
            '128 unknowntag "x"',
        )
    )
    assert parsed["present"] is True
    assert parsed["issuewild"] == [";"]
    assert parsed["unparsed"] == ['128 unknowntag "x"']


def test_caa_parser_reports_absence_explicitly() -> None:
    assert parse_caa(())["present"] is False


def test_nameserver_diversity_deduplicates_and_normalizes() -> None:
    diversity = nameserver_diversity(("NS1.Provider.test.", "ns1.provider.test", "ns2.other.test"))
    assert diversity["nameservers"] == ["ns1.provider.test", "ns2.other.test"]
    assert diversity["distinct_parent_count"] == 2


def test_nameserver_diversity_of_empty_delegation_claims_nothing() -> None:
    diversity = nameserver_diversity(())
    assert diversity["nameserver_count"] == 0
    assert diversity["single_parent_domain"] is False
