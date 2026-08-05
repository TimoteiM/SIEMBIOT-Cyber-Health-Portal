from __future__ import annotations

from collector_support import build_broker, frozen_clock, request_for, response
from siembiot_worker.adapters.contract import CollectionResult, CollectionStatus
from siembiot_worker.collectors.email_records import (
    EmailTrustCollector,
    parse_dmarc,
    parse_mta_sts_policy,
    parse_spf,
    select_policy_record,
)

STRONG_POLICY = b"version: STSv1\nmode: enforce\nmx: mail.strong.example.test\nmax_age: 604800\n"


def collect(host: str, selectors: tuple[str, ...] = ()) -> CollectionResult:
    routes = {
        "https://mta-sts.strong.example.test/.well-known/mta-sts.txt": response(
            200, {"content-type": "text/plain"}, STRONG_POLICY
        ),
        "https://mta-sts.hostile.example.test/.well-known/mta-sts.txt": response(
            200, {"content-type": "text/plain"}, b"garbage\nmode: sideways\n"
        ),
    }
    collector = EmailTrustCollector(build_broker(routes=routes), frozen_clock)
    return collector.collect(request_for(host), declared_dkim_selectors=selectors)


def test_strong_domain_collects_every_email_control() -> None:
    result = collect("strong.example.test", ("selector1",))
    assert result.status is CollectionStatus.OK
    payload = result.payload
    assert payload["spf"]["parsed"]["all_qualifier"] == "-all"
    assert payload["dmarc"]["parsed"]["policy"] == "reject"
    assert payload["dmarc"]["parsed"]["subdomain_policy"] == "reject"
    assert payload["mta_sts"]["policy"]["mode"] == "enforce"
    assert payload["tls_rpt"]["valid"] is True
    assert payload["dane"]["hosts"][0]["present"] is True
    assert payload["dkim"]["selectors"][0]["present"] is True


def test_dkim_selectors_are_never_guessed() -> None:
    result = collect("strong.example.test")
    assert result.payload["dkim"]["selector_source"] == "none_declared"
    assert result.payload["dkim"]["selectors"] == []


def test_bimi_is_collected_as_informational_only() -> None:
    result = collect("strong.example.test", ("selector1",))
    assert result.payload["bimi"]["informational_only"] is True


def test_weak_domain_exposes_permissive_spf_and_monitoring_only_dmarc() -> None:
    result = collect("weak.example.test")
    payload = result.payload
    spf = payload["spf"]["parsed"]
    assert spf["dns_lookup_count"] > 10
    assert spf["exceeds_lookup_limit"] is True
    assert spf["has_ptr_mechanism"] is True
    assert spf["soft_all"] is True
    dmarc = payload["dmarc"]["parsed"]
    assert dmarc["policy"] == "none"
    assert dmarc["percentage"] == 50
    assert dmarc["external_report_domains"] == ["thirdparty.test"]
    assert dmarc["external_authorization_required"] is True


def test_absent_policies_are_recorded_as_absent_not_unknown() -> None:
    result = collect("weak.example.test")
    assert result.payload["mta_sts"]["dns_record_present"] is False
    assert result.payload["mta_sts"]["conclusive"] is True
    assert result.payload["tls_rpt"]["present"] is False


def test_unreachable_dns_makes_email_collection_unavailable() -> None:
    result = collect("unknown.example.test")
    assert result.status is CollectionStatus.UNAVAILABLE
    assert result.usable is False


def test_hostile_records_are_parsed_defensively() -> None:
    result = collect("hostile.example.test")
    payload = result.payload
    assert payload["spf"]["multiple_records"] is True
    assert payload["spf"]["parsed"] is None
    assert payload["dmarc"]["present"] is False
    assert payload["mta_sts"]["policy"]["valid"] is False
    assert payload["tls_rpt"]["valid"] is False


def test_malformed_mx_preferences_do_not_crash_dane_collection() -> None:
    result = collect("hostile.example.test")
    exchanges = [host["mx_host"] for host in result.payload["dane"]["hosts"]]
    assert exchanges == ["mail.hostile.example.test"]


def test_dane_is_not_applicable_without_mx() -> None:
    result = collect("unknown.example.test")
    assert result.payload["dane"]["applicable"] is False


# -- pure parsers ------------------------------------------------------------


def test_spf_counts_only_lookup_mechanisms() -> None:
    parsed = parse_spf("v=spf1 ip4:192.0.2.0/24 include:a.test a mx -all")
    assert parsed["dns_lookup_count"] == 3
    assert parsed["exceeds_lookup_limit"] is False
    assert parsed["permissive_all"] is False
    assert parsed["valid"] is True


def test_spf_flags_plus_all_as_permissive() -> None:
    assert parse_spf("v=spf1 +all")["permissive_all"] is True
    assert parse_spf("v=spf1 all")["permissive_all"] is True


def test_spf_without_version_is_invalid() -> None:
    parsed = parse_spf("include:a.test -all")
    assert parsed["valid"] is False
    assert "missing_version" in parsed["syntax_errors"]


def test_spf_include_without_domain_is_a_syntax_error() -> None:
    assert parse_spf("v=spf1 include -all")["valid"] is False


def test_dmarc_duplicate_tag_is_an_error_not_a_last_one_wins() -> None:
    parsed = parse_dmarc("v=DMARC1; p=none; p=reject")
    assert parsed["policy"] == "none"
    assert "duplicate_tag:p" in parsed["syntax_errors"]


def test_dmarc_defaults_alignment_to_relaxed() -> None:
    parsed = parse_dmarc("v=DMARC1; p=quarantine")
    assert parsed["adkim"] == "r"
    assert parsed["aspf"] == "r"
    assert parsed["percentage"] is None


def test_dmarc_external_reporting_domain_is_extracted() -> None:
    parsed = parse_dmarc("v=DMARC1; p=reject; rua=mailto:x@reports.vendor.test!10m")
    assert parsed["external_report_domains"] == ["reports.vendor.test"]


def test_mta_sts_policy_rejects_unknown_mode() -> None:
    parsed = parse_mta_sts_policy("version: STSv1\nmode: sideways\nmax_age: 1\n")
    assert parsed["valid"] is False
    assert "invalid_mode" in parsed["syntax_errors"]


def test_mta_sts_policy_collects_every_mx_pattern() -> None:
    parsed = parse_mta_sts_policy(
        "version: STSv1\nmode: testing\nmx: a.test\nmx: *.b.test\nmax_age: 86400\n"
    )
    assert parsed["mx_patterns"] == ["a.test", "*.b.test"]
    assert parsed["valid"] is True


def test_multiple_matching_policy_records_are_refused() -> None:
    record, count = select_policy_record(("v=spf1 -all", "v=spf1 +all"), "v=spf1")
    assert record is None
    assert count == 2
