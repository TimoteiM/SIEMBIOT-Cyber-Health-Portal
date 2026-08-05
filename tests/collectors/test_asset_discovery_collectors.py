from __future__ import annotations

import json

from collector_support import (
    FIXTURES,
    PublicResolver,
    build_broker,
    frozen_clock,
    request_for,
    response,
)
from siembiot_worker.adapters.contract import CollectionStatus
from siembiot_worker.collectors.ct_log import (
    CertificateTransparencyCollector,
    FixtureCTSource,
    attribution_confidence,
    extract_candidates,
)
from siembiot_worker.collectors.rdap import RDAPCollector, parse_rdap_domain
from siembiot_worker.network_safety.collection_policy import OperationClass
from siembiot_worker.network_safety.models import TransportResponse

HOST = "strong.example.test"
RDAP_HOST = "rdap.registry.test"
RDAP_URL = f"https://{RDAP_HOST}/domain/{HOST}"

RDAP_DOCUMENT = {
    "objectClassName": "domain",
    "handle": "D123-TEST",
    "ldhName": "STRONG.EXAMPLE.TEST",
    "status": ["client transfer prohibited", "client delete prohibited", "active"],
    "events": [
        {"eventAction": "registration", "eventDate": "2018-03-01T10:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-03-01T10:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2026-02-14T09:30:00Z"},
    ],
    "nameservers": [{"ldhName": "NS1.REGISTRAR.TEST."}, {"ldhName": "ns2.otherprovider.test"}],
    "entities": [
        {
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["fn", {}, "text", "A Real Person"]]],
        }
    ],
}


def rdap_collector(routes: dict[str, TransportResponse]) -> RDAPCollector:
    return RDAPCollector(build_broker(routes=routes), RDAP_HOST, frozen_clock)


# -- RDAP --------------------------------------------------------------------


def test_rdap_registration_facts_are_collected() -> None:
    collector = rdap_collector({RDAP_URL: response(200, {}, json.dumps(RDAP_DOCUMENT).encode())})
    result = collector.collect(request_for(HOST, OperationClass.RDAP_QUERY))
    assert result.status is CollectionStatus.OK
    registration = result.payload["registration"]
    assert registration["ldh_name"] == HOST
    assert registration["expiration_date"] == "2027-03-01T10:00:00Z"
    assert registration["transfer_prohibited"] is True
    assert registration["nameservers"] == ["ns1.registrar.test", "ns2.otherprovider.test"]


def test_rdap_contact_data_is_never_retained() -> None:
    collector = rdap_collector({RDAP_URL: response(200, {}, json.dumps(RDAP_DOCUMENT).encode())})
    result = collector.collect(request_for(HOST, OperationClass.RDAP_QUERY))
    assert "A Real Person" not in json.dumps(result.payload)
    assert "entities" not in result.payload["registration"]


def test_rdap_without_expiration_is_partial() -> None:
    document = {key: value for key, value in RDAP_DOCUMENT.items() if key != "events"}
    collector = rdap_collector({RDAP_URL: response(200, {}, json.dumps(document).encode())})
    result = collector.collect(request_for(HOST, OperationClass.RDAP_QUERY))
    assert result.status is CollectionStatus.PARTIAL
    assert result.partial_reasons == ("expiration_date_absent",)


def test_rdap_404_means_not_applicable_not_a_failure() -> None:
    collector = rdap_collector({RDAP_URL: response(404, {}, b"{}")})
    result = collector.collect(request_for(HOST, OperationClass.RDAP_QUERY))
    assert result.status is CollectionStatus.NOT_APPLICABLE
    assert result.reason_code == "domain_not_in_registry"


def test_rdap_server_error_is_unavailable() -> None:
    collector = rdap_collector({RDAP_URL: response(503, {}, b"busy")})
    result = collector.collect(request_for(HOST, OperationClass.RDAP_QUERY))
    assert result.status is CollectionStatus.UNAVAILABLE
    assert result.reason_code == "http_status_503"


def test_malformed_rdap_json_is_an_error() -> None:
    collector = rdap_collector({RDAP_URL: response(200, {}, b"not json")})
    result = collector.collect(request_for(HOST, OperationClass.RDAP_QUERY))
    assert result.status is CollectionStatus.ERROR
    assert result.reason_code == "invalid_rdap_document"


def test_rdap_array_response_is_rejected() -> None:
    collector = rdap_collector({RDAP_URL: response(200, {}, b"[1,2,3]")})
    result = collector.collect(request_for(HOST, OperationClass.RDAP_QUERY))
    assert result.status is CollectionStatus.ERROR


def test_hostile_rdap_fields_are_bounded_and_type_checked() -> None:
    parsed = parse_rdap_domain(
        {
            "handle": "H" * 5000,
            "ldhName": 12345,
            "status": ["ok", 7, None, "x" * 500],
            "events": "not-a-list",
            "nameservers": [{"ldhName": "N" * 1000}, "not-a-dict", {}],
        }
    )
    assert len(parsed["handle"]) == 64
    assert parsed["ldh_name"] is None
    assert parsed["events"] == {}
    assert all(len(item) <= 64 for item in parsed["statuses"])
    assert all(len(item) <= 255 for item in parsed["nameservers"])


# -- Certificate Transparency ------------------------------------------------


def ct_collector() -> CertificateTransparencyCollector:
    source = FixtureCTSource(FIXTURES / "providers" / "ct")
    return CertificateTransparencyCollector(build_broker(), source, frozen_clock)


def test_ct_candidates_are_deduplicated_and_confidence_labelled() -> None:
    result = ct_collector().collect(request_for(HOST, OperationClass.CT_QUERY))
    assert result.status is CollectionStatus.PARTIAL
    assert "malformed_names_rejected" in result.partial_reasons
    candidates = {item["name"]: item for item in result.payload["candidates"]}
    assert candidates[HOST]["confidence"] == 1.0
    assert candidates[HOST]["attribution_basis"] == "authorized_domain"
    assert candidates[f"www.{HOST}"]["observation_count"] == 2
    assert candidates[f"www.{HOST}"]["confidence"] == 0.9


def test_unrelated_shared_hosting_name_gets_low_confidence() -> None:
    result = ct_collector().collect(request_for(HOST, OperationClass.CT_QUERY))
    candidates = {item["name"]: item for item in result.payload["candidates"]}
    unrelated = candidates["unrelated-tenant.hosting.test"]
    assert unrelated["confidence"] == 0.2
    assert unrelated["attribution_basis"] == "unrelated_name"


def test_wildcard_entry_is_recorded_as_a_wildcard_observation() -> None:
    result = ct_collector().collect(request_for(HOST, OperationClass.CT_QUERY))
    candidates = {item["name"]: item for item in result.payload["candidates"]}
    assert candidates[HOST]["wildcard_observed"] is True


def test_first_and_last_seen_span_all_observations() -> None:
    result = ct_collector().collect(request_for(HOST, OperationClass.CT_QUERY))
    candidates = {item["name"]: item for item in result.payload["candidates"]}
    www = candidates[f"www.{HOST}"]
    assert www["first_seen"] == "2026-01-10T00:00:00Z"
    assert www["last_seen"] == "2026-07-01T00:00:00Z"


def test_domain_without_ct_entries_is_not_applicable() -> None:
    result = ct_collector().collect(request_for("weak.example.test", OperationClass.CT_QUERY))
    assert result.status is CollectionStatus.NOT_APPLICABLE
    assert result.reason_code == "no_ct_entries"


def test_ct_collection_makes_no_network_connection() -> None:
    resolver = PublicResolver()
    broker = build_broker(resolver=resolver)
    source = FixtureCTSource(FIXTURES / "providers" / "ct")
    CertificateTransparencyCollector(broker, source, frozen_clock).collect(
        request_for(HOST, OperationClass.CT_QUERY)
    )
    assert resolver.queries == []


def test_attribution_confidence_never_claims_ownership_of_lookalikes() -> None:
    confidence, basis = attribution_confidence("strong-example.test", HOST)
    assert confidence == 0.2
    assert basis == "unrelated_name"


def test_extract_candidates_tolerates_non_dict_entries() -> None:
    candidates, rejected = extract_candidates(
        [{"dns_names": "not-a-list"}, "junk", {"dns_names": [None, 5, HOST]}],  # type: ignore[list-item]
        HOST,
    )
    assert [item["name"] for item in candidates] == [HOST]
    assert rejected == []
