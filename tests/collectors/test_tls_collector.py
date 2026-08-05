from __future__ import annotations

import datetime as dt
import ssl

import pytest
from certificates import REFERENCE_NOW, build_certificate
from collector_support import build_broker, frozen_clock, request_for
from siembiot_worker.adapters.contract import CollectionResult, CollectionStatus
from siembiot_worker.collectors.tls_certificate import (
    WEAK_SIGNATURE_ALGORITHMS,
    TLSCertificateCollector,
    describe_certificate,
    hostname_covered,
)
from siembiot_worker.network_safety.collection_policy import OperationClass
from siembiot_worker.network_safety.tls_client import TLSBudget, TLSInspector, TLSObservation

HOST = "strong.example.test"
HEALTHY_LEAF = build_certificate(common_name=HOST, dns_names=(HOST, f"www.{HOST}"))


class ScriptedConnector:
    """Returns a scripted observation per (verify, pinned version) combination."""

    def __init__(
        self,
        verified: TLSObservation,
        unverified: TLSObservation | None = None,
        protocol_support: frozenset[str] = frozenset({"TLSv1.2", "TLSv1.3"}),
    ) -> None:
        self.verified = verified
        self.unverified = unverified or verified
        self.protocol_support = protocol_support
        self.handshakes: list[tuple[bool, str | None]] = []

    def handshake(
        self,
        address: str,
        port: int,
        server_hostname: str,
        *,
        verify: bool,
        budget: TLSBudget,
        minimum_version: ssl.TLSVersion | None = None,
        maximum_version: ssl.TLSVersion | None = None,
    ) -> TLSObservation:
        pinned = None if maximum_version is None else maximum_version.name
        self.handshakes.append((verify, pinned))
        if maximum_version is not None:
            version = {
                "TLSv1": "TLSv1",
                "TLSv1_1": "TLSv1.1",
                "TLSv1_2": "TLSv1.2",
                "TLSv1_3": "TLSv1.3",
            }[maximum_version.name]
            if version in self.protocol_support:
                return TLSObservation("handshake_ok", version, "TLS_AES_256_GCM_SHA384")
            return TLSObservation("handshake_failed", verification_error="unsupported_protocol")
        return self.verified if verify else self.unverified


def collect(connector: ScriptedConnector, *, probe: bool = True) -> CollectionResult:
    inspector = TLSInspector(connector)
    broker = build_broker(tls_inspector=inspector)
    collector = TLSCertificateCollector(broker, frozen_clock)
    return collector.collect(
        request_for(HOST, OperationClass.TLS_INSPECTION), probe_protocols=probe
    )


def test_trusted_certificate_is_collected_with_full_detail() -> None:
    connector = ScriptedConnector(
        TLSObservation(
            "handshake_ok",
            "TLSv1.3",
            "TLS_AES_256_GCM_SHA384",
            trusted=True,
            hostname_verified=True,
            certificate_chain=(HEALTHY_LEAF,),
        )
    )
    result = collect(connector)
    assert result.status is CollectionStatus.OK
    leaf = result.payload["leaf"]
    assert leaf["hostname_covered"] is True
    assert leaf["expired"] is False
    assert leaf["public_key"]["type"] == "ec"
    assert result.payload["handshake"]["trusted"] is True
    assert result.payload["protocols"]["supported"] == ["TLSv1.2", "TLSv1.3"]
    assert result.payload["protocols"]["deprecated_supported"] == []


def test_untrusted_certificate_is_still_described() -> None:
    connector = ScriptedConnector(
        TLSObservation("verification_failed", verification_error="self signed certificate"),
        TLSObservation("handshake_ok", "TLSv1.2", "ECDHE", certificate_chain=(HEALTHY_LEAF,)),
    )
    result = collect(connector)
    assert result.status is CollectionStatus.OK
    assert result.payload["handshake"]["status"] == "verification_failed"
    assert result.payload["handshake"]["trusted"] is False
    assert result.payload["leaf"]["subject"].endswith(HOST)


def test_deprecated_protocol_support_is_reported() -> None:
    connector = ScriptedConnector(
        TLSObservation(
            "handshake_ok",
            "TLSv1.2",
            "ECDHE",
            trusted=True,
            hostname_verified=True,
            certificate_chain=(HEALTHY_LEAF,),
        ),
        protocol_support=frozenset({"TLSv1", "TLSv1.1", "TLSv1.2"}),
    )
    result = collect(connector)
    assert result.payload["protocols"]["deprecated_supported"] == ["TLSv1", "TLSv1.1"]


def test_unreachable_host_is_unavailable_not_a_tls_failure() -> None:
    connector = ScriptedConnector(TLSObservation("timeout"))
    result = collect(connector)
    assert result.status is CollectionStatus.UNAVAILABLE
    assert result.reason_code == "timeout"
    assert result.usable is False


def test_missing_tls_inspector_is_an_explicit_error() -> None:
    collector = TLSCertificateCollector(build_broker(), frozen_clock)
    result = collector.collect(request_for(HOST, OperationClass.TLS_INSPECTION))
    assert result.status is CollectionStatus.ERROR
    assert result.reason_code == "tls_inspector_unavailable"


def test_unparsable_certificate_is_partial_not_silently_dropped() -> None:
    connector = ScriptedConnector(
        TLSObservation(
            "handshake_ok",
            "TLSv1.3",
            "TLS_AES_256_GCM_SHA384",
            trusted=True,
            hostname_verified=True,
            certificate_chain=(b"not-a-certificate",),
        )
    )
    result = collect(connector)
    assert result.status is CollectionStatus.PARTIAL
    assert "certificate_parse_failed" in result.partial_reasons
    assert "no_certificate_observed" in result.partial_reasons


def test_protocol_probing_can_be_skipped() -> None:
    connector = ScriptedConnector(
        TLSObservation(
            "handshake_ok",
            "TLSv1.3",
            "x",
            trusted=True,
            hostname_verified=True,
            certificate_chain=(HEALTHY_LEAF,),
        )
    )
    result = collect(connector, probe=False)
    assert result.payload["protocols"]["probed"] == []
    assert connector.handshakes == [(True, None)]


# -- pure description --------------------------------------------------------


def test_expired_certificate_is_described_as_expired() -> None:
    expired = build_certificate(
        common_name=HOST,
        dns_names=(HOST,),
        not_before=REFERENCE_NOW - dt.timedelta(days=400),
        not_after=REFERENCE_NOW - dt.timedelta(days=10),
    )
    described = describe_certificate(expired, HOST, REFERENCE_NOW)
    assert described["expired"] is True
    assert described["days_until_expiry"] < 0


def test_undersized_rsa_key_is_observed_not_judged() -> None:
    weak = build_certificate(common_name=HOST, dns_names=(HOST,), rsa_bits=1024)
    described = describe_certificate(weak, HOST, REFERENCE_NOW)
    assert described["public_key"]["type"] == "rsa"
    assert described["public_key"]["weak"] is True
    assert described["weak_signature"] is False


def test_adequate_rsa_key_is_not_marked_weak() -> None:
    strong = build_certificate(common_name=HOST, dns_names=(HOST,), rsa_bits=2048)
    assert describe_certificate(strong, HOST, REFERENCE_NOW)["public_key"]["weak"] is False


def test_deprecated_signature_hashes_are_classified_as_weak() -> None:
    # The backend refuses to *produce* a SHA-1 signature, so this classification is
    # asserted directly rather than through a generated fixture.
    assert {"sha1", "md5"} <= WEAK_SIGNATURE_ALGORITHMS
    assert "sha256" not in WEAK_SIGNATURE_ALGORITHMS


def test_hostname_outside_san_list_is_not_covered() -> None:
    certificate = build_certificate(common_name="other.test", dns_names=("other.test",))
    assert describe_certificate(certificate, HOST, REFERENCE_NOW)["hostname_covered"] is False


def test_self_signed_certificate_is_flagged() -> None:
    described = describe_certificate(HEALTHY_LEAF, HOST, REFERENCE_NOW)
    assert described["self_signed"] is True


@pytest.mark.parametrize(
    ("hostname", "names", "expected"),
    [
        ("a.example.test", ["*.example.test"], True),
        ("example.test", ["*.example.test"], False),
        ("deep.a.example.test", ["*.example.test"], False),
        ("A.Example.Test", ["a.example.test"], True),
        ("a.example.test", [], False),
    ],
)
def test_wildcard_matching_covers_exactly_one_label(
    hostname: str, names: list[str], expected: bool
) -> None:
    assert hostname_covered(hostname, names) is expected
