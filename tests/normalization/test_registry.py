from __future__ import annotations

from datetime import UTC, datetime

import pytest
from siembiot_worker.collection.models import (
    CollectionObservation,
    ObservationOutcome,
    build_fixture_observation,
)
from siembiot_worker.normalization.registry import NormalizationError, normalize_observation


def source(collector: str, payload: dict[str, object]) -> CollectionObservation:
    return build_fixture_observation(
        scope_reference="018f5f80-8a4b-7c1b-b55e-ea65c9126203",
        collector_id=collector,
        collector_version="1.0.0",
        adapter_id=f"fixture-{collector}",
        adapter_version="1.0.0",
        collected_at=datetime(2026, 8, 3, 12, tzinfo=UTC),
        scenario_id="healthy",
        scenario_sha256="b" * 64,
        outcome=ObservationOutcome.PASS,
        payload=payload,
    )


@pytest.mark.parametrize(
    ("collector", "payload", "expected_type"),
    [
        ("dns", {"record_type": "DNSSEC", "secure": True}, "dns.dnssec"),
        ("email-dns", {"check": "DMARC", "policy": "reject"}, "email.dmarc"),
        (
            "http",
            {"status": 200, "headers": {"strict-transport-security": "max-age=1"}},
            "http.security_headers",
        ),
        ("tls", {"protocol": "TLSv1.3", "hostname_valid": True}, "tls.handshake"),
        ("rdap", {"status": ["active"]}, "rdap.registration"),
        ("ct", {"asserted_names": ["portal.example.test"]}, "ct.names"),
    ],
)
def test_allowlisted_family_normalizers_are_deterministic(
    collector: str, payload: dict[str, object], expected_type: str
) -> None:
    item = source(collector, payload)
    first = normalize_observation(item, organization_id="org-a", asset_id="asset-a")
    second = normalize_observation(item, organization_id="org-a", asset_id="asset-a")
    assert first == second
    assert first.observation_type == expected_type
    assert first.mode.value == "fixture"
    assert not first.publishable and not first.real_world
    assert first.provenance.scenario_sha256 == "b" * 64


@pytest.mark.parametrize(
    "payload",
    [
        {"api_token": "must-not-persist"},
        {"value": "x" * 1025},
        {"values": list(range(129))},
        {"nested": {"a": {"b": {"c": {"d": {"e": 1}}}}}},
    ],
)
def test_untrusted_or_sensitive_payload_is_rejected(payload: dict[str, object]) -> None:
    with pytest.raises(NormalizationError):
        normalize_observation(source("dns", payload), organization_id="org-a", asset_id="asset-a")


def test_unknown_collector_version_is_rejected() -> None:
    item = build_fixture_observation(
        scope_reference="scope",
        collector_id="dns",
        collector_version="2.0.0",
        adapter_id="fixture-dns",
        adapter_version="1.0.0",
        collected_at=datetime(2026, 8, 3, 12, tzinfo=UTC),
        scenario_id="healthy",
        scenario_sha256="b" * 64,
        outcome=ObservationOutcome.PASS,
        payload={"record_type": "A"},
    )
    with pytest.raises(NormalizationError, match="normalizer_not_registered"):
        normalize_observation(item, organization_id="org-a", asset_id="asset-a")
