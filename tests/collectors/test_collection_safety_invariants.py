"""Cross-collector invariants.

These hold for every collector regardless of what it parses, so they are asserted
once here rather than repeated in each collector's own test module.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from collector_support import ZONES, ZoneDNSTransport, build_broker, frozen_clock, request_for
from siembiot_worker.adapters.contract import CollectionStatus
from siembiot_worker.collectors.dns_records import DNSResilienceCollector
from siembiot_worker.collectors.email_records import EmailTrustCollector
from siembiot_worker.network_safety.collection_policy import OperationClass
from siembiot_worker.network_safety.dns_client import ALLOWED_RECORD_TYPES

ROOT = Path(__file__).resolve().parents[2]
COLLECTORS = ROOT / "services" / "worker" / "src" / "siembiot_worker" / "collectors"


def test_no_collector_constructs_its_own_network_client() -> None:
    forbidden = {"SocketConnector", "SocketTLSConnector", "BoundedHTTPTransport", "SystemResolver"}
    violations: list[str] = []
    for path in COLLECTORS.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in forbidden:
                    violations.append(f"{path.name}:{node.lineno}")
    assert violations == []


def test_no_collector_declares_its_own_dnspython_transport() -> None:
    for path in COLLECTORS.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "DnspythonTransport" not in source, path.name


def test_collectors_only_ever_ask_for_allowlisted_record_types() -> None:
    transport = ZoneDNSTransport(ZONES)
    broker = build_broker(dns_transport=transport)
    DNSResilienceCollector(broker, frozen_clock).collect(request_for("strong.example.test"))
    EmailTrustCollector(broker, frozen_clock).collect(
        request_for("strong.example.test"), declared_dkim_selectors=("selector1",)
    )
    assert transport.calls
    assert all(record_type in ALLOWED_RECORD_TYPES for _, record_type in transport.calls)


def test_dkim_lookups_are_limited_to_declared_selectors() -> None:
    transport = ZoneDNSTransport(ZONES)
    broker = build_broker(dns_transport=transport)
    EmailTrustCollector(broker, frozen_clock).collect(
        request_for("strong.example.test"), declared_dkim_selectors=("selector1",)
    )
    dkim_lookups = [name for name, _ in transport.calls if "_domainkey" in name]
    assert dkim_lookups == ["selector1._domainkey.strong.example.test"]


def test_declared_selector_list_is_capped() -> None:
    transport = ZoneDNSTransport(ZONES)
    broker = build_broker(dns_transport=transport)
    result = EmailTrustCollector(broker, frozen_clock).collect(
        request_for("strong.example.test"),
        declared_dkim_selectors=tuple(f"selector{index}" for index in range(50)),
    )
    dkim_lookups = [name for name, _ in transport.calls if "_domainkey" in name]
    assert len(dkim_lookups) == 10
    assert result.payload["dkim"]["truncated"] is True


@pytest.mark.parametrize(
    "host", ["strong.example.test", "weak.example.test", "hostile.example.test"]
)
def test_collection_is_deterministic_for_identical_fixture_input(host: str) -> None:
    first = DNSResilienceCollector(build_broker(), frozen_clock).collect(request_for(host))
    second = DNSResilienceCollector(build_broker(), frozen_clock).collect(request_for(host))
    assert first.status is second.status
    assert first.payload == second.payload


def test_unusable_results_never_carry_evidence_that_could_be_scored() -> None:
    result = DNSResilienceCollector(build_broker(), frozen_clock).collect(
        request_for("unknown.example.test")
    )
    assert result.status is CollectionStatus.UNAVAILABLE
    assert result.usable is False
    for lookup in result.payload.values():
        if isinstance(lookup, dict) and "records" in lookup:
            assert lookup["records"] == []


def test_every_collector_result_carries_provenance() -> None:
    result = DNSResilienceCollector(build_broker(), frozen_clock).collect(
        request_for("strong.example.test", OperationClass.DNS_QUERY)
    )
    assert result.provenance.adapter_id == "dns_resilience"
    assert result.provenance.adapter_version == "1.0.0"
    assert result.provenance.collected_at.tzinfo is not None
    assert result.provenance.from_cache is False
