from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from siembiot_worker.collection.broker import FixtureBrokerResult, FixtureInternetBroker
from siembiot_worker.collection.fixtures import FixtureScenarioPack
from siembiot_worker.collection.models import ExecutionMode, ObservationOutcome
from siembiot_worker.collectors.common import FixtureCollectorContext
from siembiot_worker.collectors.dns.collector import DNSCollector

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "fake_internet" / "v1"


class StaticDNSBroker:
    def __init__(self, records: object) -> None:
        self.records = records

    def resolve_dns(
        self,
        scenario_id: str,
        host: str,
        record_type: str,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> FixtureBrokerResult:
        del scenario_id, host, record_type, cancelled
        return FixtureBrokerResult(
            True,
            "fixture",
            datetime(2026, 8, 3, 12, tzinfo=UTC),
            {"records": self.records},
        )


def _components() -> tuple[FixtureInternetBroker, FixtureCollectorContext]:
    pack = FixtureScenarioPack.load(FIXTURE_ROOT)
    scenario = pack.scenario("healthy")
    return FixtureInternetBroker(pack), FixtureCollectorContext(
        scope_reference="scope-example-test",
        scenario_id=scenario.id,
        scenario_sha256=scenario.digest,
    )


def test_dns_collector_emits_fixture_provenance_for_declared_checks() -> None:
    broker, context = _components()
    observations = DNSCollector(broker).collect(context, "example.test")
    by_type = {item.payload["record_type"]: item for item in observations}
    assert set(by_type) == {"NS", "SOA", "DS", "DNSKEY", "CAA", "A", "WILDCARD_A"}
    assert all(item.execution_mode is ExecutionMode.FIXTURE for item in observations)
    assert all(item.scenario is not None for item in observations)
    assert all(item.collector.version == "1.0.0" for item in observations)
    assert all(not item.publishable and not item.real_world for item in observations)
    assert by_type["DS"].outcome is ObservationOutcome.PASS


def test_dns_collection_is_byte_deterministic() -> None:
    broker, context = _components()
    first = DNSCollector(broker).collect(context, "example.test")
    second = DNSCollector(broker).collect(context, "example.test")
    assert [item.model_dump_json() for item in first] == [item.model_dump_json() for item in second]


def test_missing_dns_records_are_unknown_not_real_findings() -> None:
    broker, context = _components()
    observations = DNSCollector(broker).collect(context, "missing.example.test")
    assert all(item.outcome is ObservationOutcome.UNKNOWN for item in observations)
    assert all(item.payload["reason_code"] == "fixture_unavailable" for item in observations)


@pytest.mark.parametrize("records", [{"hostile": "mapping"}, ["x" * 2_049]])
def test_malformed_and_oversized_dns_fixture_data_fails_safely(records: object) -> None:
    _, context = _components()
    observations = DNSCollector(StaticDNSBroker(records)).collect(context, "example.test")
    assert all(item.outcome is ObservationOutcome.ERROR for item in observations)
    assert all(item.payload["records"] == [] for item in observations)
    assert all(item.payload["reason_code"] == "malformed_fixture_data" for item in observations)
