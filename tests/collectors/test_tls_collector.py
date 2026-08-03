from __future__ import annotations

from pathlib import Path

from siembiot_worker.collection.broker import FixtureInternetBroker
from siembiot_worker.collection.fixtures import FixtureScenarioPack
from siembiot_worker.collection.models import ObservationOutcome
from siembiot_worker.collectors.common import FixtureCollectorContext
from siembiot_worker.collectors.tls.collector import TLSCollector

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "fake_internet" / "v1"


def _components(scenario_id: str) -> tuple[FixtureInternetBroker, FixtureCollectorContext]:
    pack = FixtureScenarioPack.load(FIXTURE_ROOT)
    scenario = pack.scenario(scenario_id)
    return FixtureInternetBroker(pack), FixtureCollectorContext(
        scope_reference="scope-portal-example-test",
        scenario_id=scenario.id,
        scenario_sha256=scenario.digest,
    )


def test_tls_collector_normalizes_fixture_handshake_metadata() -> None:
    broker, context = _components("healthy")
    observation = TLSCollector(broker).collect(context, "portal.example.test")
    assert observation.outcome is ObservationOutcome.PASS
    assert observation.payload == {
        "fixture_only": True,
        "host": "portal.example.test",
        "reason_code": "fixture",
        "version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "hostname_valid": True,
        "chain_valid": True,
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z",
    }


def test_tls_private_destination_is_ssrf_denied_without_payload() -> None:
    broker, context = _components("adversarial")
    observation = TLSCollector(broker).collect(context, "private.example.test")
    assert observation.outcome is ObservationOutcome.ERROR
    assert observation.payload["reason_code"] == "forbidden_address"
    assert "cipher" not in observation.payload


def test_malformed_tls_fixture_is_rejected() -> None:
    broker, context = _components("adversarial")
    observation = TLSCollector(broker).collect(context, "malformed.example.test")
    assert observation.outcome is ObservationOutcome.ERROR
    assert observation.payload["reason_code"] == "malformed_fixture_data"
