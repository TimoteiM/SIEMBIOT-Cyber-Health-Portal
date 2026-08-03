from __future__ import annotations

from typing import Any

from siembiot_worker.collection.models import (
    CollectionObservation,
    ObservationOutcome,
    build_fixture_observation,
)
from siembiot_worker.collectors.common import FixtureCollectorContext, TLSBroker

FIELDS = ("version", "cipher", "hostname_valid", "chain_valid", "not_before", "not_after")


class TLSCollector:
    def __init__(self, broker: TLSBroker) -> None:
        self._broker = broker

    def collect(self, context: FixtureCollectorContext, host: str) -> CollectionObservation:
        result = self._broker.handshake_tls(context.scenario_id, host, cancelled=context.cancelled)
        payload: dict[str, Any] = {
            "fixture_only": True,
            "host": host,
            "reason_code": result.reason_code,
        }
        if result.allowed:
            valid = (
                all(field in result.data for field in FIELDS)
                and isinstance(result.data.get("version"), str)
                and isinstance(result.data.get("cipher"), str)
                and isinstance(result.data.get("hostname_valid"), bool)
                and isinstance(result.data.get("chain_valid"), bool)
                and isinstance(result.data.get("not_before"), str)
                and isinstance(result.data.get("not_after"), str)
                and all(len(str(result.data[field])) <= 256 for field in FIELDS)
            )
            if valid:
                payload.update({field: result.data[field] for field in FIELDS})
                outcome = (
                    ObservationOutcome.PASS
                    if result.data["hostname_valid"] and result.data["chain_valid"]
                    else ObservationOutcome.FAIL
                )
            else:
                payload["reason_code"] = "malformed_fixture_data"
                outcome = ObservationOutcome.ERROR
        elif result.reason_code in {"fixture_unavailable", "scenario_not_found"}:
            outcome = ObservationOutcome.UNKNOWN
        else:
            outcome = ObservationOutcome.ERROR
        return build_fixture_observation(
            scope_reference=context.scope_reference,
            collector_id="tls",
            collector_version="1.0.0",
            adapter_id="fixture-internet",
            adapter_version="1.0.0",
            collected_at=result.fixture_timestamp,
            scenario_id=context.scenario_id,
            scenario_sha256=context.scenario_sha256,
            outcome=outcome,
            payload=payload,
        )
