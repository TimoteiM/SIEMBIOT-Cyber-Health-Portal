from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from siembiot_worker.collection.models import (
    CollectionObservation,
    ObservationOutcome,
    build_fixture_observation,
)
from siembiot_worker.collectors.common import CTBroker, FixtureCollectorContext


class CTCollector:
    def __init__(self, broker: CTBroker) -> None:
        self._broker = broker

    def collect(self, context: FixtureCollectorContext, domain: str) -> CollectionObservation:
        result = self._broker.query_ct(
            context.scenario_id, domain, cancelled=context.cancelled
        )
        payload: dict[str, Any] = {
            "fixture_only": True,
            "domain": domain,
            "reason_code": result.reason_code,
            "asset_authorized": False,
            "asset_created": False,
        }
        if result.allowed:
            certificates = result.data.get("certificates")
            if not self._valid_certificates(certificates):
                payload["reason_code"] = "malformed_fixture_data"
                outcome = ObservationOutcome.ERROR
            else:
                normalized_certificates = cast(list[Mapping[str, Any]], certificates)
                asserted: set[str] = set()
                ignored = 0
                for certificate in normalized_certificates:
                    for name in cast(list[str], certificate["names"]):
                        if self._related(name, domain):
                            asserted.add(name)
                        else:
                            ignored += 1
                payload["asserted_names"] = sorted(asserted)
                payload["ignored_unrelated_names"] = ignored
                outcome = ObservationOutcome.PASS
        elif result.reason_code in {"fixture_unavailable", "scenario_not_found"}:
            outcome = ObservationOutcome.UNAVAILABLE
        else:
            outcome = ObservationOutcome.ERROR
        return build_fixture_observation(
            scope_reference=context.scope_reference,
            collector_id="ct",
            collector_version="1.0.0",
            adapter_id="fixture-internet",
            adapter_version="1.0.0",
            collected_at=result.fixture_timestamp,
            scenario_id=context.scenario_id,
            scenario_sha256=context.scenario_sha256,
            outcome=outcome,
            payload=payload,
        )

    @staticmethod
    def _related(name: str, domain: str) -> bool:
        normalized = name[2:] if name.startswith("*.") else name
        return normalized == domain or normalized.endswith(f".{domain}")

    @staticmethod
    def _valid_certificates(value: object) -> bool:
        if not isinstance(value, list) or len(value) > 100:
            return False
        for certificate in value:
            if not isinstance(certificate, Mapping):
                return False
            names = certificate.get("names")
            if (
                set(certificate) != {"issuer", "names", "not_after"}
                or not isinstance(certificate.get("issuer"), str)
                or not isinstance(certificate.get("not_after"), str)
                or not isinstance(names, list)
                or len(names) > 100
                or any(not isinstance(name, str) or len(name) > 253 for name in names)
            ):
                return False
        return True
