from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from siembiot_worker.collection.models import (
    CollectionObservation,
    ObservationOutcome,
    build_fixture_observation,
)
from siembiot_worker.collectors.common import (
    FixtureCollectorContext,
    RDAPBroker,
    broker_provenance,
)


class RDAPCollector:
    def __init__(self, broker: RDAPBroker) -> None:
        self._broker = broker

    def collect(self, context: FixtureCollectorContext, domain: str) -> CollectionObservation:
        result = self._broker.query_rdap(context.scenario_id, domain, cancelled=context.cancelled)
        payload: dict[str, Any] = {
            "fixture_only": True,
            "domain": domain,
            "reason_code": result.reason_code,
        }
        if result.allowed:
            status = result.data.get("status")
            events = result.data.get("events")
            entities = result.data.get("entities", [])
            valid = (
                isinstance(status, list | tuple)
                and len(status) <= 32
                and all(isinstance(item, str) and len(item) <= 128 for item in status)
                and isinstance(events, list | tuple)
                and len(events) <= 64
                and all(self._valid_event(item) for item in events)
                and isinstance(entities, list | tuple)
                and len(entities) <= 64
                and all(self._valid_entity(item) for item in entities)
            )
            if valid:
                normalized_status = cast(tuple[str, ...] | list[str], status)
                normalized_event_source = cast(
                    tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]], events
                )
                normalized_entities = cast(
                    tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]], entities
                )
                normalized_events = [
                    {"action": item["action"], "date": item["date"]}
                    for item in normalized_event_source
                ]
                roles = sorted(
                    {
                        role
                        for entity in normalized_entities
                        for role in entity.get("roles", [])
                        if isinstance(role, str)
                    }
                )
                payload.update(
                    {
                        "status": sorted(set(normalized_status)),
                        "events": normalized_events,
                        "entity_roles": roles,
                    }
                )
                outcome = ObservationOutcome.PASS
            else:
                payload["reason_code"] = "malformed_fixture_data"
                outcome = ObservationOutcome.ERROR
        elif result.reason_code in {"fixture_unavailable", "scenario_not_found"}:
            outcome = ObservationOutcome.UNAVAILABLE
        else:
            outcome = ObservationOutcome.ERROR
        scenario_id, scenario_sha256 = broker_provenance(context, result)
        return build_fixture_observation(
            scope_reference=context.scope_reference,
            collector_id="rdap",
            collector_version="1.0.0",
            adapter_id="fixture-internet",
            adapter_version="1.0.0",
            collected_at=result.fixture_timestamp,
            scenario_id=scenario_id,
            scenario_sha256=scenario_sha256,
            outcome=outcome,
            payload=payload,
        )

    @staticmethod
    def _valid_event(value: object) -> bool:
        return (
            isinstance(value, Mapping)
            and set(value) == {"action", "date"}
            and isinstance(value.get("action"), str)
            and isinstance(value.get("date"), str)
            and len(value["action"]) <= 128
            and len(value["date"]) <= 64
        )

    @staticmethod
    def _valid_entity(value: object) -> bool:
        if not isinstance(value, Mapping):
            return False
        roles = value.get("roles", [])
        return (
            isinstance(roles, list | tuple)
            and len(roles) <= 16
            and all(isinstance(role, str) and len(role) <= 64 for role in roles)
        )
