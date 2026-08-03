from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from siembiot_worker.collection.broker import (
    FixtureBrokerResult,
    HTTPFixtureRequest,
)
from siembiot_worker.collection.models import (
    CollectionObservation,
    ObservationOutcome,
    build_fixture_observation,
)


class DNSBroker(Protocol):
    def resolve_dns(
        self,
        scenario_id: str,
        host: str,
        record_type: str,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> FixtureBrokerResult: ...


class HTTPBroker(Protocol):
    def fetch_http(
        self,
        scenario_id: str,
        request: HTTPFixtureRequest,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> FixtureBrokerResult: ...


class TLSBroker(Protocol):
    def handshake_tls(
        self,
        scenario_id: str,
        host: str,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> FixtureBrokerResult: ...


class RDAPBroker(Protocol):
    def query_rdap(
        self,
        scenario_id: str,
        domain: str,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> FixtureBrokerResult: ...


class CTBroker(Protocol):
    def query_ct(
        self,
        scenario_id: str,
        domain: str,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> FixtureBrokerResult: ...


@dataclass(frozen=True)
class FixtureCollectorContext:
    scope_reference: str
    scenario_id: str
    cancelled: Callable[[], bool] | None = None


def broker_provenance(
    context: FixtureCollectorContext, result: FixtureBrokerResult
) -> tuple[str, str]:
    if result.scenario_id != context.scenario_id or result.scenario_sha256 is None:
        raise ValueError("broker_scenario_provenance_mismatch")
    return result.scenario_id, result.scenario_sha256


def dns_observation(
    *,
    context: FixtureCollectorContext,
    result: FixtureBrokerResult,
    collector_id: str,
    host: str,
    record_type: str,
    check: str | None = None,
) -> CollectionObservation:
    raw_records = result.data.get("records")
    records: list[str] = []
    reason_code = result.reason_code
    if result.allowed:
        if (
            not isinstance(raw_records, list | tuple)
            or len(raw_records) > 64
            or any(not isinstance(value, str) or len(value) > 2_048 for value in raw_records)
        ):
            outcome = ObservationOutcome.ERROR
            reason_code = "malformed_fixture_data"
        else:
            records = list(raw_records)
            outcome = ObservationOutcome.PASS if records else ObservationOutcome.WARNING
    elif result.reason_code in {"fixture_unavailable", "scenario_not_found"}:
        outcome = ObservationOutcome.UNKNOWN
    else:
        outcome = ObservationOutcome.ERROR
    payload: dict[str, object] = {
        "fixture_only": True,
        "host": host,
        "record_type": record_type,
        "records": records,
        "reason_code": reason_code,
    }
    if check is not None:
        payload["check"] = check
    scenario_id, scenario_sha256 = broker_provenance(context, result)
    return build_fixture_observation(
        scope_reference=context.scope_reference,
        collector_id=collector_id,
        collector_version="1.0.0",
        adapter_id="fixture-internet",
        adapter_version="1.0.0",
        collected_at=result.fixture_timestamp,
        scenario_id=scenario_id,
        scenario_sha256=scenario_sha256,
        outcome=outcome,
        payload=payload,
    )
