"""Shared collector plumbing.

A collector owns parsing and applicability, never networking or scoring. It receives
a broker and a clock, and returns a ``CollectionResult`` whose payload is raw enough
that the Milestone 4 normalizers, not the collector, decide what it means.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from siembiot_worker.adapters.contract import (
    AdapterDescriptor,
    CollectionResult,
    CollectionStatus,
    HealthReport,
    HealthState,
    Provenance,
)
from siembiot_worker.network_safety.collection_broker import (
    CollectionNetworkBroker,
    CollectionRequest,
)
from siembiot_worker.network_safety.dns_client import DNSRecordSet

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


class Collector:
    """Base class binding a descriptor to a network broker."""

    descriptor: AdapterDescriptor

    def __init__(self, broker: CollectionNetworkBroker, clock: Clock = utc_now) -> None:
        self._broker = broker
        self._clock = clock

    @property
    def broker(self) -> CollectionNetworkBroker:
        return self._broker

    def health(self) -> HealthReport:
        return HealthReport(HealthState.HEALTHY, "keyless collector", self._clock())

    def _provenance(self, source_reference: str | None = None) -> Provenance:
        return Provenance(
            self.descriptor.adapter_id,
            self.descriptor.version,
            self._clock(),
            source_reference=source_reference,
        )

    def ok(self, payload: dict[str, Any], source: str | None = None) -> CollectionResult:
        return CollectionResult(CollectionStatus.OK, self._provenance(source), payload)

    def partial(
        self, payload: dict[str, Any], reasons: tuple[str, ...], source: str | None = None
    ) -> CollectionResult:
        return CollectionResult(
            CollectionStatus.PARTIAL,
            self._provenance(source),
            payload,
            reason_code="incomplete_collection",
            partial_reasons=reasons,
        )

    def unavailable(self, reason: str, payload: dict[str, Any] | None = None) -> CollectionResult:
        return CollectionResult(
            CollectionStatus.UNAVAILABLE, self._provenance(), payload or {}, reason_code=reason
        )

    def denied(self, reason: str) -> CollectionResult:
        return CollectionResult(CollectionStatus.DENIED, self._provenance(), {}, reason_code=reason)

    def not_applicable(
        self, reason: str, payload: dict[str, Any] | None = None
    ) -> CollectionResult:
        return CollectionResult(
            CollectionStatus.NOT_APPLICABLE,
            self._provenance(),
            payload or {},
            reason_code=reason,
        )

    def error(self, reason: str) -> CollectionResult:
        return CollectionResult(CollectionStatus.ERROR, self._provenance(), {}, reason_code=reason)


def record_set_payload(record_set: DNSRecordSet) -> dict[str, Any]:
    """Serialize a DNS answer without hiding an inconclusive outcome as an empty set."""
    return {
        "name": record_set.query.name,
        "record_type": record_set.query.record_type,
        "status": record_set.status,
        "records": list(record_set.records),
        "dnssec_authenticated": record_set.authenticated,
        "ttl_seconds": record_set.ttl_seconds,
        "conclusive": record_set.is_conclusive,
    }


def inconclusive_reasons(
    answers: dict[str, DNSRecordSet], required: tuple[str, ...] = ()
) -> tuple[str, ...]:
    """Name every lookup that could not prove presence or absence."""
    reasons = tuple(
        f"{key}_{answer.status}"
        for key, answer in sorted(answers.items())
        if not answer.is_conclusive
    )
    missing = tuple(f"{key}_missing" for key in required if key not in answers)
    return reasons + missing


def request_for(
    base: CollectionRequest, operation_class: Any, host: str | None = None
) -> CollectionRequest:
    """Derive a request for a different operation class on the same authorized scope."""
    from dataclasses import replace

    changes: dict[str, Any] = {"operation_class": operation_class}
    if host is not None:
        changes["canonical_host"] = host
    return replace(base, **changes)
