"""Registration data collection over RDAP (pillar A).

RDAP responses are third-party JSON: hostile until proven otherwise. Only the small
set of fields below is read, sizes are capped, and nothing from the response is ever
used to choose the next destination.
"""

from __future__ import annotations

import json
from typing import Any

from siembiot_worker.adapters.contract import (
    AdapterDescriptor,
    AdapterGroup,
    CachePolicy,
    CollectionResult,
    CostUnit,
    DataClassification,
    RateLimitPolicy,
)
from siembiot_worker.collectors.base import Clock, Collector, utc_now
from siembiot_worker.network_safety.collection_broker import (
    CollectionNetworkBroker,
    CollectionRequest,
)
from siembiot_worker.network_safety.collection_policy import (
    OperationClass,
    encode_path_segment,
    provider_destination,
)
from siembiot_worker.network_safety.host_policy import canonical_host

MAX_EVENTS = 20
MAX_NAMESERVERS = 20
MAX_STATUS_VALUES = 20
_INTERESTING_EVENTS = frozenset(
    {"registration", "expiration", "last changed", "last update of rdap database", "transfer"}
)

RDAP_DESCRIPTOR = AdapterDescriptor(
    adapter_id="rdap_registration",
    version="1.0.0",
    group=AdapterGroup.DNS_RDAP,
    title="RDAP registration collector",
    capabilities=frozenset({"rdap.registration", "rdap.expiry", "rdap.status"}),
    data_classification=DataClassification.PUBLIC_OBSERVATION,
    terms_notes=(
        "RDAP is a public registration data protocol; responses may redact contacts "
        "under registry policy and GDPR. Contact objects are never stored."
    ),
    terms_url="https://datatracker.ietf.org/doc/html/rfc7483",
    required_secrets=frozenset(),
    timeout_seconds=8.0,
    rate_limit=RateLimitPolicy(2, 1.0, burst=1, minimum_interval_seconds=0.25),
    cost_unit=CostUnit.NONE,
    cache=CachePolicy(86_400),
    supports_fixtures=True,
)


def parse_rdap_domain(document: dict[str, Any]) -> dict[str, Any]:
    """Read only the registration facts we use; contact and entity data is discarded."""
    events: dict[str, str] = {}
    raw_events = document.get("events")
    if isinstance(raw_events, list):
        for event in raw_events[:MAX_EVENTS]:
            if not isinstance(event, dict):
                continue
            action = event.get("eventAction")
            date = event.get("eventDate")
            if isinstance(action, str) and isinstance(date, str):
                lowered = action.lower()
                if lowered in _INTERESTING_EVENTS:
                    events[lowered] = date[:64]
    statuses: list[str] = []
    raw_status = document.get("status")
    if isinstance(raw_status, list):
        statuses = sorted(
            {item[:64] for item in raw_status[:MAX_STATUS_VALUES] if isinstance(item, str)}
        )
    nameservers: list[str] = []
    raw_nameservers = document.get("nameservers")
    if isinstance(raw_nameservers, list):
        for nameserver in raw_nameservers[:MAX_NAMESERVERS]:
            if isinstance(nameserver, dict):
                name = nameserver.get("ldhName")
                if isinstance(name, str) and name:
                    nameservers.append(name.rstrip(".").lower()[:255])
    handle = document.get("handle")
    ldh_name = document.get("ldhName")
    return {
        "handle": handle[:64] if isinstance(handle, str) else None,
        "ldh_name": ldh_name.rstrip(".").lower()[:255] if isinstance(ldh_name, str) else None,
        "statuses": statuses,
        "events": events,
        "registration_date": events.get("registration"),
        "expiration_date": events.get("expiration"),
        "last_changed_date": events.get("last changed"),
        "nameservers": sorted(set(nameservers)),
        "transfer_prohibited": any("transfer prohibited" in item for item in statuses),
        "delete_prohibited": any("delete prohibited" in item for item in statuses),
    }


class RDAPCollector(Collector):
    descriptor = RDAP_DESCRIPTOR

    def __init__(
        self,
        broker: CollectionNetworkBroker,
        endpoint_host: str,
        clock: Clock = utc_now,
    ) -> None:
        super().__init__(broker, clock)
        self._endpoint_host = canonical_host(endpoint_host)

    def collect(self, request: CollectionRequest) -> CollectionResult:
        host = request.canonical_host
        rdap_request = CollectionRequest(
            request.organization_id,
            request.domain_id,
            request.assessment_id,
            OperationClass.RDAP_QUERY,
            self._endpoint_host,
            (self._endpoint_host,),
        )
        destination = provider_destination(
            OperationClass.RDAP_QUERY,
            self._endpoint_host,
            f"/domain/{encode_path_segment(host)}",
        )
        result = self._broker.fetch(rdap_request, destination)
        if not result.allowed:
            return self.unavailable(result.reason_code, {"host": host})
        if result.status_code == 404:
            return self.not_applicable("domain_not_in_registry", {"host": host})
        if result.status_code != 200:
            return self.unavailable(f"http_status_{result.status_code}", {"host": host})
        try:
            document = json.loads(result.body.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self.error("invalid_rdap_document")
        if not isinstance(document, dict):
            return self.error("invalid_rdap_document")
        parsed = parse_rdap_domain(document)
        payload = {"host": host, "endpoint": self._endpoint_host, "registration": parsed}
        if parsed["expiration_date"] is None:
            return self.partial(payload, ("expiration_date_absent",), source=self._endpoint_host)
        return self.ok(payload, source=self._endpoint_host)
