from __future__ import annotations

from siembiot_worker.collection.models import CollectionObservation
from siembiot_worker.collectors.common import (
    DNSBroker,
    FixtureCollectorContext,
    dns_observation,
)


class DNSCollector:
    def __init__(self, broker: DNSBroker) -> None:
        self._broker = broker

    def collect(
        self, context: FixtureCollectorContext, domain: str
    ) -> tuple[CollectionObservation, ...]:
        requests = (
            (domain, "NS", "NS"),
            (domain, "SOA", "SOA"),
            (domain, "DS", "DS"),
            (domain, "DNSKEY", "DNSKEY"),
            (domain, "CAA", "CAA"),
            (domain, "A", "A"),
            (f"wildcard.{domain}", "A", "WILDCARD_A"),
        )
        observations: list[CollectionObservation] = []
        for host, query_type, label in requests:
            result = self._broker.resolve_dns(
                context.scenario_id,
                host,
                query_type,
                cancelled=context.cancelled,
            )
            observations.append(
                dns_observation(
                    context=context,
                    result=result,
                    collector_id="dns",
                    host=host,
                    record_type=label,
                )
            )
        return tuple(observations)
