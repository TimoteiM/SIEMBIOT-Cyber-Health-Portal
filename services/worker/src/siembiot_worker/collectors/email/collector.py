from __future__ import annotations

import re

from siembiot_worker.collection.models import CollectionObservation
from siembiot_worker.collectors.common import (
    DNSBroker,
    FixtureCollectorContext,
    dns_observation,
)

SELECTOR = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class EmailDNSCollector:
    def __init__(self, broker: DNSBroker) -> None:
        self._broker = broker

    def collect(
        self,
        context: FixtureCollectorContext,
        domain: str,
        *,
        dkim_selectors: tuple[str, ...],
    ) -> tuple[CollectionObservation, ...]:
        if len(dkim_selectors) != len(set(dkim_selectors)) or any(
            SELECTOR.fullmatch(selector) is None for selector in dkim_selectors
        ):
            raise ValueError("invalid_dkim_selector")
        requests = [
            (domain, "MX", "mx"),
            (domain, "TXT", "spf"),
            (f"_dmarc.{domain}", "TXT", "dmarc"),
            (f"_mta-sts.{domain}", "TXT", "mta_sts"),
            (f"_smtp._tls.{domain}", "TXT", "tls_rpt"),
            (f"_25._tcp.mail.{domain}", "TLSA", "tlsa"),
            (f"default._bimi.{domain}", "TXT", "bimi"),
        ]
        requests.extend(
            (f"{selector}._domainkey.{domain}", "TXT", f"dkim:{selector}")
            for selector in dkim_selectors
        )
        observations: list[CollectionObservation] = []
        for host, record_type, check in requests:
            result = self._broker.resolve_dns(
                context.scenario_id,
                host,
                record_type,
                cancelled=context.cancelled,
            )
            observations.append(
                dns_observation(
                    context=context,
                    result=result,
                    collector_id="email-dns",
                    host=host,
                    record_type=record_type,
                    check=check,
                )
            )
        return tuple(observations)
