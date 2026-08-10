"""Whether the mail servers a domain publishes will encrypt what arrives (pillar B).

The e-mail collector reads what a domain *says* about its mail: SPF, DMARC, MTA-STS,
TLS-RPT. All of it is policy, and all of it is published in DNS by whoever edits the zone
-- which is frequently not whoever runs the mail server. So a domain can hold a full set
of correct records while its actual mail server refuses STARTTLS and takes every message
in plaintext. That gap is invisible to every check that reads only DNS, and it is exactly
the gap an institution would want told to them.

This connects to each published MX host and asks. The hosts come from the e-mail
collector's own observation rather than a fresh MX lookup, for the reason attribution
reads the DNS collector's addresses: a second lookup can legitimately answer differently,
and reporting transport for a mail host the rest of the assessment never saw would be a
statement about neither.
"""

from __future__ import annotations

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
from siembiot_worker.network_safety.smtp_probe import (
    HANDSHAKE_FAILED,
    NOT_OFFERED,
    OFFERED,
    UNREACHABLE,
)

#: How many MX hosts one domain's transport is checked against. Domains commonly publish
#: two to four for redundancy; where there are more, the first few by preference are the
#: ones that actually receive mail, and they are ordered by preference before slicing.
MAX_MAIL_HOSTS = 4

MAIL_TRANSPORT_DESCRIPTOR = AdapterDescriptor(
    adapter_id="mail_transport",
    version="1.0.0",
    # TLS_HTTP rather than ACTIVE_PROBE: what this observes is a TLS capability, and the
    # connection it opens is the one the MX record exists to invite.
    group=AdapterGroup.TLS_HTTP,
    title="Mail transport security",
    capabilities=frozenset({"mail.transport_security"}),
    data_classification=DataClassification.PUBLIC_OBSERVATION,
    terms_notes=(
        "Connects to published MX hosts on port 25 and completes the STARTTLS "
        "negotiation an ordinary sending mail server performs. No message is offered: "
        "the session ends at QUIT, before MAIL FROM."
    ),
    terms_url=None,
    required_secrets=frozenset(),
    timeout_seconds=28.0,
    rate_limit=RateLimitPolicy(2, 1.0, burst=1, minimum_interval_seconds=0.5),
    cost_unit=CostUnit.NONE,
    cache=CachePolicy(86_400),
    supports_fixtures=True,
)


class MailTransportCollector(Collector):
    descriptor = MAIL_TRANSPORT_DESCRIPTOR

    def __init__(self, broker: CollectionNetworkBroker, clock: Clock | None = None) -> None:
        super().__init__(broker, clock or utc_now)

    def collect(
        self, request: CollectionRequest, mail_hosts: tuple[str, ...] = ()
    ) -> CollectionResult:
        if not mail_hosts:
            # A domain that receives no mail is not failing at mail security. The e-mail
            # collector has already reported whether that is deliberate (a null MX) or an
            # absence, and this check has nothing to add to either.
            return self.not_applicable("no_mail_hosts", {"host": request.canonical_host})

        observed = [
            self._broker.probe_mail_transport(request, mail_host)
            for mail_host in mail_hosts[:MAX_MAIL_HOSTS]
        ]
        hosts: list[dict[str, Any]] = [
            {
                "host": item.host,
                "state": item.state,
                "tls_version": item.tls_version,
                "certificate_matches_host": item.certificate_matches_host,
                "greeting": item.greeting,
            }
            for item in observed
        ]

        reachable = [item for item in observed if item.state != UNREACHABLE]
        if not reachable:
            # Port 25 outbound is blocked by a great many hosting providers, so a total
            # failure here says where the assessment ran from, not what the mail server
            # does. Reporting it as "no encryption offered" would be a finding invented
            # out of our own network conditions.
            return self.not_applicable(
                "mail_hosts_unreachable", {"host": request.canonical_host, "hosts": hosts}
            )

        offering = [item for item in reachable if item.state == OFFERED]
        return self.ok(
            {
                "host": request.canonical_host,
                "hosts": hosts,
                "hosts_checked": len(reachable),
                "starttls_offered": len(offering),
                # The scored attribute. Every reachable mail host must offer it: one that
                # does not is a way in for plaintext, and a sender that fails over to it
                # will use it. Reporting "some do" as a pass would describe a domain that
                # is encrypted only when it happens to be.
                "starttls_everywhere": len(offering) == len(reachable),
                "starttls_refused": len([item for item in reachable if item.state == NOT_OFFERED]),
                "starttls_broken": len(
                    [item for item in reachable if item.state == HANDSHAKE_FAILED]
                ),
                # Kept separate from whether encryption is offered at all. A mismatched
                # certificate still encrypts, which is worth more than plaintext and less
                # than a correct one -- and collapsing the two would hide the difference.
                "certificate_valid_everywhere": all(
                    item.certificate_matches_host for item in offering
                ),
                "unreachable": len(observed) - len(reachable),
            },
            source=request.canonical_host,
        )
