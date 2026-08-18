"""AlienVault OTX as a reputation provider.

**Private report only, permanently.** OTX pulses are other researchers' threat reports
about somebody's domain. Republishing "this institution appears in N threat reports" on a
public page is a claim about them, sourced from a third party, that they have no way to
contest -- and it would be a claim we made, not one OTX made. The catalogue enforces this:
`E.domain_reputation_clean` is `private_only`, and the publication projector refuses any
check the catalogue does not mark `public_profile`. This module must never be the reason
that classification changes.

**A pulse is not a conviction.** OTX indexes reports; a domain can appear in one because
it was attacked, because it was mentioned, or because somebody's automation was noisy.
That is exactly why the reputation pillar resolves to `warning` and never `fail`, why it
sits in its own pillar, and why the report shows the evidence beside the verdict. This
module reports what OTX said and does not upgrade it into a judgement.

**No key means no answer, never a clean answer.** An unconfigured or refused provider
reports `UNAVAILABLE`, which the collector keeps distinct from `NOT_LISTED` all the way to
the report. A tool that reported a clean reputation because it failed to ask would be
worse than one that never asked.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from siembiot_worker.collectors.reputation import Listing, ProviderVerdict
from siembiot_worker.network_safety.collection_broker import (
    CollectionNetworkBroker,
    CollectionRequest,
)
from siembiot_worker.network_safety.collection_policy import (
    OperationClass,
    encode_path_segment,
    provider_destination,
)
from siembiot_worker.network_safety.url_policy import DestinationPolicyError

#: The service this speaks to. Named here rather than inline so the one third-party
#: dependency of the reputation pillar is visible in a single place.
DEFAULT_OTX_HOST = "otx.alienvault.com"

#: The header OTX authenticates with. The key travels only in this header, never in the
#: path or the query: a URL is written to logs, proxy records and error messages by
#: everything it passes through, and a credential in one is a credential published.
OTX_KEY_HEADER = "X-OTX-API-KEY"

PROVIDER_NAME = "otx"


class OTXReputationProvider:
    """Asks OTX whether a domain appears in any threat report."""

    def __init__(
        self,
        broker: CollectionNetworkBroker,
        api_key: str,
        organization_id: UUID,
        domain_id: UUID,
        assessment_id: UUID | None = None,
        host: str = DEFAULT_OTX_HOST,
    ) -> None:
        self._broker = broker
        self._api_key = api_key.strip()
        self._organization_id = organization_id
        self._domain_id = domain_id
        self._assessment_id = assessment_id
        self._host = host

    @property
    def name(self) -> str:
        return PROVIDER_NAME

    def lookup(self, host: str) -> ProviderVerdict:
        if not self._api_key:
            return ProviderVerdict(PROVIDER_NAME, Listing.UNAVAILABLE, "no_api_key")

        request = CollectionRequest(
            self._organization_id,
            self._domain_id,
            self._assessment_id,
            OperationClass.REPUTATION_QUERY,
            # The provider is the host being connected to, not the domain being asked
            # about. The other way round would apply the institution's rate limit and
            # address policy to a third party and file the audit row against the wrong
            # host.
            self._host,
            (self._host,),
        )
        try:
            destination = provider_destination(
                OperationClass.REPUTATION_QUERY,
                self._host,
                f"/api/v1/indicators/domain/{encode_path_segment(host)}/general",
            )
        except DestinationPolicyError as exc:
            # Defence in depth: the host reaches here from a validated column, so this
            # should be unreachable. If it ever is reached, a name that cannot be turned
            # into a safe request is one we report as unasked rather than one we crash
            # the assessment over -- or, worse, send.
            return ProviderVerdict(
                PROVIDER_NAME, Listing.UNAVAILABLE, f"unusable_host:{exc.reason}"
            )
        response = self._broker.fetch(
            request,
            destination,
            credentials={OTX_KEY_HEADER: self._api_key},
        )

        if not response.allowed or response.status_code != 200:
            # Including 403 and 429. A key that is rejected or throttled has told us
            # nothing about the domain, and "we could not ask" is the honest report.
            return ProviderVerdict(
                PROVIDER_NAME,
                Listing.UNAVAILABLE,
                f"status:{response.status_code}" if response.allowed else response.reason_code,
            )

        try:
            payload = json.loads(response.body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return ProviderVerdict(PROVIDER_NAME, Listing.UNAVAILABLE, "malformed_response")
        if not isinstance(payload, dict):
            return ProviderVerdict(PROVIDER_NAME, Listing.UNAVAILABLE, "malformed_response")

        return _verdict(payload)


def _verdict(payload: dict[str, Any]) -> ProviderVerdict:
    """Read one OTX answer.

    `pulse_info.count` is the number of threat reports naming the domain. A missing or
    unreadable count is not zero -- zero is an answer, and inventing it here is how a
    provider outage becomes a clean bill of health.

    `validation` is OTX's own note that an indicator is on a known-good list. It is
    reported in the operator detail rather than used to overrule the count: OTX saying
    both things at once is information, and quietly resolving the contradiction in either
    direction would be us deciding something the source did not.
    """
    pulse_info = payload.get("pulse_info")
    if not isinstance(pulse_info, dict):
        return ProviderVerdict(PROVIDER_NAME, Listing.UNAVAILABLE, "no_pulse_info")
    count = pulse_info.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        return ProviderVerdict(PROVIDER_NAME, Listing.UNAVAILABLE, "no_pulse_count")

    validations = payload.get("validation")
    whitelisted = len(validations) if isinstance(validations, list) else 0
    detail = f"pulses:{count} whitelisted:{whitelisted}"

    if count == 0:
        return ProviderVerdict(PROVIDER_NAME, Listing.NOT_LISTED, detail)
    return ProviderVerdict(PROVIDER_NAME, Listing.LISTED, detail)
