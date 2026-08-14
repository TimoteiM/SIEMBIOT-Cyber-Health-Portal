"""The shipped adapter catalog.

Every descriptor the platform knows about is listed here, including adapters that
require secrets the deployment may not have. An unconfigured adapter is still
catalogued so its checks resolve to ``unavailable`` instead of silently vanishing.
"""

from __future__ import annotations

from collections.abc import Mapping

from siembiot_worker.adapters.contract import (
    AdapterDescriptor,
    AdapterGroup,
    CachePolicy,
    CostUnit,
    DataClassification,
    HealthState,
    RateLimitPolicy,
)
from siembiot_worker.collectors.ct_log import CT_DESCRIPTOR
from siembiot_worker.collectors.dns_records import DNS_DESCRIPTOR
from siembiot_worker.collectors.email_records import EMAIL_DESCRIPTOR
from siembiot_worker.collectors.http_surface import HTTP_DESCRIPTOR
from siembiot_worker.collectors.rdap import RDAP_DESCRIPTOR
from siembiot_worker.collectors.tls_certificate import TLS_DESCRIPTOR

KEYLESS_DESCRIPTORS: tuple[AdapterDescriptor, ...] = (
    CT_DESCRIPTOR,
    DNS_DESCRIPTOR,
    EMAIL_DESCRIPTOR,
    HTTP_DESCRIPTOR,
    RDAP_DESCRIPTOR,
    TLS_DESCRIPTOR,
)

PASSIVE_ASSET_INTELLIGENCE_DESCRIPTOR = AdapterDescriptor(
    adapter_id="passive_asset_intelligence",
    version="1.0.0",
    group=AdapterGroup.PASSIVE_ASSET_INTELLIGENCE,
    title="Passive asset intelligence provider (opt-in)",
    capabilities=frozenset({"assets.exposed_services", "assets.hosting_context"}),
    data_classification=DataClassification.RESTRICTED_PROVIDER_DATA,
    terms_notes=(
        "Licensed passive dataset. Redistribution of raw records is prohibited; only a "
        "normalized subset plus a content hash is retained."
    ),
    terms_url=None,
    required_secrets=frozenset({"SIEMBIOT_PASSIVE_INTEL_TOKEN"}),
    timeout_seconds=10.0,
    rate_limit=RateLimitPolicy(1, 1.0, burst=1, minimum_interval_seconds=1.0),
    cost_unit=CostUnit.QUERY,
    cache=CachePolicy(3_600),
    supports_fixtures=True,
    passive=True,
    licence_notes="Requires a provider agreement before enablement.",
)

REPUTATION_DESCRIPTOR = AdapterDescriptor(
    adapter_id="reputation_safe_browsing",
    version="1.0.0",
    group=AdapterGroup.REPUTATION,
    title="Reputation and safe-browsing provider (opt-in)",
    capabilities=frozenset({"reputation.domain", "reputation.url"}),
    data_classification=DataClassification.RESTRICTED_PROVIDER_DATA,
    terms_notes=(
        "Official reputation API. A listing is a third-party signal, never evidence of "
        "compromise; disagreement between providers is preserved."
    ),
    terms_url=None,
    required_secrets=frozenset({"SIEMBIOT_SAFE_BROWSING_KEY"}),
    timeout_seconds=8.0,
    rate_limit=RateLimitPolicy(5, 1.0, burst=2),
    cost_unit=CostUnit.QUERY,
    cache=CachePolicy(1_800),
    supports_fixtures=True,
    passive=True,
    licence_notes="Requires a provider agreement before enablement.",
)

SPAMHAUS_DESCRIPTOR = AdapterDescriptor(
    adapter_id="reputation_spamhaus_dqs",
    version="1.0.0",
    group=AdapterGroup.REPUTATION,
    title="Spamhaus Data Query Service (opt-in)",
    capabilities=frozenset({"reputation.domain", "reputation.ip"}),
    data_classification=DataClassification.RESTRICTED_PROVIDER_DATA,
    terms_notes=(
        "Free Data Query Service is limited to non-commercial use and must not "
        "consistently exceed 100,000 queries per day. Spamhaus's published terms do not "
        "address using results inside a tool offered to other organisations, or "
        "displaying them to those organisations -- which is what this platform would do. "
        "Silence is not permission: enablement waits on a written answer from Spamhaus."
    ),
    terms_url="https://www.spamhaus.com/terms-of-use-fair-use-policy-for-free-data-query-service/",
    #: The key is the leftmost label of the query name -- `<key>.<list>.dq.spamhaus.net`
    #: -- not a header. `telemetry.redact` has a rule for that shape specifically,
    #: because the redactor written for `scheme://user:pass@host` saw nothing wrong with
    #: an ordinary-looking hostname.
    required_secrets=frozenset({"SIEMBIOT_SPAMHAUS_DQS_KEY"}),
    timeout_seconds=5.0,
    rate_limit=RateLimitPolicy(5, 1.0, burst=2, minimum_interval_seconds=0.1),
    cost_unit=CostUnit.QUERY,
    cache=CachePolicy(3_600),
    supports_fixtures=True,
    passive=True,
    licence_notes="Blocked on written confirmation that the free tier covers this use.",
)

OTX_DESCRIPTOR = AdapterDescriptor(
    adapter_id="reputation_otx",
    version="1.0.0",
    group=AdapterGroup.REPUTATION,
    title="Open Threat Exchange indicators (opt-in)",
    capabilities=frozenset({"reputation.domain"}),
    data_classification=DataClassification.RESTRICTED_PROVIDER_DATA,
    terms_notes=(
        "Community-contributed indicators, which means variable quality and real false "
        "positives. Results are private-report-only and must never reach a public page "
        "or an opt-in publication: publishing 'this town hall appears in threat "
        "intelligence' on evidence that can be wrong is the sharpest reputational risk "
        "in this product. The policy catalogue enforces it -- the reputation check is "
        "classed `private_only`, which the publication projector filters on."
    ),
    terms_url="https://otx.alienvault.com/",
    required_secrets=frozenset({"SIEMBIOT_OTX_API_KEY"}),
    timeout_seconds=8.0,
    rate_limit=RateLimitPolicy(2, 1.0, burst=1, minimum_interval_seconds=0.5),
    cost_unit=CostUnit.QUERY,
    cache=CachePolicy(21_600),
    supports_fixtures=True,
    passive=True,
    licence_notes="Free API key; terms not independently verified.",
)

OPT_IN_DESCRIPTORS: tuple[AdapterDescriptor, ...] = (
    PASSIVE_ASSET_INTELLIGENCE_DESCRIPTOR,
    REPUTATION_DESCRIPTOR,
    SPAMHAUS_DESCRIPTOR,
    OTX_DESCRIPTOR,
)

ALL_DESCRIPTORS: tuple[AdapterDescriptor, ...] = tuple(
    sorted(KEYLESS_DESCRIPTORS + OPT_IN_DESCRIPTORS, key=lambda item: item.adapter_id)
)

CORE_CAPABILITIES: frozenset[str] = frozenset(
    {
        "dns.delegation",
        "dns.dnssec",
        "dns.caa",
        "email.spf",
        "email.dmarc",
        "email.mta_sts",
        "tls.certificate",
        "http.headers",
        "rdap.registration",
        "ct.asset_candidates",
    }
)


def keyless_capabilities() -> frozenset[str]:
    """Capabilities available with no provider keys configured at all."""
    return frozenset().union(*(item.capabilities for item in KEYLESS_DESCRIPTORS))


def descriptor_health(descriptor: AdapterDescriptor, secrets: Mapping[str, str]) -> HealthState:
    """An adapter missing its secrets is unconfigured, not unhealthy and not absent."""
    if not descriptor.required_secrets:
        return HealthState.HEALTHY
    if all(secrets.get(name) for name in descriptor.required_secrets):
        return HealthState.HEALTHY
    return HealthState.UNCONFIGURED
