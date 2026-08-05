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

OPT_IN_DESCRIPTORS: tuple[AdapterDescriptor, ...] = (
    PASSIVE_ASSET_INTELLIGENCE_DESCRIPTOR,
    REPUTATION_DESCRIPTOR,
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
