"""Which third parties this platform talks to, and on what terms.

An institution enrolling a domain is entitled to know who else sees anything as a result.
Most of the answer is reassuring — the collectors are keyless and talk to public
resolvers and registries — but "most" is not something a public body should have to take
on trust, and the honest way to say it is to publish the list.

Read from the adapter descriptors rather than from a hand-written page. A document
describing providers is a document that goes stale the first time somebody adds one; the
descriptors are what the collectors actually run under, so this cannot describe a
provider the platform does not use or omit one it does.

Not tenant data. Every organization sees the same list, so there is no row-level security
here and nothing to scope — but it still requires a session, because "which services does
this platform depend on" is a reasonable question for an attacker to want answered
cheaply.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from siembiot.auth import current_principal
from siembiot.contracts import ContractModel
from siembiot.identity import Principal


class ProviderResponse(ContractModel):
    adapter_id: str
    version: str
    group: str
    title: str
    capabilities: list[str]
    #: What this provider is trusted to tell us, in the same vocabulary the evidence
    #: contracts use. `public_observation` means it reports facts anybody could check.
    data_classification: str
    terms_notes: str
    terms_url: str | None
    #: Whether it needs a credential. Empty for every collector shipped today, which is
    #: what makes the platform runnable without paid keys -- and is worth showing rather
    #: than asserting in a README.
    required_secrets: list[str]
    cost_unit: str
    #: Whether the platform can exercise it against recorded fixtures. A provider that
    #: cannot be tested offline is one whose behaviour is only ever observed in
    #: production.
    supports_fixtures: bool
    passive: bool


class ProvidersResponse(ContractModel):
    providers: list[ProviderResponse]


def _descriptors() -> list[ProviderResponse]:
    """Every adapter the collectors declare.

    Imported here rather than at module scope so the API does not carry the worker's
    import graph on every startup, and so a collector that fails to import surfaces as a
    failed request to one endpoint rather than an API that will not boot.
    """
    from siembiot_worker.collectors.ct_log import CT_DESCRIPTOR
    from siembiot_worker.collectors.dns_records import DNS_DESCRIPTOR
    from siembiot_worker.collectors.email_records import EMAIL_DESCRIPTOR
    from siembiot_worker.collectors.http_surface import HTTP_DESCRIPTOR
    from siembiot_worker.collectors.mail_transport import MAIL_TRANSPORT_DESCRIPTOR
    from siembiot_worker.collectors.network_attribution import ATTRIBUTION_DESCRIPTOR
    from siembiot_worker.collectors.port_surface import PORT_DESCRIPTOR
    from siembiot_worker.collectors.rdap import RDAP_DESCRIPTOR
    from siembiot_worker.collectors.tls_certificate import TLS_DESCRIPTOR

    descriptors = (
        DNS_DESCRIPTOR,
        EMAIL_DESCRIPTOR,
        TLS_DESCRIPTOR,
        HTTP_DESCRIPTOR,
        RDAP_DESCRIPTOR,
        CT_DESCRIPTOR,
        PORT_DESCRIPTOR,
        ATTRIBUTION_DESCRIPTOR,
        MAIL_TRANSPORT_DESCRIPTOR,
    )
    return [
        ProviderResponse(
            adapter_id=descriptor.adapter_id,
            version=descriptor.version,
            group=str(descriptor.group.value),
            title=descriptor.title,
            capabilities=sorted(descriptor.capabilities),
            data_classification=str(descriptor.data_classification.value),
            terms_notes=descriptor.terms_notes,
            terms_url=descriptor.terms_url,
            required_secrets=sorted(descriptor.required_secrets),
            cost_unit=str(descriptor.cost_unit.value),
            supports_fixtures=descriptor.supports_fixtures,
            passive=descriptor.passive,
        )
        for descriptor in sorted(descriptors, key=lambda item: item.adapter_id)
    ]


def build_providers_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["providers"])

    @router.get("/providers", response_model=ProvidersResponse)
    def index(principal: Principal = Depends(current_principal)) -> ProvidersResponse:
        del principal
        return ProvidersResponse(providers=_descriptors())

    return router
