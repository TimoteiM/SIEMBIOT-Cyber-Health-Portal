from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from siembiot_worker.collection.models import CollectionObservation
from siembiot_worker.evidence.models import NormalizedObservation, Provenance
from siembiot_worker.normalization import ct, dns, email, http, rdap, tls
from siembiot_worker.normalization.common import NormalizationError, bounded_payload

TypeResolver = Callable[[Mapping[str, Any]], str]
_NORMALIZERS: dict[tuple[str, str], TypeResolver] = {
    ("dns", "1.0.0"): dns.observation_type,
    ("email-dns", "1.0.0"): email.observation_type,
    ("http", "1.0.0"): http.observation_type,
    ("tls", "1.0.0"): tls.observation_type,
    ("rdap", "1.0.0"): rdap.observation_type,
    ("ct", "1.0.0"): ct.observation_type,
}


def normalize_observation(
    source: CollectionObservation, *, organization_id: str, asset_id: str
) -> NormalizedObservation:
    resolver = _NORMALIZERS.get((source.collector.id, source.collector.version))
    if resolver is None:
        raise NormalizationError("normalizer_not_registered")
    payload = bounded_payload(source.payload)
    if not isinstance(payload, Mapping):
        raise NormalizationError("payload_not_object")
    scenario = source.scenario
    attribution = source.confidence
    if payload.get("provider_disagreement") is True or payload.get("asset_authorized") is False:
        attribution = min(attribution, 0.5)
    return NormalizedObservation.build(
        organization_id=organization_id,
        asset_id=asset_id,
        scope_reference=source.scope_reference,
        source_evidence_id=source.evidence_id,
        observation_type=resolver(payload),
        source_outcome=source.outcome,
        observed_at=source.collected_at,
        mode="fixture",
        provenance=Provenance(
            collector_id=source.collector.id,
            collector_version=source.collector.version,
            adapter_id=source.adapter.id,
            adapter_version=source.adapter.version,
            normalizer_version="1.0.0",
            scenario_id=scenario.id,
            scenario_sha256=scenario.sha256,
        ),
        payload=payload,
        source_confidence=source.confidence,
        attribution_confidence=attribution,
        freshness_seconds=source.freshness_seconds,
        publishable=False,
        real_world=False,
    )


__all__ = ["NormalizationError", "normalize_observation"]
