"""The provider adapter contract.

Every collection source — a no-key deterministic collector or a paid passive
intelligence provider — is described by the same declarative descriptor so the
platform can reason about terms, cost, freshness, and degradation uniformly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

ADAPTER_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
SEMANTIC_VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")


class AdapterError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AdapterGroup(StrEnum):
    DNS_RDAP = "dns_rdap"
    CERTIFICATE_TRANSPARENCY = "certificate_transparency"
    TLS_HTTP = "tls_http"
    PASSIVE_ASSET_INTELLIGENCE = "passive_asset_intelligence"
    REPUTATION = "reputation"
    NOTIFICATION = "notification"
    MODEL_PROVIDER = "model_provider"
    OBJECT_STORAGE = "object_storage"


class DataClassification(StrEnum):
    """How the adapter's output must be handled once it lands in the platform."""

    PUBLIC_OBSERVATION = "public_observation"
    TENANT_CONFIDENTIAL = "tenant_confidential"
    RESTRICTED_PROVIDER_DATA = "restricted_provider_data"


class CostUnit(StrEnum):
    NONE = "none"
    QUERY = "query"
    RESULT = "result"
    MONTHLY_SUBSCRIPTION = "monthly_subscription"


class CollectionStatus(StrEnum):
    """Collection never guesses; every run reports one of these explicitly."""

    OK = "ok"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    UNAVAILABLE = "unavailable"
    DENIED = "denied"
    ERROR = "error"


class HealthState(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNCONFIGURED = "unconfigured"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class RateLimitPolicy:
    """Requests are shaped before they leave, never discovered by being throttled."""

    max_requests: int
    per_seconds: float
    burst: int = 1
    minimum_interval_seconds: float = 0.0

    def __post_init__(self) -> None:
        if self.max_requests < 1 or self.per_seconds <= 0 or self.burst < 1:
            raise AdapterError("invalid_rate_limit")


@dataclass(frozen=True)
class CachePolicy:
    ttl_seconds: int
    cacheable: bool = True
    provider_terms_permit_caching: bool = True

    def __post_init__(self) -> None:
        if self.ttl_seconds < 0:
            raise AdapterError("invalid_cache_ttl")
        if self.cacheable and not self.provider_terms_permit_caching:
            raise AdapterError("cache_conflicts_with_terms")


@dataclass(frozen=True)
class AdapterDescriptor:
    adapter_id: str
    version: str
    group: AdapterGroup
    title: str
    capabilities: frozenset[str]
    data_classification: DataClassification
    terms_notes: str
    terms_url: str | None
    required_secrets: frozenset[str]
    timeout_seconds: float
    rate_limit: RateLimitPolicy
    cost_unit: CostUnit
    cache: CachePolicy
    supports_fixtures: bool
    passive: bool = True
    licence_notes: str | None = None

    def __post_init__(self) -> None:
        if not ADAPTER_ID_PATTERN.match(self.adapter_id):
            raise AdapterError("invalid_adapter_id")
        if not SEMANTIC_VERSION_PATTERN.match(self.version):
            raise AdapterError("invalid_adapter_version")
        if not self.capabilities:
            raise AdapterError("missing_capabilities")
        if not self.title.strip() or not self.terms_notes.strip():
            raise AdapterError("missing_terms_notes")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 30:
            raise AdapterError("invalid_timeout")
        if self.cost_unit is CostUnit.NONE and self.required_secrets:
            raise AdapterError("free_adapter_requires_no_secrets")
        if self.cost_unit is not CostUnit.NONE and not self.required_secrets:
            raise AdapterError("paid_adapter_requires_secrets")
        if not self.supports_fixtures:
            raise AdapterError("fixtures_required")

    @property
    def requires_configuration(self) -> bool:
        return bool(self.required_secrets)


@dataclass(frozen=True)
class HealthReport:
    state: HealthState
    detail: str
    checked_at: datetime

    def __post_init__(self) -> None:
        if self.checked_at.tzinfo is None:
            raise AdapterError("naive_timestamp")


@dataclass(frozen=True)
class Provenance:
    """Where an observation came from, so confidence and freshness stay auditable."""

    adapter_id: str
    adapter_version: str
    collected_at: datetime
    observed_at: datetime | None = None
    from_cache: bool = False
    source_reference: str | None = None

    def __post_init__(self) -> None:
        if self.collected_at.tzinfo is None:
            raise AdapterError("naive_timestamp")
        if self.observed_at is not None and self.observed_at.tzinfo is None:
            raise AdapterError("naive_timestamp")

    @property
    def age_seconds(self) -> float:
        reference = self.observed_at or self.collected_at
        return max(0.0, (datetime.now(UTC) - reference).total_seconds())


@dataclass(frozen=True)
class CollectionResult:
    """Raw, adapter-shaped output. Normalization into evidence happens downstream."""

    status: CollectionStatus
    provenance: Provenance
    payload: dict[str, Any] = field(default_factory=dict)
    reason_code: str | None = None
    partial_reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status is not CollectionStatus.OK and self.reason_code is None:
            raise AdapterError("reason_code_required")
        if self.status is CollectionStatus.PARTIAL and not self.partial_reasons:
            raise AdapterError("partial_reasons_required")

    @property
    def usable(self) -> bool:
        return self.status in {CollectionStatus.OK, CollectionStatus.PARTIAL}


class ProviderAdapter(Protocol):
    @property
    def descriptor(self) -> AdapterDescriptor: ...

    def health(self) -> HealthReport: ...
