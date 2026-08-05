from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from siembiot_worker.adapters.contract import (
    AdapterDescriptor,
    AdapterError,
    AdapterGroup,
    CachePolicy,
    CollectionResult,
    CollectionStatus,
    CostUnit,
    DataClassification,
    HealthReport,
    HealthState,
    Provenance,
    RateLimitPolicy,
)
from siembiot_worker.adapters.registry import AdapterRegistry

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def descriptor(**overrides: object) -> AdapterDescriptor:
    defaults: dict[str, object] = {
        "adapter_id": "dns_public",
        "version": "1.0.0",
        "group": AdapterGroup.DNS_RDAP,
        "title": "Public recursive DNS",
        "capabilities": frozenset({"dns.records"}),
        "data_classification": DataClassification.PUBLIC_OBSERVATION,
        "terms_notes": "Public DNS data; no provider terms restrict reuse.",
        "terms_url": None,
        "required_secrets": frozenset(),
        "timeout_seconds": 3.0,
        "rate_limit": RateLimitPolicy(10, 1.0, burst=5),
        "cost_unit": CostUnit.NONE,
        "cache": CachePolicy(300),
        "supports_fixtures": True,
    }
    defaults.update(overrides)
    return AdapterDescriptor(**defaults)  # type: ignore[arg-type]


class StubAdapter:
    def __init__(self, adapter_descriptor: AdapterDescriptor, state: HealthState) -> None:
        self._descriptor = adapter_descriptor
        self._state = state

    @property
    def descriptor(self) -> AdapterDescriptor:
        return self._descriptor

    def health(self) -> HealthReport:
        return HealthReport(self._state, "stub", NOW)


# -- descriptor validation ---------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"adapter_id": "X"}, "invalid_adapter_id"),
        ({"adapter_id": "has-dash"}, "invalid_adapter_id"),
        ({"version": "1.0"}, "invalid_adapter_version"),
        ({"capabilities": frozenset()}, "missing_capabilities"),
        ({"terms_notes": "  "}, "missing_terms_notes"),
        ({"timeout_seconds": 0}, "invalid_timeout"),
        ({"timeout_seconds": 120}, "invalid_timeout"),
        ({"supports_fixtures": False}, "fixtures_required"),
        ({"required_secrets": frozenset({"KEY"})}, "free_adapter_requires_no_secrets"),
        ({"cost_unit": CostUnit.QUERY}, "paid_adapter_requires_secrets"),
    ],
)
def test_incomplete_descriptors_are_rejected(overrides: dict[str, object], reason: str) -> None:
    with pytest.raises(AdapterError) as error:
        descriptor(**overrides)
    assert error.value.reason == reason


def test_paid_adapter_with_secrets_is_valid_and_requires_configuration() -> None:
    paid = descriptor(
        adapter_id="passive_intel",
        group=AdapterGroup.PASSIVE_ASSET_INTELLIGENCE,
        cost_unit=CostUnit.QUERY,
        required_secrets=frozenset({"SIEMBIOT_PASSIVE_INTEL_TOKEN"}),
        data_classification=DataClassification.RESTRICTED_PROVIDER_DATA,
    )
    assert paid.requires_configuration is True


def test_cache_policy_cannot_contradict_provider_terms() -> None:
    with pytest.raises(AdapterError) as error:
        CachePolicy(600, cacheable=True, provider_terms_permit_caching=False)
    assert error.value.reason == "cache_conflicts_with_terms"


def test_rate_limit_policy_rejects_unbounded_configuration() -> None:
    with pytest.raises(AdapterError):
        RateLimitPolicy(0, 1.0)
    with pytest.raises(AdapterError):
        RateLimitPolicy(1, 0.0)


# -- results -----------------------------------------------------------------


def provenance(**overrides: object) -> Provenance:
    defaults: dict[str, object] = {
        "adapter_id": "dns_public",
        "adapter_version": "1.0.0",
        "collected_at": NOW,
    }
    defaults.update(overrides)
    return Provenance(**defaults)  # type: ignore[arg-type]


def test_non_ok_results_must_carry_a_reason_code() -> None:
    for status in (
        CollectionStatus.UNAVAILABLE,
        CollectionStatus.ERROR,
        CollectionStatus.DENIED,
        CollectionStatus.NOT_APPLICABLE,
    ):
        with pytest.raises(AdapterError) as error:
            CollectionResult(status, provenance())
        assert error.value.reason == "reason_code_required"


def test_partial_results_must_explain_what_is_missing() -> None:
    with pytest.raises(AdapterError) as error:
        CollectionResult(CollectionStatus.PARTIAL, provenance(), reason_code="timeout")
    assert error.value.reason == "partial_reasons_required"

    partial = CollectionResult(
        CollectionStatus.PARTIAL,
        provenance(),
        reason_code="timeout",
        partial_reasons=("caa_timeout",),
    )
    assert partial.usable is True


def test_unavailable_result_is_not_usable_evidence() -> None:
    unavailable = CollectionResult(
        CollectionStatus.UNAVAILABLE, provenance(), reason_code="adapter_unconfigured"
    )
    assert unavailable.usable is False


def test_naive_timestamps_are_rejected_everywhere() -> None:
    with pytest.raises(AdapterError):
        provenance(collected_at=datetime(2026, 8, 5, 12, 0))  # noqa: DTZ001
    with pytest.raises(AdapterError):
        HealthReport(HealthState.HEALTHY, "ok", datetime(2026, 8, 5, 12, 0))  # noqa: DTZ001


def test_provenance_age_prefers_observation_time_over_collection_time() -> None:
    observed = datetime.now(UTC) - timedelta(days=2)
    record = provenance(collected_at=datetime.now(UTC), observed_at=observed)
    assert record.age_seconds >= timedelta(days=2).total_seconds() - 5


# -- registry ----------------------------------------------------------------


def test_registry_rejects_duplicate_adapter_ids() -> None:
    registry = AdapterRegistry()
    registry.register(StubAdapter(descriptor(), HealthState.HEALTHY))
    with pytest.raises(AdapterError) as error:
        registry.register(StubAdapter(descriptor(), HealthState.HEALTHY))
    assert error.value.reason == "duplicate_adapter_id"


def test_unknown_adapter_lookup_is_an_explicit_error() -> None:
    with pytest.raises(AdapterError) as error:
        AdapterRegistry().get("missing")
    assert error.value.reason == "unknown_adapter"


def test_unconfigured_paid_adapter_stays_registered_and_reports_unconfigured() -> None:
    registry = AdapterRegistry()
    free = descriptor()
    paid = descriptor(
        adapter_id="passive_intel",
        group=AdapterGroup.PASSIVE_ASSET_INTELLIGENCE,
        cost_unit=CostUnit.QUERY,
        required_secrets=frozenset({"SIEMBIOT_PASSIVE_INTEL_TOKEN"}),
    )
    registry.register(StubAdapter(free, HealthState.HEALTHY))
    registry.register(StubAdapter(paid, HealthState.UNCONFIGURED))

    assert len(registry) == 2
    assert {adapter.descriptor.adapter_id for adapter in registry.keyless()} == {"dns_public"}
    assert registry.health_snapshot()["passive_intel"] is HealthState.UNCONFIGURED
    assert registry.configured({}) == registry.keyless()
    configured = registry.configured({"SIEMBIOT_PASSIVE_INTEL_TOKEN": "value"})
    assert {adapter.descriptor.adapter_id for adapter in configured} == {
        "dns_public",
        "passive_intel",
    }


def test_registry_indexes_by_group_and_capability() -> None:
    registry = AdapterRegistry()
    registry.register(StubAdapter(descriptor(), HealthState.HEALTHY))
    registry.register(
        StubAdapter(
            descriptor(
                adapter_id="tls_collector",
                group=AdapterGroup.TLS_HTTP,
                capabilities=frozenset({"tls.certificate", "tls.protocols"}),
            ),
            HealthState.HEALTHY,
        )
    )
    assert len(registry.by_group(AdapterGroup.TLS_HTTP)) == 1
    assert len(registry.by_capability("tls.certificate")) == 1
    assert registry.by_capability("nonexistent") == ()


def test_descriptor_is_immutable_and_copies_explicitly() -> None:
    original = descriptor()
    with pytest.raises(AttributeError):
        original.version = "9.9.9"  # type: ignore[misc]
    assert replace(original, version="1.1.0").version == "1.1.0"
