"""Adapter registry.

Registration is the only way an adapter becomes reachable, and an adapter whose
secrets are absent stays registered and reports ``unconfigured`` rather than
disappearing — a missing provider must surface as unknown, never as a passing check.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping

from siembiot_worker.adapters.contract import (
    AdapterDescriptor,
    AdapterError,
    AdapterGroup,
    HealthState,
    ProviderAdapter,
)


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, ProviderAdapter] = {}

    def register(self, adapter: ProviderAdapter) -> None:
        descriptor = adapter.descriptor
        if descriptor.adapter_id in self._adapters:
            raise AdapterError("duplicate_adapter_id")
        self._adapters[descriptor.adapter_id] = adapter

    def get(self, adapter_id: str) -> ProviderAdapter:
        adapter = self._adapters.get(adapter_id)
        if adapter is None:
            raise AdapterError("unknown_adapter")
        return adapter

    def __iter__(self) -> Iterator[ProviderAdapter]:
        return iter(self._adapters.values())

    def __len__(self) -> int:
        return len(self._adapters)

    @property
    def descriptors(self) -> tuple[AdapterDescriptor, ...]:
        return tuple(adapter.descriptor for adapter in self._adapters.values())

    def by_group(self, group: AdapterGroup) -> tuple[ProviderAdapter, ...]:
        return tuple(
            adapter for adapter in self._adapters.values() if adapter.descriptor.group is group
        )

    def by_capability(self, capability: str) -> tuple[ProviderAdapter, ...]:
        return tuple(
            adapter
            for adapter in self._adapters.values()
            if capability in adapter.descriptor.capabilities
        )

    def configured(self, secrets: Mapping[str, str]) -> tuple[ProviderAdapter, ...]:
        return tuple(
            adapter
            for adapter in self._adapters.values()
            if all(secrets.get(name) for name in adapter.descriptor.required_secrets)
        )

    def keyless(self) -> tuple[ProviderAdapter, ...]:
        return tuple(
            adapter
            for adapter in self._adapters.values()
            if not adapter.descriptor.requires_configuration
        )

    def health_snapshot(self) -> dict[str, HealthState]:
        return {
            adapter.descriptor.adapter_id: adapter.health().state
            for adapter in self._adapters.values()
        }
