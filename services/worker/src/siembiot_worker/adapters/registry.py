from __future__ import annotations

from siembiot_worker.adapters.contracts import AdapterDescriptor


class RegistryError(LookupError):
    pass


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, AdapterDescriptor] = {}

    def register(self, descriptor: AdapterDescriptor) -> None:
        if descriptor.adapter_id in self._adapters:
            raise RegistryError("duplicate_adapter")
        self._adapters[descriptor.adapter_id] = descriptor

    def require(self, adapter_id: str, capability: str) -> AdapterDescriptor:
        descriptor = self._adapters.get(adapter_id)
        if descriptor is None:
            raise RegistryError("adapter_not_registered")
        if capability not in descriptor.capabilities:
            raise RegistryError("capability_not_declared")
        return descriptor

    @property
    def descriptors(self) -> tuple[AdapterDescriptor, ...]:
        return tuple(self._adapters[key] for key in sorted(self._adapters))
