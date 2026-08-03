from __future__ import annotations

import pytest
from siembiot_worker.adapters.registry import AdapterRegistry, RegistryError

from .test_contract import descriptor


def test_registry_is_deny_by_default_for_capabilities() -> None:
    registry = AdapterRegistry()
    registry.register(descriptor())
    assert registry.require("fixture-dns", "dns.lookup").adapter_id == "fixture-dns"
    with pytest.raises(RegistryError, match="capability_not_declared"):
        registry.require("fixture-dns", "http.head")
    with pytest.raises(RegistryError, match="adapter_not_registered"):
        registry.require("missing", "dns.lookup")


def test_registry_rejects_duplicate_adapter_identity() -> None:
    registry = AdapterRegistry()
    registry.register(descriptor())
    with pytest.raises(RegistryError, match="duplicate_adapter"):
        registry.register(descriptor())
