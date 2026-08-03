from __future__ import annotations

import pytest
from pydantic import ValidationError
from siembiot_worker.adapters.contracts import AdapterDescriptor


def descriptor(**overrides: object) -> AdapterDescriptor:
    values: dict[str, object] = {
        "adapter_id": "fixture-dns",
        "adapter_version": "1.0.0",
        "capabilities": ("dns.lookup",),
        "terms_note": "Local deterministic fixtures only",
        "input_classification": "public_metadata",
        "output_classification": "public_metadata",
        "required_secret_names": (),
        "health_semantics": "deterministic_fixture",
        "timeout_seconds": 1.0,
        "rate_unit": "request",
        "cost_unit": "none",
        "cache_ttl_seconds": 0,
        "fixture_support": True,
        "output_schema": "collection.observation.v1",
        "retries_allowed": False,
    }
    values.update(overrides)
    return AdapterDescriptor.model_validate(values)


def test_descriptor_requires_complete_typed_metadata() -> None:
    model = descriptor()
    assert model.fixture_support
    assert model.required_secret_names == ()
    assert model.capabilities == ("dns.lookup",)


def test_fixture_adapter_cannot_require_provider_secrets() -> None:
    with pytest.raises(ValidationError, match="fixture_adapter_requires_no_secrets"):
        descriptor(required_secret_names=("PROVIDER_TOKEN",))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("capabilities", ()),
        ("terms_note", ""),
        ("timeout_seconds", 0),
        ("output_schema", "unversioned"),
        ("fixture_support", False),
    ],
)
def test_invalid_or_non_fixture_descriptors_are_rejected(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        descriptor(**{field: value})
