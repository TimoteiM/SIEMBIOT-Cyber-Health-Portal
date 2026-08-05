from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from siembiot_worker.adapters.catalog import (
    ALL_DESCRIPTORS,
    CORE_CAPABILITIES,
    KEYLESS_DESCRIPTORS,
    OPT_IN_DESCRIPTORS,
    descriptor_health,
    keyless_capabilities,
)
from siembiot_worker.adapters.contract import CostUnit, DataClassification, HealthState

ROOT = Path(__file__).resolve().parents[2]


def test_core_capabilities_are_available_without_any_provider_key() -> None:
    assert CORE_CAPABILITIES <= keyless_capabilities()


def test_no_keyless_adapter_requires_a_secret_or_costs_money() -> None:
    for descriptor in KEYLESS_DESCRIPTORS:
        assert descriptor.required_secrets == frozenset()
        assert descriptor.cost_unit is CostUnit.NONE


def test_paid_adapters_are_catalogued_even_when_unconfigured() -> None:
    for descriptor in OPT_IN_DESCRIPTORS:
        assert descriptor_health(descriptor, {}) is HealthState.UNCONFIGURED
        assert descriptor in ALL_DESCRIPTORS


def test_configured_paid_adapter_becomes_healthy() -> None:
    descriptor = OPT_IN_DESCRIPTORS[0]
    secrets = dict.fromkeys(descriptor.required_secrets, "value")
    assert descriptor_health(descriptor, secrets) is HealthState.HEALTHY


def test_blank_secret_does_not_count_as_configured() -> None:
    descriptor = OPT_IN_DESCRIPTORS[0]
    secrets = dict.fromkeys(descriptor.required_secrets, "")
    assert descriptor_health(descriptor, secrets) is HealthState.UNCONFIGURED


def test_restricted_provider_data_never_comes_from_a_keyless_adapter() -> None:
    for descriptor in KEYLESS_DESCRIPTORS:
        assert descriptor.data_classification is DataClassification.PUBLIC_OBSERVATION


def test_adapter_ids_and_capabilities_are_unique_across_the_catalog() -> None:
    identifiers = [descriptor.adapter_id for descriptor in ALL_DESCRIPTORS]
    assert len(identifiers) == len(set(identifiers))
    assert identifiers == sorted(identifiers)


def test_every_adapter_supports_fixtures_so_tests_never_need_a_real_provider() -> None:
    assert all(descriptor.supports_fixtures for descriptor in ALL_DESCRIPTORS)


def test_provider_matrix_document_is_not_stale() -> None:
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(ROOT / "scripts" / "generate_provider_matrix.py"), "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
