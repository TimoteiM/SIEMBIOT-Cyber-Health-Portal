from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypedDict, cast

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError
from siembiot_worker.collection.models import (
    CollectionObservation,
    ExecutionMode,
    ObservationOutcome,
    build_fixture_observation,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "packages" / "contracts" / "jsonschema" / "collection" / "v1"


class FixtureObservationArguments(TypedDict):
    scope_reference: str
    collector_id: str
    collector_version: str
    adapter_id: str
    adapter_version: str
    collected_at: datetime
    scenario_id: str
    scenario_sha256: str
    outcome: ObservationOutcome
    payload: dict[str, Any]


def validate(name: str, payload: dict[str, Any]) -> None:
    schema = cast(
        dict[str, Any],
        json.loads((SCHEMAS / f"{name}.json").read_text(encoding="utf-8")),
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(payload)


def fixture_payload() -> dict[str, Any]:
    return build_fixture_observation(
        scope_reference="018f5f80-8a4b-7c1b-b55e-ea65c9126205",
        collector_id="dns",
        collector_version="1.0.0",
        adapter_id="fixture-dns",
        adapter_version="1.0.0",
        collected_at=datetime(2026, 8, 3, 12, tzinfo=UTC),
        scenario_id="healthy.test",
        scenario_sha256="b" * 64,
        outcome=ObservationOutcome.PASS,
        payload={"record_type": "NS", "values": ["ns1.healthy.test"]},
    ).model_dump(mode="json")


@pytest.mark.parametrize("name", ["observation", "run-summary", "adapter-manifest"])
def test_versioned_collection_schemas_exist_and_are_valid(name: str) -> None:
    payload = fixture_payload()
    if name == "run-summary":
        payload = {
            "contract_version": "v1",
            "run_id": "018f5f80-8a4b-7c1b-b55e-ea65c9126206",
            "execution_mode": "fixture",
            "status": "completed",
            "fixture_only": True,
            "publishable": False,
            "observation_ids": ["sha256:" + "a" * 64],
            "banner": "FIXTURE DATA — NOT A LIVE ASSESSMENT",
        }
    elif name == "adapter-manifest":
        payload = {
            "contract_version": "v1",
            "adapter_id": "fixture-dns",
            "adapter_version": "1.0.0",
            "capabilities": ["dns.lookup"],
            "terms_note": "Local deterministic fixtures only",
            "input_classification": "public_metadata",
            "output_classification": "public_metadata",
            "required_secret_names": [],
            "health_semantics": "deterministic",
            "timeout_seconds": 1.0,
            "rate_unit": "request",
            "cost_unit": "none",
            "cache_ttl_seconds": 0,
            "fixture_support": True,
            "output_schema": "collection.observation.v1",
        }
    validate(name, payload)


def test_fixture_observation_cannot_be_relabelled_or_published() -> None:
    valid = fixture_payload()
    observation = CollectionObservation.model_validate(valid)
    assert observation.execution_mode is ExecutionMode.FIXTURE
    for field, value in (("publishable", True), ("real_world", True)):
        invalid = {**valid, field: value}
        with pytest.raises(ValidationError):
            CollectionObservation.model_validate(invalid)


@pytest.mark.parametrize("mode", ["unavailable", "disabled_by_policy", "live"])
def test_milestone_3_observation_schema_rejects_non_fixture_modes(mode: str) -> None:
    invalid = {**fixture_payload(), "execution_mode": mode, "scenario": None}
    with pytest.raises(Exception):
        validate("observation", invalid)
    with pytest.raises(ValidationError):
        CollectionObservation.model_validate(invalid)


def test_fixture_evidence_identifier_is_deterministic_and_provenance_bound() -> None:
    collected_at = datetime(2026, 8, 3, 12, tzinfo=UTC)
    arguments: FixtureObservationArguments = {
        "scope_reference": "018f5f80-8a4b-7c1b-b55e-ea65c9126205",
        "collector_id": "dns",
        "collector_version": "1.0.0",
        "adapter_id": "fixture-dns",
        "adapter_version": "1.0.0",
        "collected_at": collected_at,
        "scenario_id": "healthy.test",
        "scenario_sha256": "b" * 64,
        "outcome": ObservationOutcome.PASS,
        "payload": {"values": ["ns1.healthy.test"]},
    }
    first = build_fixture_observation(**arguments)
    second = build_fixture_observation(**arguments)
    changed_arguments = arguments.copy()
    changed_arguments["collector_version"] = "1.0.1"
    changed = build_fixture_observation(**changed_arguments)
    assert first == second
    assert first.evidence_id.startswith("sha256:")
    assert first.evidence_id != changed.evidence_id
    assert not first.publishable
    assert not first.real_world
