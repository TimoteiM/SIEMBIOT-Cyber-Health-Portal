from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError
from siembiot_worker.evidence.models import (
    EvaluationOutcome,
    EvidenceMode,
    NormalizedObservation,
    Provenance,
)

SCHEMAS = Path(__file__).resolve().parents[2] / "packages/contracts/jsonschema/evidence/v1"


@pytest.mark.parametrize(
    "name",
    [
        "common",
        "normalized-observation",
        "check-evaluation",
        "finding",
        "finding-event",
        "score-snapshot",
        "score-attribution",
    ],
)
def test_evidence_schema_is_valid(name: str) -> None:
    Draft202012Validator.check_schema(json.loads((SCHEMAS / f"{name}.json").read_text()))


def observation(**changes: object) -> NormalizedObservation:
    values: dict[str, object] = {
        "organization_id": "018f5f80-8a4b-7c1b-b55e-ea65c9126201",
        "asset_id": "018f5f80-8a4b-7c1b-b55e-ea65c9126202",
        "scope_reference": "018f5f80-8a4b-7c1b-b55e-ea65c9126203",
        "source_evidence_id": "sha256:" + "a" * 64,
        "observation_type": "dns.nameservers",
        "source_outcome": "pass",
        "observed_at": datetime(2026, 8, 3, 12, tzinfo=UTC),
        "mode": "fixture",
        "provenance": Provenance(
            collector_id="dns",
            collector_version="1.0.0",
            adapter_id="fixture-dns",
            adapter_version="1.0.0",
            normalizer_version="1.0.0",
            scenario_id="healthy",
            scenario_sha256="b" * 64,
        ),
        "payload": {"count": 2},
        "source_confidence": 1,
        "attribution_confidence": 1,
        "freshness_seconds": 0,
        "publishable": False,
        "real_world": False,
    }
    values.update(changes)
    return NormalizedObservation.build(**values)


def test_fixture_mode_is_structural_and_identity_bound() -> None:
    item = observation()
    assert item.mode is EvidenceMode.FIXTURE
    assert item.normalized_id.startswith("sha256-v1:")
    with pytest.raises(ValidationError):
        observation(publishable=True)
    with pytest.raises(ValidationError):
        observation(real_world=True)
    stale = item.model_dump(mode="python")
    stale["payload"] = {"count": 3}
    with pytest.raises(ValidationError, match="normalized_id_mismatch"):
        NormalizedObservation.model_validate(stale)


def test_naive_time_and_live_scenario_are_rejected() -> None:
    with pytest.raises(ValueError):
        observation(observed_at=datetime(2026, 8, 3, 12))
    with pytest.raises(ValidationError):
        observation(mode="live")


def test_all_evaluation_outcomes_remain_distinct() -> None:
    assert {item.value for item in EvaluationOutcome} == {
        "pass",
        "fail",
        "warning",
        "unknown",
        "error",
        "not_applicable",
        "suppressed",
        "accepted_risk",
    }
