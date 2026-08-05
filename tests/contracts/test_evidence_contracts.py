"""The engines' real output must validate against the published evidence schemas.

These are not schema-shape tests; they feed genuine engine output through the
contracts so the two cannot drift apart.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "packages" / "contracts" / "jsonschema" / "evidence" / "v1"
REFERENCE_SNAPSHOT = ROOT / "docs" / "methodology" / "v1" / "reference-snapshot.json"


def load_validator(name: str) -> Draft202012Validator:
    """Resolve sibling $ref files from the same directory."""
    registry = Registry()
    for path in SCHEMAS.glob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        registry = registry.with_resource(
            path.name, Resource.from_contents(document, default_specification=DRAFT202012)
        )
    schema = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=registry)


@pytest.fixture(scope="module")
def snapshot_document() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(REFERENCE_SNAPSHOT.read_text(encoding="utf-8"))
    document.pop("evaluations", None)
    return document


def test_every_evidence_schema_is_itself_valid() -> None:
    for path in SCHEMAS.glob("*.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)


def test_reference_snapshot_validates_against_the_published_schema(
    snapshot_document: dict[str, Any],
) -> None:
    errors = sorted(
        load_validator("score-snapshot.json").iter_errors(snapshot_document),
        key=lambda error: error.json_path,
    )
    assert errors == [], [f"{error.json_path}: {error.message}" for error in errors]


def test_a_cap_that_raises_a_score_is_representable_only_as_invalid_data(
    snapshot_document: dict[str, Any],
) -> None:
    tampered = json.loads(json.dumps(snapshot_document))
    tampered["overall"]["score"] = 150
    errors = list(load_validator("score-snapshot.json").iter_errors(tampered))
    assert errors


def test_an_unknown_band_is_rejected(snapshot_document: dict[str, Any]) -> None:
    tampered = json.loads(json.dumps(snapshot_document))
    tampered["overall"]["band"] = "excellent"
    assert list(load_validator("score-snapshot.json").iter_errors(tampered))


def test_engine_observations_validate_against_the_observation_schema() -> None:
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    from reproduce_methodology import build_observations  # noqa: PLC0415

    validator = load_validator("normalized-observation.json")
    for observation in build_observations():
        document = {
            "contract_version": "v1",
            "observation_id": str(observation.observation_id),
            "organization_id": str(observation.organization_id),
            "assessment_id": str(observation.assessment_id),
            "subject": observation.subject.as_dict(),
            "observation_type": observation.observation_type,
            "status": str(observation.status),
            "attributes": observation.attributes,
            "provenance": {
                "adapter_id": observation.adapter_id,
                "adapter_version": observation.adapter_version,
                "collected_at": observation.collected_at.isoformat().replace("+00:00", "Z"),
                "observed_at": None,
                "from_cache": observation.from_cache,
                "source_reference": observation.source_reference,
            },
            "confidence": observation.confidence.as_dict(0.8, 0.5),
            "content_hash": observation.content_hash,
        }
        errors = list(validator.iter_errors(document))
        assert errors == [], [
            f"{observation.observation_type} {error.json_path}: {error.message}" for error in errors
        ]


def test_engine_findings_validate_against_the_finding_schema() -> None:
    import sys
    from datetime import UTC, datetime
    from uuid import uuid4

    sys.path.insert(0, str(ROOT / "services" / "worker" / "src"))
    from siembiot_worker.policy.catalog import Result, load_catalog  # noqa: PLC0415
    from siembiot_worker.policy.evidence import (  # noqa: PLC0415
        CheckEvaluation,
        Confidence,
        Subject,
        SubjectKind,
    )
    from siembiot_worker.policy.findings import derive_findings  # noqa: PLC0415

    catalog = load_catalog()
    now = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
    organization_id, assessment_id = uuid4(), uuid4()
    subject = Subject(SubjectKind.DOMAIN, "reference.example.test")
    check = catalog.by_id("A.dnssec_enabled")
    evaluation = CheckEvaluation(
        evaluation_id=uuid4(),
        organization_id=organization_id,
        assessment_id=assessment_id,
        check_id=check.check_id,
        check_version=check.version,
        methodology_version=catalog.methodology.version,
        pillar=check.pillar,
        subject=subject,
        result=str(Result.FAIL),
        weight=check.weight,
        severity=str(check.severity),
        confidence=Confidence(1.0, 1.0, 1.0),
        observation_ids=(uuid4(),),
        reason_code="dnssec_absent",
        evaluated_at=now,
    )
    findings = derive_findings(
        catalog,
        [evaluation],
        organization_id=organization_id,
        assessment_id=assessment_id,
        observed_at=now,
    )
    validator = load_validator("finding.json")
    for finding in findings:
        errors = list(validator.iter_errors(finding.as_dict(0.8, 0.5)))
        assert errors == [], [f"{error.json_path}: {error.message}" for error in errors]


def test_check_ids_in_the_catalog_match_the_contract_pattern() -> None:
    import re
    import sys

    sys.path.insert(0, str(ROOT / "services" / "worker" / "src"))
    from siembiot_worker.policy.catalog import load_catalog  # noqa: PLC0415

    schema = json.loads((SCHEMAS / "check-evaluation.json").read_text(encoding="utf-8"))
    pattern = re.compile(schema["properties"]["check_id"]["pattern"])
    for check in load_catalog().checks:
        assert pattern.match(check.check_id), check.check_id
