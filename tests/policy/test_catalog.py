from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from siembiot_worker.evaluation.policy import PolicyValidationError, load_policy_catalog

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "packages/policy/checks/v1"


def test_catalog_is_versioned_complete_and_content_addressed() -> None:
    catalog = load_policy_catalog(CATALOG)
    assert catalog.methodology_version == "1.0.0"
    assert catalog.policy_hash.startswith("sha256-v1:")
    assert len(catalog.pillars) == 6
    assert {check.pillar for check in catalog.checks} == set(catalog.pillars)
    assert all(check.remediation and check.references for check in catalog.checks)


def mutated_catalog(tmp_path: Path) -> Path:
    target = tmp_path / "v1"
    shutil.copytree(CATALOG, target)
    return target


def update_first_check(path: Path, **changes: object) -> None:
    file = path / "domain-dns.json"
    payload = json.loads(file.read_text(encoding="utf-8"))
    payload["checks"][0].update(changes)
    file.write_text(json.dumps(payload), encoding="utf-8")


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"schema_version": "v9"}, "unsupported_check_schema"),
        ({"remediation": ""}, "missing_remediation"),
        ({"references": ["missing"]}, "invalid_reference"),
        ({"weight": 0}, "invalid_weight"),
    ],
)
def test_catalog_rejects_invalid_check_definitions(
    tmp_path: Path, changes: dict[str, object], reason: str
) -> None:
    path = mutated_catalog(tmp_path)
    update_first_check(path, **changes)
    with pytest.raises(PolicyValidationError, match=reason):
        load_policy_catalog(path)


def test_catalog_rejects_duplicate_stable_ids(tmp_path: Path) -> None:
    path = mutated_catalog(tmp_path)
    first = json.loads((path / "domain-dns.json").read_text(encoding="utf-8"))["checks"][0]
    file = path / "email-trust.json"
    payload = json.loads(file.read_text(encoding="utf-8"))
    payload["checks"].append(first)
    file.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(PolicyValidationError, match="duplicate_check_id"):
        load_policy_catalog(path)


def test_catalog_rejects_inconsistent_pillar_weights(tmp_path: Path) -> None:
    path = mutated_catalog(tmp_path)
    file = path / "methodology.json"
    payload = json.loads(file.read_text(encoding="utf-8"))
    payload["pillars"][0]["weight"] = 0.9
    file.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(PolicyValidationError, match="invalid_pillar_weights"):
        load_policy_catalog(path)
