from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from siembiot_worker.collection.fixtures import FixtureIntegrityError, FixtureScenarioPack


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def write_pack(root: Path, scenarios: dict[str, dict[str, object]]) -> Path:
    scenario_dir = root / "scenarios"
    scenario_dir.mkdir(parents=True)
    files: dict[str, str] = {}
    for name, payload in scenarios.items():
        relative = f"scenarios/{name}.json"
        content = _canonical(payload)
        (root / relative).write_bytes(content)
        files[relative] = hashlib.sha256(content).hexdigest()
    manifest = {"version": "v1", "files": files}
    (root / "manifest.json").write_bytes(_canonical(manifest))
    return root


def test_scenario_pack_validates_manifest_and_has_stable_digest(tmp_path: Path) -> None:
    root = write_pack(
        tmp_path,
        {"healthy": {"id": "healthy", "timestamp": "2026-08-03T12:00:00Z"}},
    )
    first = FixtureScenarioPack.load(root)
    second = FixtureScenarioPack.load(root)
    assert first.digest == second.digest
    assert first.scenario("healthy").timestamp.isoformat() == "2026-08-03T12:00:00+00:00"


def test_scenario_pack_rejects_tampering_and_unknown_scenarios(tmp_path: Path) -> None:
    root = write_pack(
        tmp_path,
        {"healthy": {"id": "healthy", "timestamp": "2026-08-03T12:00:00Z"}},
    )
    (root / "scenarios" / "healthy.json").write_text("{}", encoding="utf-8")
    with pytest.raises(FixtureIntegrityError, match="fixture_digest_mismatch"):
        FixtureScenarioPack.load(root)

    valid = FixtureScenarioPack.load(
        write_pack(
            tmp_path / "valid",
            {"healthy": {"id": "healthy", "timestamp": "2026-08-03T12:00:00Z"}},
        )
    )
    with pytest.raises(FixtureIntegrityError, match="scenario_not_found"):
        valid.scenario("missing")


def test_repository_fake_internet_pack_is_integrity_checked() -> None:
    root = Path(__file__).parent / "fake_internet" / "v1"
    pack = FixtureScenarioPack.load(root)
    assert {scenario.id for scenario in pack.scenarios} >= {
        "healthy",
        "adversarial",
        "partial-failure",
    }
