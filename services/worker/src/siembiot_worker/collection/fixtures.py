from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, cast

from siembiot_worker.collection.immutability import deep_freeze


class FixtureIntegrityError(ValueError):
    pass


@dataclass(frozen=True)
class FixtureScenario:
    id: str
    timestamp: datetime
    digest: str
    data: Mapping[str, Any]


@dataclass(frozen=True)
class FixtureScenarioPack:
    version: str
    digest: str
    scenarios: tuple[FixtureScenario, ...]

    @classmethod
    def load(cls, root: Path) -> FixtureScenarioPack:
        manifest_path = root / "manifest.json"
        try:
            manifest_bytes = manifest_path.read_bytes()
            manifest = cast(dict[str, Any], json.loads(manifest_bytes))
            version = manifest["version"]
            files = manifest["files"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise FixtureIntegrityError("invalid_fixture_manifest") from exc
        if version != "v1" or not isinstance(files, dict) or not files:
            raise FixtureIntegrityError("invalid_fixture_manifest")

        scenarios: list[FixtureScenario] = []
        digests: list[tuple[str, str]] = []
        for relative, expected_digest in sorted(files.items()):
            if not isinstance(relative, str) or not isinstance(expected_digest, str):
                raise FixtureIntegrityError("invalid_fixture_manifest")
            path = PurePosixPath(relative)
            if path.is_absolute() or ".." in path.parts or path.suffix != ".json":
                raise FixtureIntegrityError("invalid_fixture_path")
            try:
                content = (root / Path(*path.parts)).read_bytes()
            except OSError as exc:
                raise FixtureIntegrityError("fixture_file_missing") from exc
            actual_digest = hashlib.sha256(content).hexdigest()
            if actual_digest != expected_digest:
                raise FixtureIntegrityError("fixture_digest_mismatch")
            digests.append((relative, actual_digest))
            if path.parts[0] != "scenarios":
                continue
            try:
                payload = cast(dict[str, Any], json.loads(content))
                scenario_id = payload["id"]
                timestamp = datetime.fromisoformat(payload["timestamp"].replace("Z", "+00:00"))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                raise FixtureIntegrityError("invalid_fixture_scenario") from exc
            if not isinstance(scenario_id, str) or not scenario_id:
                raise FixtureIntegrityError("invalid_fixture_scenario")
            if timestamp.utcoffset() is None:
                raise FixtureIntegrityError("invalid_fixture_scenario")
            scenarios.append(
                FixtureScenario(
                    scenario_id,
                    timestamp,
                    actual_digest,
                    deep_freeze(payload),
                )
            )
        if len({item.id for item in scenarios}) != len(scenarios):
            raise FixtureIntegrityError("duplicate_scenario_id")
        pack_digest = hashlib.sha256(
            json.dumps(digests, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()
        return cls(version, pack_digest, tuple(scenarios))

    def scenario(self, scenario_id: str) -> FixtureScenario:
        for scenario in self.scenarios:
            if scenario.id == scenario_id:
                return scenario
        raise FixtureIntegrityError("scenario_not_found")
