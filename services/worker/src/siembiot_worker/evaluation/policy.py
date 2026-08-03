from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from siembiot_worker.evidence.canonical import canonical_hash


class PolicyValidationError(ValueError):
    pass


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Pillar(_Strict):
    id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    weight: float = Field(gt=0, le=1)


class CheckDefinition(_Strict):
    schema_version: str
    check_id: str = Field(pattern=r"^[a-z][a-z0-9._-]{2,127}$")
    content_version: str
    observation_type: str
    pillar: str
    weight: float
    severity: str
    freshness_seconds: int = Field(gt=0)
    remediation: str
    references: tuple[str, ...]
    public_classification: str
    result_rule: str
    critical_cap: int | None = None


@dataclass(frozen=True)
class PolicyCatalog:
    methodology_version: str
    scoring_behavior_version: str
    pillars: dict[str, Pillar]
    checks: tuple[CheckDefinition, ...]
    policy_hash: str


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyValidationError("invalid_policy_json") from exc


def load_policy_catalog(path: Path) -> PolicyCatalog:
    methodology = _read(path / "methodology.json")
    references_data = _read(path / "references.json")
    if methodology.get("schema_version") != "v1":
        raise PolicyValidationError("unsupported_methodology_schema")
    try:
        pillars = tuple(Pillar.model_validate(item) for item in methodology["pillars"])
    except (KeyError, TypeError, ValidationError) as exc:
        raise PolicyValidationError("invalid_pillar") from exc
    if abs(sum(item.weight for item in pillars) - 1) > 0.000001:
        raise PolicyValidationError("invalid_pillar_weights")
    pillar_map = {item.id: item for item in pillars}
    references = {item["id"] for item in references_data.get("references", [])}
    raw_checks: list[dict[str, Any]] = []
    for file in sorted(path.glob("*.json")):
        if file.name in {"methodology.json", "references.json"}:
            continue
        document = _read(file)
        raw_checks.extend(document.get("checks", []))
    checks: list[CheckDefinition] = []
    identifiers: set[str] = set()
    for raw in raw_checks:
        if raw.get("schema_version") != "v1":
            raise PolicyValidationError("unsupported_check_schema")
        if not isinstance(raw.get("remediation"), str) or not raw["remediation"].strip():
            raise PolicyValidationError("missing_remediation")
        if not isinstance(raw.get("weight"), int | float) or raw["weight"] <= 0:
            raise PolicyValidationError("invalid_weight")
        if not raw.get("references") or any(item not in references for item in raw["references"]):
            raise PolicyValidationError("invalid_reference")
        try:
            check = CheckDefinition.model_validate(raw)
        except ValidationError as exc:
            raise PolicyValidationError("invalid_check") from exc
        if check.check_id in identifiers:
            raise PolicyValidationError("duplicate_check_id")
        if check.pillar not in pillar_map:
            raise PolicyValidationError("invalid_check_pillar")
        identifiers.add(check.check_id)
        checks.append(check)
    if set(item.pillar for item in checks) != set(pillar_map):
        raise PolicyValidationError("missing_pillar_check")
    identity = {"methodology": methodology, "references": references_data, "checks": raw_checks}
    return PolicyCatalog(
        methodology["methodology_version"],
        methodology["scoring_behavior_version"],
        pillar_map,
        tuple(sorted(checks, key=lambda item: item.check_id)),
        canonical_hash(identity),
    )
