from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from siembiot_worker.evidence.canonical import CanonicalizationError, canonical_hash, parse_json


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
    content_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    observation_type: str
    pillar: str
    weight: float
    severity: Literal["info", "low", "medium", "high", "critical"]
    freshness_seconds: int = Field(gt=0)
    remediation: str
    references: tuple[str, ...]
    public_classification: Literal["public_aggregate", "public_profile", "private_only"]
    result_rule: Literal[
        "boolean_secure",
        "policy_strength",
        "header_present",
        "attribution_review",
        "provider_signal",
        "registration_freshness",
    ]
    critical_cap: int | None = None
    required_cap_evidence: int | None = Field(default=None, ge=1, le=10)
    required_cap_observation_type: str | None = None
    cap_requires_authorized_asset: bool | None = None


@dataclass(frozen=True)
class PolicyCatalog:
    methodology_version: str
    scoring_behavior_version: str
    minimum_coverage: float
    pillars: Mapping[str, Pillar]
    checks: tuple[CheckDefinition, ...]
    policy_hash: str


def _read(path: Path) -> Any:
    try:
        return parse_json(path.read_text(encoding="utf-8"))
    except (OSError, CanonicalizationError) as exc:
        raise PolicyValidationError("invalid_policy_json") from exc


def load_policy_catalog(path: Path) -> PolicyCatalog:
    methodology = _read(path / "methodology.json")
    references_data = _read(path / "references.json")
    stable_ids = _read(path / "stable-ids.json")
    if methodology.get("schema_version") != "v1":
        raise PolicyValidationError("unsupported_methodology_schema")
    for version_field in ("methodology_version", "scoring_behavior_version"):
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(methodology.get(version_field))) is None:
            raise PolicyValidationError("invalid_methodology_version")
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
        if file.name in {"methodology.json", "references.json", "stable-ids.json"}:
            continue
        document = _read(file)
        if (
            re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(document.get("policy_content_version")))
            is None
        ):
            raise PolicyValidationError("invalid_policy_content_version")
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
        cap_fields = (
            check.required_cap_evidence,
            check.required_cap_observation_type,
            check.cap_requires_authorized_asset,
        )
        if check.critical_cap is None and any(item is not None for item in cap_fields):
            raise PolicyValidationError("invalid_cap_evidence_requirement")
        if check.critical_cap is not None and (
            check.required_cap_evidence is None
            or check.required_cap_observation_type != check.observation_type
            or check.cap_requires_authorized_asset is not True
        ):
            raise PolicyValidationError("invalid_cap_evidence_requirement")
        identifiers.add(check.check_id)
        stable = stable_ids.get("checks", {}).get(check.check_id)
        if (
            stable is None
            or stable.get("observation_type") != check.observation_type
            or stable.get("pillar") != check.pillar
            or stable.get("result_rule") != check.result_rule
        ):
            raise PolicyValidationError("stable_check_id_repurposed")
        checks.append(check)
    if set(item.pillar for item in checks) != set(pillar_map):
        raise PolicyValidationError("missing_pillar_check")
    if identifiers != set(stable_ids.get("checks", {})):
        raise PolicyValidationError("stable_check_id_history_mismatch")
    identity = {
        "methodology": methodology,
        "references": references_data,
        "stable_ids": stable_ids,
        "checks": raw_checks,
    }
    return PolicyCatalog(
        methodology["methodology_version"],
        methodology["scoring_behavior_version"],
        float(methodology["minimum_coverage"]),
        MappingProxyType(pillar_map),
        tuple(sorted(checks, key=lambda item: item.check_id)),
        canonical_hash(identity),
    )
