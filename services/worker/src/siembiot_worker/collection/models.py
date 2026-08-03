from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExecutionMode(StrEnum):
    FIXTURE = "fixture"
    UNAVAILABLE = "unavailable"
    DISABLED_BY_POLICY = "disabled_by_policy"
    LIVE = "live"


class ObservationOutcome(StrEnum):
    PASS = "pass"  # noqa: S105 - assessment outcome, not a credential
    FAIL = "fail"
    WARNING = "warning"
    UNKNOWN = "unknown"
    ERROR = "error"
    UNAVAILABLE = "unavailable"
    DISABLED_BY_POLICY = "disabled_by_policy"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ComponentIdentity(StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9._-]{1,63}$")
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")


class FixtureScenario(StrictModel):
    id: str = Field(min_length=1, max_length=128)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class CollectionObservation(StrictModel):
    contract_version: Literal["v1"] = "v1"
    evidence_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    scope_reference: str = Field(min_length=1, max_length=256)
    collector: ComponentIdentity
    adapter: ComponentIdentity
    collected_at: datetime
    execution_mode: ExecutionMode
    scenario: FixtureScenario | None = None
    classification: Literal["public_metadata", "private_metadata", "sensitive"]
    outcome: ObservationOutcome
    confidence: float = Field(ge=0, le=1)
    freshness_seconds: int = Field(ge=0)
    publishable: bool
    real_world: bool
    payload: dict[str, Any]

    @model_validator(mode="after")
    def enforce_fixture_boundary(self) -> CollectionObservation:
        if self.execution_mode is ExecutionMode.FIXTURE:
            if self.scenario is None or self.publishable or self.real_world:
                raise ValueError("fixture_observation_boundary")
        return self


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def build_fixture_observation(
    *,
    scope_reference: str,
    collector_id: str,
    collector_version: str,
    adapter_id: str,
    adapter_version: str,
    collected_at: datetime,
    scenario_id: str,
    scenario_sha256: str,
    outcome: ObservationOutcome,
    payload: dict[str, Any],
    classification: Literal["public_metadata", "private_metadata", "sensitive"] = "public_metadata",
    confidence: float = 1.0,
    freshness_seconds: int = 0,
) -> CollectionObservation:
    identity = {
        "scope_reference": scope_reference,
        "collector": {"id": collector_id, "version": collector_version},
        "adapter": {"id": adapter_id, "version": adapter_version},
        "collected_at": collected_at.isoformat(),
        "execution_mode": ExecutionMode.FIXTURE.value,
        "scenario": {"id": scenario_id, "sha256": scenario_sha256},
        "classification": classification,
        "outcome": outcome.value,
        "confidence": confidence,
        "freshness_seconds": freshness_seconds,
        "payload": payload,
    }
    evidence_id = "sha256:" + hashlib.sha256(_canonical_json(identity)).hexdigest()
    return CollectionObservation(
        evidence_id=evidence_id,
        scope_reference=scope_reference,
        collector=ComponentIdentity(id=collector_id, version=collector_version),
        adapter=ComponentIdentity(id=adapter_id, version=adapter_version),
        collected_at=collected_at,
        execution_mode=ExecutionMode.FIXTURE,
        scenario=FixtureScenario(id=scenario_id, sha256=scenario_sha256),
        classification=classification,
        outcome=outcome,
        confidence=confidence,
        freshness_seconds=freshness_seconds,
        publishable=False,
        real_world=False,
        payload=payload,
    )
