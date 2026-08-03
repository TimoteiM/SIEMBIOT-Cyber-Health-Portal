from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from siembiot_worker.collection.immutability import deep_freeze, json_compatible
from siembiot_worker.collection.models import ObservationOutcome
from siembiot_worker.evidence.canonical import canonical_hash


class EvidenceMode(StrEnum):
    FIXTURE = "fixture"
    LIVE = "live"


class EvaluationOutcome(StrEnum):
    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    WARNING = "warning"
    UNKNOWN = "unknown"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"
    SUPPRESSED = "suppressed"
    ACCEPTED_RISK = "accepted_risk"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Provenance(StrictModel):
    collector_id: str = Field(pattern=r"^[a-z][a-z0-9._-]{1,63}$")
    collector_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    adapter_id: str = Field(pattern=r"^[a-z][a-z0-9._-]{1,63}$")
    adapter_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    normalizer_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    scenario_id: str | None = Field(default=None, min_length=1, max_length=128)
    scenario_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class NormalizedObservation(StrictModel):
    contract_version: Literal["v1"] = "v1"
    canonicalization_version: Literal["canonical-json-v1"] = "canonical-json-v1"
    hash_version: Literal["sha256-v1"] = "sha256-v1"
    normalized_id: str = Field(pattern=r"^sha256-v1:[a-f0-9]{64}$")
    organization_id: str = Field(min_length=1, max_length=64)
    asset_id: str = Field(min_length=1, max_length=64)
    scope_reference: str = Field(min_length=1, max_length=256)
    source_evidence_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    observation_type: str = Field(pattern=r"^[a-z][a-z0-9._-]{1,127}$")
    source_outcome: ObservationOutcome
    observed_at: datetime
    mode: Literal[EvidenceMode.FIXTURE]
    provenance: Provenance
    payload: Mapping[str, Any]
    source_confidence: float = Field(ge=0, le=1)
    attribution_confidence: float = Field(ge=0, le=1)
    freshness_seconds: int = Field(ge=0)
    publishable: Literal[False]
    real_world: Literal[False]

    def identity(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "organization_id": self.organization_id,
            "asset_id": self.asset_id,
            "scope_reference": self.scope_reference,
            "source_evidence_id": self.source_evidence_id,
            "observation_type": self.observation_type,
            "source_outcome": (
                self.source_outcome.value
                if isinstance(self.source_outcome, ObservationOutcome)
                else str(self.source_outcome)
            ),
            "observed_at": self.observed_at,
            "mode": self.mode.value if isinstance(self.mode, EvidenceMode) else str(self.mode),
            "provenance": self.provenance.model_dump(mode="json"),
            "payload": json_compatible(self.payload),
            "source_confidence": self.source_confidence,
            "attribution_confidence": self.attribution_confidence,
            "freshness_seconds": self.freshness_seconds,
        }

    @model_validator(mode="after")
    def validate_identity(self) -> NormalizedObservation:
        if self.observed_at.utcoffset() is None:
            raise ValueError("timezone_aware_timestamp_required")
        if self.provenance.scenario_id is None or self.provenance.scenario_sha256 is None:
            raise ValueError("fixture_provenance_required")
        if self.normalized_id != canonical_hash(self.identity()):
            raise ValueError("normalized_id_mismatch")
        object.__setattr__(self, "payload", deep_freeze(self.payload))
        return self

    @classmethod
    def build(cls, **values: Any) -> NormalizedObservation:
        draft = cls.model_construct(normalized_id="sha256-v1:" + "0" * 64, **values)
        values["normalized_id"] = canonical_hash(draft.identity())
        return cls.model_validate(values)


class CheckEvaluation(StrictModel):
    contract_version: Literal["v1"] = "v1"
    evaluation_id: str = Field(pattern=r"^sha256-v1:[a-f0-9]{64}$")
    organization_id: str
    asset_id: str
    check_id: str
    policy_hash: str = Field(pattern=r"^sha256-v1:[a-f0-9]{64}$")
    methodology_version: str
    scoring_behavior_version: str
    mode: EvidenceMode
    outcome: EvaluationOutcome
    evidence_ids: tuple[str, ...]
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    evaluated_at: datetime
    source_confidence: float = Field(ge=0, le=1)
    attribution_confidence: float = Field(ge=0, le=1)
    fresh: bool
    directly_attributable: bool
    provider_disagreement: bool
    publishable: bool

    def identity(self) -> dict[str, Any]:
        return self.model_dump(mode="python", exclude={"evaluation_id"})

    @model_validator(mode="after")
    def validate_evaluation(self) -> CheckEvaluation:
        if self.evaluated_at.utcoffset() is None:
            raise ValueError("timezone_aware_timestamp_required")
        if self.mode is EvidenceMode.FIXTURE and self.publishable:
            raise ValueError("fixture_evaluation_boundary")
        if self.evaluation_id != canonical_hash(self.identity()):
            raise ValueError("evaluation_id_mismatch")
        return self

    @classmethod
    def build(cls, **values: Any) -> CheckEvaluation:
        draft = cls.model_construct(evaluation_id="sha256-v1:" + "0" * 64, **values)
        values["evaluation_id"] = canonical_hash(draft.identity())
        return cls.model_validate(values)


class ScoreSnapshot(StrictModel):
    contract_version: Literal["v1"] = "v1"
    snapshot_id: str = Field(pattern=r"^sha256-v1:[a-f0-9]{64}$")
    organization_id: str
    asset_id: str
    policy_hash: str = Field(pattern=r"^sha256-v1:[a-f0-9]{64}$")
    methodology_version: str
    scoring_behavior_version: str
    mode: EvidenceMode
    evaluation_ids: tuple[str, ...]
    pillar_scores: Mapping[str, float | None]
    technical_posture: float | None = Field(default=None, ge=0, le=100)
    coverage: float = Field(ge=0, le=100)
    evidence_confidence: float = Field(ge=0, le=1)
    attribution_confidence: float = Field(ge=0, le=1)
    caps_applied: tuple[str, ...] = ()
    created_at: datetime
    publishable: bool
    classification: str

    @model_validator(mode="after")
    def validate_snapshot(self) -> ScoreSnapshot:
        if self.created_at.utcoffset() is None:
            raise ValueError("timezone_aware_timestamp_required")
        if self.mode is EvidenceMode.FIXTURE and (
            self.publishable or self.classification != "DEMO/FIXTURE"
        ):
            raise ValueError("fixture_snapshot_boundary")
        identity = self.model_dump(mode="python", exclude={"snapshot_id"})
        if self.snapshot_id != canonical_hash(identity):
            raise ValueError("snapshot_id_mismatch")
        object.__setattr__(self, "pillar_scores", deep_freeze(self.pillar_scores))
        return self

    @classmethod
    def build(cls, **values: Any) -> ScoreSnapshot:
        draft = cls.model_construct(snapshot_id="sha256-v1:" + "0" * 64, **values)
        values["snapshot_id"] = canonical_hash(
            draft.model_dump(mode="python", exclude={"snapshot_id"})
        )
        return cls.model_validate(values)


class ScoreAttribution(StrictModel):
    contract_version: Literal["v1"] = "v1"
    attribution_id: str = Field(pattern=r"^sha256-v1:[a-f0-9]{64}$")
    organization_id: str
    asset_id: str
    snapshot_id: str = Field(pattern=r"^sha256-v1:[a-f0-9]{64}$")
    previous_snapshot_id: str | None = Field(default=None, pattern=r"^sha256-v1:[a-f0-9]{64}$")
    attribution_type: Literal["evidence", "methodology", "applicability", "coverage", "confidence"]
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    delta: float
    details: Mapping[str, Any]
    created_at: datetime

    @model_validator(mode="after")
    def validate_attribution(self) -> ScoreAttribution:
        if self.created_at.utcoffset() is None:
            raise ValueError("timezone_aware_timestamp_required")
        identity = self.model_dump(mode="python", exclude={"attribution_id"})
        if self.attribution_id != canonical_hash(identity):
            raise ValueError("attribution_id_mismatch")
        object.__setattr__(self, "details", deep_freeze(self.details))
        return self

    @classmethod
    def build(cls, **values: Any) -> ScoreAttribution:
        draft = cls.model_construct(attribution_id="sha256-v1:" + "0" * 64, **values)
        values["attribution_id"] = canonical_hash(
            draft.model_dump(mode="python", exclude={"attribution_id"})
        )
        return cls.model_validate(values)


class Finding(StrictModel):
    contract_version: Literal["v1"] = "v1"
    finding_id: str = Field(pattern=r"^sha256-v1:[a-f0-9]{64}$")
    fingerprint_version: Literal["fingerprint-v1"] = "fingerprint-v1"
    organization_id: str
    asset_id: str
    scope_reference: str
    check_id: str
    policy_hash: str = Field(pattern=r"^sha256-v1:[a-f0-9]{64}$")
    mode: EvidenceMode
    severity: Literal["info", "low", "medium", "high", "critical"]
    attribution_state: Literal["direct", "shared_hosting", "uncertain"]
    first_seen_at: datetime
    publishable: bool
    classification: Literal["DEMO/FIXTURE", "PRIVATE"]

    @model_validator(mode="after")
    def fixture_boundary(self) -> Finding:
        if self.first_seen_at.utcoffset() is None:
            raise ValueError("timezone_aware_timestamp_required")
        if self.mode is EvidenceMode.FIXTURE and (
            self.publishable or self.classification != "DEMO/FIXTURE"
        ):
            raise ValueError("fixture_finding_boundary")
        return self
