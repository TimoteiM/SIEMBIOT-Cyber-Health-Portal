from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FindingResponse(StrictModel):
    id: UUID
    asset_id: UUID
    check_id: str
    evidence_mode: Literal["fixture", "live"]
    severity: Literal["info", "low", "medium", "high", "critical"]
    first_seen_at: datetime
    publishable: bool
    classification: Literal["DEMO/FIXTURE", "PRIVATE"]
    state: str | None
    review_due: bool


class FindingEventCreate(StrictModel):
    event_type: Literal["suppressed", "accepted_risk", "reopened", "remediation_verified"]
    reason: str = Field(min_length=10, max_length=1000)
    review_at: datetime | None = None

    @model_validator(mode="after")
    def require_review(self) -> FindingEventCreate:
        if self.event_type in {"suppressed", "accepted_risk"} and self.review_at is None:
            raise ValueError("decision_review_required")
        if self.review_at is not None and self.review_at.utcoffset() is None:
            raise ValueError("timezone_aware_timestamp_required")
        return self


class FindingEventResponse(StrictModel):
    id: UUID
    finding_id: UUID
    event_type: str
    actor_id: UUID
    reason: str
    scope_reference: str
    occurred_at: datetime
    review_at: datetime | None
    request_id: str
    correlation_id: str


class ScoreSnapshotResponse(StrictModel):
    id: UUID
    asset_id: UUID
    evidence_mode: Literal["fixture", "live"]
    methodology_version: str
    technical_posture: float | None
    coverage: float
    evidence_confidence: float
    attribution_confidence: float
    publishable: bool
    classification: Literal["DEMO/FIXTURE", "PRIVATE"]
    created_at: datetime


class CheckEvaluationResponse(StrictModel):
    id: UUID
    asset_id: UUID
    check_id: str
    evidence_mode: Literal["fixture", "live"]
    methodology_version: str
    scoring_behavior_version: str
    outcome: str
    reason_code: str
    evaluated_at: datetime
    publishable: bool


class EvidenceExportResponse(StrictModel):
    contract_version: Literal["v1"] = "v1"
    organization_id: UUID
    evidence_mode: Literal["fixture"]
    classification: Literal["DEMO/FIXTURE"]
    publishable: Literal[False]
    disclaimer: Literal["Fixture-only demonstration; not a live internet assessment."]
    snapshot_count: int
    finding_count: int
