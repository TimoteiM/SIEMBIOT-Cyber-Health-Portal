from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from siembiot_worker.evidence.canonical import canonical_hash


class FindingEventType(StrEnum):
    OBSERVED = "observed"
    SUPPRESSED = "suppressed"
    ACCEPTED_RISK = "accepted_risk"
    REOPENED = "reopened"
    EXPIRED_REVIEW = "expired_review"
    REMEDIATION_VERIFIED = "remediation_verified"


class FindingEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: Literal["v1"] = "v1"
    event_id: str = Field(pattern=r"^sha256-v1:[a-f0-9]{64}$")
    finding_id: str = Field(pattern=r"^sha256-v1:[a-f0-9]{64}$")
    organization_id: str
    event_type: FindingEventType
    actor_id: str
    reason: str = Field(min_length=10, max_length=1000)
    scope_reference: str
    occurred_at: datetime
    review_at: datetime | None = None
    request_id: str
    correlation_id: str
    audit_event_id: str

    @model_validator(mode="after")
    def validate_event(self) -> FindingEvent:
        if self.occurred_at.utcoffset() is None:
            raise ValueError("timezone_aware_timestamp_required")
        if self.event_type in {FindingEventType.SUPPRESSED, FindingEventType.ACCEPTED_RISK}:
            if self.review_at is None or self.review_at <= self.occurred_at:
                raise ValueError("decision_review_required")
        if self.review_at is not None and self.review_at.utcoffset() is None:
            raise ValueError("timezone_aware_timestamp_required")
        if self.event_id != canonical_hash(self.model_dump(mode="python", exclude={"event_id"})):
            raise ValueError("finding_event_id_mismatch")
        return self

    @classmethod
    def build(cls, *, authorized: bool, **values: Any) -> FindingEvent:
        if not authorized:
            raise ValueError("finding_event_not_authorized")
        draft = cls.model_construct(event_id="sha256-v1:" + "0" * 64, **values)
        values["event_id"] = canonical_hash(draft.model_dump(mode="python", exclude={"event_id"}))
        return cls.model_validate(values)
