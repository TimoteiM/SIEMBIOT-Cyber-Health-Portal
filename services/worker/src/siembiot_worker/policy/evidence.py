"""Evidence value objects.

A NormalizedObservation is immutable and content-addressed: identical evidence always
hashes identically, which is what makes a score reproducible.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from siembiot_worker.policy.catalog import Pillar


class EvidenceError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ObservationStatus(StrEnum):
    OBSERVED = "observed"
    ABSENT = "absent"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"


class SubjectKind(StrEnum):
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    MX_HOST = "mx_host"
    URL = "url"
    IP_ADDRESS = "ip_address"
    CERTIFICATE = "certificate"


class ConfidenceLevel(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Subject:
    kind: SubjectKind
    identifier: str
    authorized_domain_id: UUID | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"kind": str(self.kind), "identifier": self.identifier}
        if self.authorized_domain_id is not None:
            payload["authorized_domain_id"] = str(self.authorized_domain_id)
        return payload


@dataclass(frozen=True)
class Confidence:
    attribution: float
    source: float
    freshness: float
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for value in (self.attribution, self.source, self.freshness):
            if not 0.0 <= value <= 1.0:
                raise EvidenceError("confidence_out_of_range")

    @property
    def weakest(self) -> float:
        """The roll-up takes the minimum: one weak dimension is never averaged away."""
        return min(self.attribution, self.source, self.freshness)

    def level(self, high_minimum: float, medium_minimum: float) -> ConfidenceLevel:
        weakest = self.weakest
        if weakest >= high_minimum:
            return ConfidenceLevel.HIGH
        if weakest >= medium_minimum:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    def combine(self, other: Confidence) -> Confidence:
        return Confidence(
            min(self.attribution, other.attribution),
            min(self.source, other.source),
            min(self.freshness, other.freshness),
            tuple(sorted(set(self.reasons) | set(other.reasons))),
        )

    def as_dict(self, high_minimum: float, medium_minimum: float) -> dict[str, Any]:
        return {
            "attribution": self.attribution,
            "source": self.source,
            "freshness": self.freshness,
            "level": str(self.level(high_minimum, medium_minimum)),
            "reasons": list(self.reasons),
        }


FULL_CONFIDENCE = Confidence(1.0, 1.0, 1.0)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


@dataclass(frozen=True)
class NormalizedObservation:
    observation_id: UUID
    organization_id: UUID
    assessment_id: UUID
    subject: Subject
    observation_type: str
    status: ObservationStatus
    attributes: dict[str, Any] = field(default_factory=dict)
    confidence: Confidence = FULL_CONFIDENCE
    adapter_id: str = "unknown"
    adapter_version: str = "0.0.0"
    collected_at: datetime = datetime(1970, 1, 1, tzinfo=UTC)
    observed_at: datetime | None = None
    from_cache: bool = False
    source_reference: str | None = None

    def __post_init__(self) -> None:
        if self.collected_at.tzinfo is None:
            raise EvidenceError("naive_timestamp")
        if self.status is not ObservationStatus.OBSERVED and self.attributes:
            allowed = {"reason", "detail", "status_detail"}
            if not set(self.attributes) <= allowed:
                raise EvidenceError("non_observed_status_carries_attributes")

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(
            canonical_bytes(
                {
                    "subject": self.subject.as_dict(),
                    "observation_type": self.observation_type,
                    "status": str(self.status),
                    "attributes": self.attributes,
                }
            )
        ).hexdigest()

    @property
    def is_conclusive(self) -> bool:
        return self.status in {ObservationStatus.OBSERVED, ObservationStatus.ABSENT}

    def age_seconds(self, now: datetime) -> float:
        reference = self.observed_at or self.collected_at
        return max(0.0, (now - reference).total_seconds())

    def is_stale(self, now: datetime, window_seconds: int) -> bool:
        return self.age_seconds(now) > window_seconds


@dataclass(frozen=True)
class CheckEvaluation:
    evaluation_id: UUID
    organization_id: UUID
    assessment_id: UUID
    check_id: str
    check_version: str
    methodology_version: str
    pillar: Pillar
    subject: Subject
    result: str
    weight: float
    severity: str
    confidence: Confidence
    observation_ids: tuple[UUID, ...] = ()
    reason_code: str | None = None
    evaluated_at: datetime = datetime(1970, 1, 1, tzinfo=UTC)

    @property
    def score_bearing(self) -> bool:
        return self.result in {"pass", "warning", "fail"}


def evidence_digest(observations: tuple[NormalizedObservation, ...]) -> str:
    """Digest of the exact evidence set, so a snapshot can prove what it scored."""
    return hashlib.sha256(
        canonical_bytes(sorted(observation.content_hash for observation in observations))
    ).hexdigest()
