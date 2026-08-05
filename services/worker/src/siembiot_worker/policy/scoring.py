"""The scoring engine.

Pure arithmetic over evaluations. Given the same evaluations and the same catalog it
returns the same snapshot, always. A cap can only lower a score and must name the
checks that triggered it. Missing data reduces coverage; it never becomes a factor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from siembiot_worker.policy.catalog import (
    COVERAGE_REDUCING_RESULTS,
    SCORE_BEARING_RESULTS,
    Pillar,
    PolicyCatalog,
    Result,
)
from siembiot_worker.policy.evidence import (
    CheckEvaluation,
    Confidence,
    ConfidenceLevel,
    NormalizedObservation,
    evidence_digest,
)

INSUFFICIENT_COVERAGE = "insufficient_coverage"


@dataclass(frozen=True)
class Contribution:
    check_id: str
    result: str
    weight: float
    factor: float | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "result": self.result,
            "weight": self.weight,
            "factor": self.factor,
        }


@dataclass(frozen=True)
class PillarScore:
    pillar: Pillar
    weight: float
    score: float | None
    scored_checks: int
    excluded_checks: int
    contributions: tuple[Contribution, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "pillar": str(self.pillar),
            "weight": self.weight,
            "score": self.score,
            "scored_checks": self.scored_checks,
            "excluded_checks": self.excluded_checks,
            "contributions": [item.as_dict() for item in self.contributions],
        }


@dataclass(frozen=True)
class AppliedCap:
    cap_id: str
    ceiling: float
    triggering_check_ids: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "cap_id": self.cap_id,
            "ceiling": self.ceiling,
            "triggering_check_ids": list(self.triggering_check_ids),
        }


@dataclass(frozen=True)
class Coverage:
    percentage: float
    completed_weight: float
    applicable_weight: float
    sufficient: bool
    undetermined_checks: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "percentage": self.percentage,
            "completed_weight": self.completed_weight,
            "applicable_weight": self.applicable_weight,
            "sufficient": self.sufficient,
            "undetermined_checks": list(self.undetermined_checks),
        }


@dataclass(frozen=True)
class ScoreSnapshot:
    snapshot_id: UUID
    organization_id: UUID
    assessment_id: UUID
    methodology_version: str
    policy_digest: str
    evidence_digest: str
    coverage: Coverage
    pillars: tuple[PillarScore, ...]
    uncapped_score: float | None
    score: float | None
    band: str
    caps_applied: tuple[AppliedCap, ...]
    confidence: Confidence
    computed_at: datetime
    is_projection: bool = False
    _high_minimum: float = field(default=0.8, repr=False)
    _medium_minimum: float = field(default=0.5, repr=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract_version": "v1",
            "snapshot_id": str(self.snapshot_id),
            "organization_id": str(self.organization_id),
            "assessment_id": str(self.assessment_id),
            "methodology_version": self.methodology_version,
            "is_projection": self.is_projection,
            "policy_digest": self.policy_digest,
            "evidence_digest": self.evidence_digest,
            "coverage": self.coverage.as_dict(),
            "pillars": [item.as_dict() for item in self.pillars],
            "overall": {
                "uncapped_score": self.uncapped_score,
                "score": self.score,
                "band": self.band,
                "caps_applied": [item.as_dict() for item in self.caps_applied],
            },
            "confidence": self.confidence.as_dict(self._high_minimum, self._medium_minimum),
            "computed_at": self.computed_at.isoformat().replace("+00:00", "Z"),
        }


def _round(value: float) -> float:
    """One decimal place, so a snapshot serializes and compares byte-identically."""
    return round(value + 0.0, 1)


def score_pillar(
    pillar: Pillar,
    weight: float,
    evaluations: tuple[CheckEvaluation, ...],
    catalog: PolicyCatalog,
) -> PillarScore:
    factors = catalog.methodology.result_factors
    contributions: list[Contribution] = []
    numerator = 0.0
    denominator = 0.0
    scored = 0
    excluded = 0
    for evaluation in sorted(evaluations, key=lambda item: item.check_id):
        result = Result(evaluation.result)
        if result in SCORE_BEARING_RESULTS:
            factor = factors[result]
            numerator += evaluation.weight * factor
            denominator += evaluation.weight
            scored += 1
            contributions.append(
                Contribution(evaluation.check_id, evaluation.result, evaluation.weight, factor)
            )
            continue
        excluded += 1
        contributions.append(
            Contribution(evaluation.check_id, evaluation.result, evaluation.weight, None)
        )
    score = None if denominator == 0 else _round(100.0 * numerator / denominator)
    return PillarScore(pillar, weight, score, scored, excluded, tuple(contributions))


def compute_coverage(evaluations: tuple[CheckEvaluation, ...], catalog: PolicyCatalog) -> Coverage:
    """Applicable weight excludes not-applicable; unknown and error reduce completion."""
    applicable = 0.0
    completed = 0.0
    undetermined: list[str] = []
    for evaluation in evaluations:
        result = Result(evaluation.result)
        if result is Result.NOT_APPLICABLE:
            continue
        applicable += evaluation.weight
        if result in COVERAGE_REDUCING_RESULTS:
            undetermined.append(evaluation.check_id)
            continue
        completed += evaluation.weight
    percentage = 0.0 if applicable == 0 else _round(100.0 * completed / applicable)
    sufficient = percentage >= catalog.methodology.minimum_coverage_percentage
    return Coverage(percentage, completed, applicable, sufficient, tuple(sorted(undetermined)))


def roll_up_confidence(evaluations: tuple[CheckEvaluation, ...]) -> Confidence:
    """Take the weakest dimension across scored checks; strengths never mask a weakness."""
    scored = [item for item in evaluations if Result(item.result) in SCORE_BEARING_RESULTS]
    if not scored:
        return Confidence(1.0, 1.0, 1.0, ("no_scored_checks",))
    combined = scored[0].confidence
    for evaluation in scored[1:]:
        combined = combined.combine(evaluation.confidence)
    return combined


def applicable_caps(
    evaluations: tuple[CheckEvaluation, ...], catalog: PolicyCatalog
) -> tuple[AppliedCap, ...]:
    """A cap fires only on a failing, high-confidence, directly attributable check."""
    methodology = catalog.methodology
    by_check = {item.check_id: item for item in evaluations}
    applied: list[AppliedCap] = []
    for cap in methodology.caps:
        triggering: list[str] = []
        for check_id in sorted(cap.check_ids):
            evaluation = by_check.get(check_id)
            if evaluation is None or Result(evaluation.result) is not Result.FAIL:
                continue
            level = evaluation.confidence.level(
                methodology.high_confidence_minimum, methodology.medium_confidence_minimum
            )
            if cap.requires_confidence == "high" and level is not ConfidenceLevel.HIGH:
                continue
            triggering.append(check_id)
        if triggering:
            applied.append(AppliedCap(cap.cap_id, cap.ceiling, tuple(triggering)))
    return tuple(sorted(applied, key=lambda item: item.cap_id))


def compute_score(
    catalog: PolicyCatalog,
    evaluations: tuple[CheckEvaluation, ...],
    observations: tuple[NormalizedObservation, ...],
    *,
    snapshot_id: UUID,
    organization_id: UUID,
    assessment_id: UUID,
    computed_at: datetime,
    is_projection: bool = False,
) -> ScoreSnapshot:
    methodology = catalog.methodology
    pillars: list[PillarScore] = []
    for pillar, weight in sorted(methodology.pillar_weights.items(), key=lambda item: item[0]):
        pillar_evaluations = tuple(item for item in evaluations if item.pillar is pillar)
        pillars.append(score_pillar(pillar, weight, pillar_evaluations, catalog))

    scored_pillars = [item for item in pillars if item.score is not None]
    total_weight = sum(item.weight for item in scored_pillars)
    uncapped = (
        None
        if total_weight == 0
        else _round(
            sum(item.weight * (item.score or 0.0) for item in scored_pillars) / total_weight
        )
    )

    coverage = compute_coverage(evaluations, catalog)
    caps = applicable_caps(evaluations, catalog)

    # Caps apply regardless of coverage; insufficient coverage changes only the band,
    # so an authorized reader still sees the number but is told not to trust its precision.
    if uncapped is None:
        final: float | None = None
        band = INSUFFICIENT_COVERAGE
    else:
        capped = uncapped
        for cap in caps:
            capped = min(capped, cap.ceiling)
        final = _round(capped)
        band = methodology.band_for(final) if coverage.sufficient else INSUFFICIENT_COVERAGE

    return ScoreSnapshot(
        snapshot_id=snapshot_id,
        organization_id=organization_id,
        assessment_id=assessment_id,
        methodology_version=methodology.version,
        policy_digest=catalog.digest,
        evidence_digest=evidence_digest(observations),
        coverage=coverage,
        pillars=tuple(pillars),
        uncapped_score=uncapped,
        score=final,
        band=band,
        caps_applied=caps,
        confidence=roll_up_confidence(evaluations),
        computed_at=computed_at,
        is_projection=is_projection,
        _high_minimum=methodology.high_confidence_minimum,
        _medium_minimum=methodology.medium_confidence_minimum,
    )
