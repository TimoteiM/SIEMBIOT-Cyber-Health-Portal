from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from siembiot_worker.collection.models import ObservationOutcome
from siembiot_worker.evaluation.policy import CheckDefinition, PolicyCatalog
from siembiot_worker.evidence.models import (
    CheckEvaluation,
    EvaluationOutcome,
    EvidenceMode,
    NormalizedObservation,
)


@dataclass(frozen=True)
class EvaluationContext:
    evaluated_at: datetime


def _source_outcome(item: NormalizedObservation) -> EvaluationOutcome:
    return {
        ObservationOutcome.PASS: EvaluationOutcome.PASS,
        ObservationOutcome.FAIL: EvaluationOutcome.FAIL,
        ObservationOutcome.WARNING: EvaluationOutcome.WARNING,
        ObservationOutcome.ERROR: EvaluationOutcome.ERROR,
        ObservationOutcome.UNKNOWN: EvaluationOutcome.UNKNOWN,
        ObservationOutcome.UNAVAILABLE: EvaluationOutcome.UNKNOWN,
        ObservationOutcome.DISABLED_BY_POLICY: EvaluationOutcome.UNKNOWN,
    }[item.source_outcome]


def evaluate_check(
    check: CheckDefinition,
    observations: tuple[NormalizedObservation, ...],
    catalog: PolicyCatalog,
    context: EvaluationContext,
    *,
    organization_id: str | None = None,
    asset_id: str | None = None,
    mode: str | EvidenceMode | None = None,
) -> CheckEvaluation:
    evidence_mode: EvidenceMode
    matches = tuple(
        item for item in observations if item.observation_type == check.observation_type
    )
    if matches:
        organization_id = matches[0].organization_id
        asset_id = matches[0].asset_id
        evidence_mode = matches[0].mode
        if any(
            item.organization_id != organization_id
            or item.asset_id != asset_id
            or item.mode is not evidence_mode
            for item in matches
        ):
            raise ValueError("mixed_evaluation_inputs")
        outcome = _source_outcome(matches[0])
        reason = "source_outcome"
        evidence_ids = tuple(sorted(item.normalized_id for item in matches))
        source_confidence = min(item.source_confidence for item in matches)
        attribution_confidence = min(item.attribution_confidence for item in matches)
        fresh = all(
            (context.evaluated_at - item.observed_at).total_seconds() <= check.freshness_seconds
            for item in matches
        )
        disagreement = any(item.payload.get("provider_disagreement") is True for item in matches)
    else:
        if organization_id is None or asset_id is None or mode is None:
            raise ValueError("missing_evaluation_identity")
        evidence_mode = EvidenceMode(mode)
        outcome, reason, evidence_ids = EvaluationOutcome.UNKNOWN, "missing_evidence", ()
        source_confidence = attribution_confidence = 0
        fresh = disagreement = False
    return CheckEvaluation.build(
        organization_id=organization_id,
        asset_id=asset_id,
        check_id=check.check_id,
        policy_hash=catalog.policy_hash,
        methodology_version=catalog.methodology_version,
        scoring_behavior_version=catalog.scoring_behavior_version,
        mode=evidence_mode,
        outcome=outcome,
        evidence_ids=evidence_ids,
        reason_code=reason,
        evaluated_at=context.evaluated_at,
        source_confidence=source_confidence,
        attribution_confidence=attribution_confidence,
        fresh=fresh,
        directly_attributable=attribution_confidence >= 0.8,
        provider_disagreement=disagreement,
        publishable=evidence_mode is EvidenceMode.LIVE,
    )
