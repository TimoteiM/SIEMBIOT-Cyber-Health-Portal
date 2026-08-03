from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from siembiot_worker.collection.models import ObservationOutcome
from siembiot_worker.evaluation.policy import CheckDefinition, PolicyCatalog
from siembiot_worker.evaluation.rules import evaluate_rule
from siembiot_worker.evidence.models import (
    CheckEvaluation,
    EvaluationOutcome,
    EvidenceMode,
    NormalizedObservation,
)


@dataclass(frozen=True)
class EvaluationContext:
    evaluated_at: datetime


def _evaluate_observation(
    check: CheckDefinition, item: NormalizedObservation
) -> tuple[EvaluationOutcome, str]:
    transport = {
        ObservationOutcome.ERROR: EvaluationOutcome.ERROR,
        ObservationOutcome.UNKNOWN: EvaluationOutcome.UNKNOWN,
        ObservationOutcome.UNAVAILABLE: EvaluationOutcome.UNKNOWN,
        ObservationOutcome.DISABLED_BY_POLICY: EvaluationOutcome.UNKNOWN,
    }.get(item.source_outcome)
    if transport is not None:
        return (
            transport,
            "source_error" if transport is EvaluationOutcome.ERROR else "source_unknown",
        )
    return evaluate_rule(check.result_rule, item.payload)


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
        sorted(
            (item for item in observations if item.observation_type == check.observation_type),
            key=lambda item: item.normalized_id,
        )
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
        results = tuple(_evaluate_observation(check, item) for item in matches)
        priority = {
            EvaluationOutcome.ERROR: 0,
            EvaluationOutcome.FAIL: 1,
            EvaluationOutcome.WARNING: 2,
            EvaluationOutcome.UNKNOWN: 3,
            EvaluationOutcome.NOT_APPLICABLE: 4,
            EvaluationOutcome.PASS: 5,
        }
        outcome, reason = min(results, key=lambda result: priority[result[0]])
        evidence_ids = tuple(sorted(item.normalized_id for item in matches))
        source_confidence = min(item.source_confidence for item in matches)
        attribution_confidence = min(item.attribution_confidence for item in matches)
        ages = tuple((context.evaluated_at - item.observed_at).total_seconds() for item in matches)
        future = any(age < 0 for age in ages)
        fresh = not future and all(age <= check.freshness_seconds for age in ages)
        if future:
            outcome, reason = EvaluationOutcome.ERROR, "future_evidence"
        elif not fresh:
            outcome, reason = EvaluationOutcome.UNKNOWN, "stale_evidence"
        disagreement = len({result[0] for result in results}) > 1 or any(
            item.payload.get("provider_disagreement") is True for item in matches
        )
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
