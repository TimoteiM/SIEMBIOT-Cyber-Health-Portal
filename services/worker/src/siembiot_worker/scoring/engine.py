from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from siembiot_worker.evaluation.policy import CheckDefinition, PolicyCatalog
from siembiot_worker.evidence.models import (
    CheckEvaluation,
    EvaluationOutcome,
    EvidenceMode,
    ScoreSnapshot,
)

_FACTORS = {
    EvaluationOutcome.PASS: 1.0,
    EvaluationOutcome.WARNING: 0.5,
    EvaluationOutcome.FAIL: 0.0,
    EvaluationOutcome.SUPPRESSED: 0.0,
    EvaluationOutcome.ACCEPTED_RISK: 0.0,
}


def _round(value: float) -> float:
    return round(value, 6)


def _effective_weights(catalog: PolicyCatalog) -> dict[str, float]:
    totals: dict[str, float] = defaultdict(float)
    for check in catalog.checks:
        totals[check.pillar] += check.weight
    return {
        check.check_id: catalog.pillars[check.pillar].weight * check.weight / totals[check.pillar]
        for check in catalog.checks
    }


def _eligible_cap(check: CheckDefinition, evaluation: CheckEvaluation) -> bool:
    return (
        check.critical_cap is not None
        and evaluation.outcome is EvaluationOutcome.FAIL
        and evaluation.mode is EvidenceMode.LIVE
        and evaluation.fresh
        and evaluation.directly_attributable
        and evaluation.source_confidence >= 0.8
        and evaluation.attribution_confidence >= 0.8
        and not evaluation.provider_disagreement
    )


def score_evaluations(
    evaluations: tuple[CheckEvaluation, ...],
    catalog: PolicyCatalog,
    *,
    created_at: datetime,
) -> ScoreSnapshot:
    if not evaluations:
        raise ValueError("empty_evaluation_set")
    ordered = tuple(sorted(evaluations, key=lambda item: item.check_id))
    first = ordered[0]
    if any(
        item.organization_id != first.organization_id
        or item.asset_id != first.asset_id
        or item.mode is not first.mode
        or item.policy_hash != catalog.policy_hash
        or item.methodology_version != catalog.methodology_version
        for item in ordered
    ):
        raise ValueError("mixed_score_inputs")
    by_id = {item.check_id: item for item in ordered}
    if len(by_id) != len(ordered) or any(
        item not in {c.check_id for c in catalog.checks} for item in by_id
    ):
        raise ValueError("invalid_evaluation_set")
    weights = _effective_weights(catalog)
    applicable = [
        check
        for check in catalog.checks
        if by_id.get(check.check_id) is None
        or by_id[check.check_id].outcome is not EvaluationOutcome.NOT_APPLICABLE
    ]
    applicable_weight = sum(weights[check.check_id] for check in applicable)
    completed = [
        check
        for check in applicable
        if by_id.get(check.check_id) is not None and by_id[check.check_id].outcome in _FACTORS
    ]
    completed_weight = sum(weights[check.check_id] for check in completed)
    coverage = 100 if not applicable else 100 * completed_weight / applicable_weight
    pillar_scores: dict[str, float | None] = {}
    for pillar in catalog.pillars:
        checks = [check for check in completed if check.pillar == pillar]
        denominator = sum(check.weight for check in checks)
        pillar_scores[pillar] = (
            _round(
                100
                * sum(check.weight * _FACTORS[by_id[check.check_id].outcome] for check in checks)
                / denominator
            )
            if denominator
            else None
        )
    posture: float | None = None
    if coverage >= 60 and completed_weight:
        posture = _round(
            100
            * sum(
                weights[check.check_id] * _FACTORS[by_id[check.check_id].outcome]
                for check in completed
            )
            / completed_weight
        )
    caps = tuple(
        check.check_id
        for check in catalog.checks
        if check.check_id in by_id and _eligible_cap(check, by_id[check.check_id])
    )
    if posture is not None and caps:
        posture = min(
            posture,
            min(
                check.critical_cap
                for check in catalog.checks
                if check.check_id in caps and check.critical_cap is not None
            ),
        )
    confidence_items = [by_id[check.check_id] for check in completed]
    evidence_confidence = min((item.source_confidence for item in confidence_items), default=0)
    attribution_confidence = min(
        (item.attribution_confidence for item in confidence_items), default=0
    )
    return ScoreSnapshot.build(
        organization_id=first.organization_id,
        asset_id=first.asset_id,
        policy_hash=catalog.policy_hash,
        methodology_version=catalog.methodology_version,
        scoring_behavior_version=catalog.scoring_behavior_version,
        mode=first.mode,
        evaluation_ids=tuple(sorted(item.evaluation_id for item in ordered)),
        pillar_scores=pillar_scores,
        technical_posture=posture,
        coverage=_round(coverage),
        evidence_confidence=evidence_confidence,
        attribution_confidence=attribution_confidence,
        caps_applied=tuple(sorted(caps)),
        created_at=created_at,
        publishable=first.mode is EvidenceMode.LIVE,
        classification="PRIVATE" if first.mode is EvidenceMode.LIVE else "DEMO/FIXTURE",
    )
