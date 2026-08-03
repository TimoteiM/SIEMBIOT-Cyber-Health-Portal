from __future__ import annotations

from datetime import datetime

from siembiot_worker.evidence.models import ScoreAttribution, ScoreSnapshot


def attribute_score_change(
    current: ScoreSnapshot,
    previous: ScoreSnapshot | None,
    *,
    created_at: datetime,
) -> tuple[ScoreAttribution, ...]:
    if previous is not None and (
        current.organization_id != previous.organization_id
        or current.asset_id != previous.asset_id
        or current.mode is not previous.mode
    ):
        raise ValueError("mixed_attribution_inputs")
    reasons: list[tuple[str, str, float, dict[str, object]]] = []
    old_posture = previous.technical_posture if previous else None
    delta = (current.technical_posture or 0) - (old_posture or 0)
    if previous is None or current.policy_hash != previous.policy_hash:
        reasons.append(
            ("methodology", "policy_changed", delta, {"policy_hash": current.policy_hash})
        )
    if previous is None or current.evaluation_ids != previous.evaluation_ids:
        reasons.append(
            ("evidence", "evidence_changed", delta, {"evaluation_ids": current.evaluation_ids})
        )
    if previous is None or current.coverage != previous.coverage:
        reasons.append(
            (
                "coverage",
                "coverage_changed",
                current.coverage - (previous.coverage if previous else 0),
                {},
            )
        )
    if previous is None or (
        current.evidence_confidence != previous.evidence_confidence
        or current.attribution_confidence != previous.attribution_confidence
    ):
        reasons.append(
            (
                "confidence",
                "confidence_changed",
                0,
                {
                    "evidence_confidence": current.evidence_confidence,
                    "attribution_confidence": current.attribution_confidence,
                },
            )
        )
    return tuple(
        ScoreAttribution.build(
            organization_id=current.organization_id,
            asset_id=current.asset_id,
            snapshot_id=current.snapshot_id,
            previous_snapshot_id=previous.snapshot_id if previous else None,
            attribution_type=kind,
            reason_code=reason,
            delta=value,
            details=details,
            created_at=created_at,
        )
        for kind, reason, value, details in reasons
    )
