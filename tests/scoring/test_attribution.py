from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from siembiot_worker.evaluation.policy import load_policy_catalog
from siembiot_worker.evidence.models import (
    CheckEvaluation,
    EvaluationOutcome,
    EvidenceMode,
    ScoreSnapshot,
)
from siembiot_worker.scoring.attribution import attribute_score_change
from siembiot_worker.scoring.engine import score_evaluations

ROOT = Path(__file__).resolve().parents[2]
CATALOG = load_policy_catalog(ROOT / "packages/policy/checks/v1")
NOW = datetime(2026, 8, 3, tzinfo=UTC)


def _snapshot(outcome: EvaluationOutcome) -> ScoreSnapshot:
    evaluations = tuple(
        CheckEvaluation.build(
            organization_id="org-a",
            asset_id="asset-a",
            check_id=check.check_id,
            policy_hash=CATALOG.policy_hash,
            methodology_version=CATALOG.methodology_version,
            scoring_behavior_version=CATALOG.scoring_behavior_version,
            mode=EvidenceMode.FIXTURE,
            outcome=outcome,
            evidence_ids=("sha256-v1:" + check.check_id.encode().hex().ljust(64, "0")[:64],),
            evidence_types=(check.observation_type,),
            reason_code="rule_result",
            evaluated_at=NOW,
            source_confidence=1,
            attribution_confidence=1,
            fresh=True,
            directly_attributable=True,
            provider_disagreement=False,
            asset_authorized=True,
            publishable=False,
        )
        for check in CATALOG.checks
    )
    return score_evaluations(evaluations, CATALOG, created_at=NOW)


def test_score_changes_have_stable_typed_attribution() -> None:
    previous, current = _snapshot(EvaluationOutcome.FAIL), _snapshot(EvaluationOutcome.PASS)
    first = attribute_score_change(current, previous, created_at=NOW)
    assert first == attribute_score_change(current, previous, created_at=NOW)
    assert {item.attribution_type for item in first} == {"evidence"}
    assert first[0].delta > 0
