from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from siembiot_worker.evaluation.policy import CheckDefinition, PolicyCatalog, load_policy_catalog
from siembiot_worker.evidence.models import CheckEvaluation, EvaluationOutcome, EvidenceMode
from siembiot_worker.scoring.engine import score_evaluations

ROOT = Path(__file__).resolve().parents[2]
CATALOG = load_policy_catalog(ROOT / "packages/policy/checks/v1")
NOW = datetime(2026, 8, 3, 13, tzinfo=UTC)


def evaluation(
    check: CheckDefinition,
    outcome: EvaluationOutcome,
    *,
    mode: EvidenceMode = EvidenceMode.FIXTURE,
    **changes: object,
) -> CheckEvaluation:
    values: dict[str, object] = {
        "organization_id": "org-a",
        "asset_id": "asset-a",
        "check_id": check.check_id,
        "policy_hash": CATALOG.policy_hash,
        "methodology_version": CATALOG.methodology_version,
        "scoring_behavior_version": CATALOG.scoring_behavior_version,
        "mode": mode,
        "outcome": outcome,
        "evidence_ids": ("sha256-v1:" + "a" * 64,),
        "evidence_types": (check.observation_type,),
        "reason_code": "source_outcome",
        "evaluated_at": NOW,
        "source_confidence": 1,
        "attribution_confidence": 1,
        "fresh": True,
        "directly_attributable": True,
        "provider_disagreement": False,
        "asset_authorized": True,
        "publishable": mode is EvidenceMode.LIVE,
    }
    values.update(changes)
    return CheckEvaluation.build(**values)


def all_outcomes(outcome: EvaluationOutcome) -> tuple[CheckEvaluation, ...]:
    return tuple(evaluation(check, outcome) for check in CATALOG.checks)


def test_scores_are_reproducible_and_keep_assurance_separate() -> None:
    inputs = all_outcomes(EvaluationOutcome.PASS)
    first = score_evaluations(inputs, CATALOG, created_at=NOW)
    second = score_evaluations(tuple(reversed(inputs)), CATALOG, created_at=NOW)
    assert first == second
    assert first.technical_posture == 100
    assert first.coverage == 100
    assert first.evidence_confidence == 1
    assert first.attribution_confidence == 1
    assert first.mode is EvidenceMode.FIXTURE and not first.publishable


def test_unknown_error_and_missing_reduce_coverage_without_becoming_failure() -> None:
    checks = CATALOG.checks
    inputs = tuple(evaluation(check, EvaluationOutcome.PASS) for check in checks[:4]) + (
        evaluation(checks[4], EvaluationOutcome.UNKNOWN),
    )
    result = score_evaluations(inputs, CATALOG, created_at=NOW)
    assert result.technical_posture == 100
    assert result.coverage == 60
    low = score_evaluations(inputs[:3], CATALOG, created_at=NOW)
    assert low.coverage == 50
    assert low.technical_posture is None


def test_not_applicable_does_not_reduce_coverage() -> None:
    checks = CATALOG.checks
    result = score_evaluations(
        tuple(evaluation(check, EvaluationOutcome.PASS) for check in checks[:-1])
        + (evaluation(checks[-1], EvaluationOutcome.NOT_APPLICABLE),),
        CATALOG,
        created_at=NOW,
    )
    assert result.coverage == 100


def test_monotonicity_holds_under_fixed_assurance_and_applicability() -> None:
    checks = CATALOG.checks
    scores = []
    for outcome in (EvaluationOutcome.FAIL, EvaluationOutcome.WARNING, EvaluationOutcome.PASS):
        inputs = (evaluation(checks[0], outcome),) + tuple(
            evaluation(check, EvaluationOutcome.PASS) for check in checks[1:]
        )
        scores.append(score_evaluations(inputs, CATALOG, created_at=NOW).technical_posture)
    fail_score, warning_score, pass_score = scores
    assert fail_score is not None and warning_score is not None and pass_score is not None
    assert fail_score < warning_score < pass_score


def test_critical_caps_require_eligible_non_fixture_evidence() -> None:
    capped = CATALOG.checks[0].model_copy(
        update={
            "critical_cap": 40,
            "required_cap_evidence": 1,
            "required_cap_observation_type": CATALOG.checks[0].observation_type,
            "cap_requires_authorized_asset": True,
        }
    )
    catalog = PolicyCatalog(
        CATALOG.methodology_version,
        CATALOG.scoring_behavior_version,
        CATALOG.minimum_coverage,
        CATALOG.pillars,
        (capped, *CATALOG.checks[1:]),
        CATALOG.policy_hash,
    )
    fixture = (evaluation(capped, EvaluationOutcome.FAIL),) + tuple(
        evaluation(check, EvaluationOutcome.PASS) for check in CATALOG.checks[1:]
    )
    fixture_result = score_evaluations(fixture, catalog, created_at=NOW)
    assert fixture_result.caps_applied == ()
    live = tuple(
        CheckEvaluation.build(
            **item.model_dump(exclude={"evaluation_id", "mode", "publishable"}),
            mode=EvidenceMode.LIVE,
            publishable=True,
        )
        for item in fixture
    )
    live_result = score_evaluations(live, catalog, created_at=NOW)
    assert live_result.technical_posture == 40
    assert live_result.caps_applied == ("dns.dnssec",)


@pytest.mark.parametrize(
    "changes",
    [
        {"fresh": False},
        {"directly_attributable": False},
        {"source_confidence": 0.5},
        {"provider_disagreement": True},
        {"evidence_types": ("unrelated.signal",)},
        {"asset_authorized": False},
    ],
)
def test_cap_is_denied_when_assurance_is_insufficient(changes: dict[str, object]) -> None:
    capped = CATALOG.checks[0].model_copy(
        update={
            "critical_cap": 40,
            "required_cap_evidence": 1,
            "required_cap_observation_type": CATALOG.checks[0].observation_type,
            "cap_requires_authorized_asset": True,
        }
    )
    catalog = PolicyCatalog(
        CATALOG.methodology_version,
        CATALOG.scoring_behavior_version,
        CATALOG.minimum_coverage,
        CATALOG.pillars,
        (capped, *CATALOG.checks[1:]),
        CATALOG.policy_hash,
    )
    inputs = (
        evaluation(capped, EvaluationOutcome.FAIL, mode=EvidenceMode.LIVE, **changes),
    ) + tuple(
        evaluation(check, EvaluationOutcome.PASS, mode=EvidenceMode.LIVE)
        for check in CATALOG.checks[1:]
    )
    assert score_evaluations(inputs, catalog, created_at=NOW).caps_applied == ()


def test_cap_requires_actual_evidence_reference() -> None:
    capped = CATALOG.checks[0].model_copy(
        update={
            "critical_cap": 40,
            "required_cap_evidence": 1,
            "required_cap_observation_type": CATALOG.checks[0].observation_type,
            "cap_requires_authorized_asset": True,
        }
    )
    catalog = PolicyCatalog(
        CATALOG.methodology_version,
        CATALOG.scoring_behavior_version,
        CATALOG.minimum_coverage,
        CATALOG.pillars,
        (capped, *CATALOG.checks[1:]),
        CATALOG.policy_hash,
    )
    inputs = (
        evaluation(capped, EvaluationOutcome.FAIL, mode=EvidenceMode.LIVE, evidence_ids=()),
    ) + tuple(
        evaluation(check, EvaluationOutcome.PASS, mode=EvidenceMode.LIVE)
        for check in CATALOG.checks[1:]
    )
    assert score_evaluations(inputs, catalog, created_at=NOW).caps_applied == ()


def test_scoring_behavior_version_mismatch_is_rejected() -> None:
    inputs = list(all_outcomes(EvaluationOutcome.PASS))
    changed = inputs[0].model_dump(exclude={"evaluation_id", "scoring_behavior_version"})
    inputs[0] = CheckEvaluation.build(**changed, scoring_behavior_version="999.0.0")
    with pytest.raises(ValueError, match="mixed_score_inputs"):
        score_evaluations(tuple(inputs), CATALOG, created_at=NOW)
