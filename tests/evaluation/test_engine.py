from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from siembiot_worker.collection.models import ObservationOutcome, build_fixture_observation
from siembiot_worker.evaluation.engine import EvaluationContext, evaluate_check
from siembiot_worker.evaluation.policy import load_policy_catalog
from siembiot_worker.evidence.models import EvaluationOutcome, NormalizedObservation
from siembiot_worker.normalization.registry import normalize_observation

ROOT = Path(__file__).resolve().parents[2]
CATALOG = load_policy_catalog(ROOT / "packages/policy/checks/v1")


def normalized(outcome: ObservationOutcome, payload: dict[str, object]) -> NormalizedObservation:
    source = build_fixture_observation(
        scope_reference="scope-a",
        collector_id="dns",
        collector_version="1.0.0",
        adapter_id="fixture-dns",
        adapter_version="1.0.0",
        collected_at=datetime(2026, 8, 3, 12, tzinfo=UTC),
        scenario_id="healthy",
        scenario_sha256="b" * 64,
        outcome=outcome,
        payload=payload,
    )
    return normalize_observation(source, organization_id="org-a", asset_id="asset-a")


def context() -> EvaluationContext:
    return EvaluationContext(evaluated_at=datetime(2026, 8, 3, 13, tzinfo=UTC))


def test_boolean_rule_preserves_pass_fail_warning() -> None:
    check = next(item for item in CATALOG.checks if item.check_id == "dns.dnssec")
    passed = evaluate_check(
        check,
        (normalized(ObservationOutcome.PASS, {"record_type": "DNSSEC", "secure": True}),),
        CATALOG,
        context(),
    )
    failed = evaluate_check(
        check,
        (normalized(ObservationOutcome.FAIL, {"record_type": "DNSSEC", "secure": False}),),
        CATALOG,
        context(),
    )
    warning = evaluate_check(
        check,
        (normalized(ObservationOutcome.WARNING, {"record_type": "DNSSEC", "secure": False}),),
        CATALOG,
        context(),
    )
    assert [passed.outcome, failed.outcome, warning.outcome] == [
        EvaluationOutcome.PASS,
        EvaluationOutcome.FAIL,
        EvaluationOutcome.WARNING,
    ]


def test_missing_unknown_and_error_never_become_pass_or_fail() -> None:
    check = next(item for item in CATALOG.checks if item.check_id == "dns.dnssec")
    missing = evaluate_check(
        check, (), CATALOG, context(), organization_id="org-a", asset_id="asset-a", mode="fixture"
    )
    unknown = evaluate_check(
        check,
        (
            normalized(
                ObservationOutcome.UNKNOWN,
                {"record_type": "DNSSEC", "reason_code": "fixture_unavailable"},
            ),
        ),
        CATALOG,
        context(),
    )
    error = evaluate_check(
        check,
        (
            normalized(
                ObservationOutcome.ERROR,
                {"record_type": "DNSSEC", "reason_code": "malformed_fixture_data"},
            ),
        ),
        CATALOG,
        context(),
    )
    assert missing.outcome is unknown.outcome is EvaluationOutcome.UNKNOWN
    assert error.outcome is EvaluationOutcome.ERROR


def test_fixture_evaluation_is_policy_hash_bound_and_non_publishable() -> None:
    check = next(item for item in CATALOG.checks if item.check_id == "dns.dnssec")
    evaluation = evaluate_check(
        check,
        (normalized(ObservationOutcome.PASS, {"record_type": "DNSSEC", "secure": True}),),
        CATALOG,
        context(),
    )
    assert evaluation.policy_hash == CATALOG.policy_hash
    assert evaluation.evaluation_id.startswith("sha256-v1:")
    assert evaluation.mode.value == "fixture"
    assert not evaluation.publishable
