from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from siembiot_worker.collection.models import ObservationOutcome, build_fixture_observation
from siembiot_worker.evaluation.engine import EvaluationContext, evaluate_check
from siembiot_worker.evaluation.policy import load_policy_catalog
from siembiot_worker.evidence.models import EvaluationOutcome, NormalizedObservation
from siembiot_worker.normalization.registry import normalize_observation

ROOT = Path(__file__).resolve().parents[2]
CATALOG = load_policy_catalog(ROOT / "packages/policy/checks/v1")


def normalized(
    outcome: ObservationOutcome,
    payload: dict[str, object],
    *,
    collected_at: datetime | None = None,
) -> NormalizedObservation:
    source = build_fixture_observation(
        scope_reference="scope-a",
        collector_id="dns",
        collector_version="1.0.0",
        adapter_id="fixture-dns",
        adapter_version="1.0.0",
        collected_at=collected_at or datetime(2026, 8, 3, 12, tzinfo=UTC),
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
        (normalized(ObservationOutcome.PASS, {"record_type": "DNSSEC", "secure": False}),),
        CATALOG,
        context(),
    )
    assert [passed.outcome, failed.outcome] == [EvaluationOutcome.PASS, EvaluationOutcome.FAIL]


def test_policy_rules_interpret_payload_instead_of_transport_success() -> None:
    hsts = next(item for item in CATALOG.checks if item.check_id == "web.hsts")
    source = build_fixture_observation(
        scope_reference="scope-a",
        collector_id="http",
        collector_version="1.0.0",
        adapter_id="fixture-http",
        adapter_version="1.0.0",
        collected_at=datetime(2026, 8, 3, 12, tzinfo=UTC),
        scenario_id="healthy",
        scenario_sha256="b" * 64,
        outcome=ObservationOutcome.PASS,
        payload={"status": 200, "headers": {}},
    )
    item = normalize_observation(source, organization_id="org-a", asset_id="asset-a")
    result = evaluate_check(hsts, (item,), CATALOG, context())
    assert result.outcome is EvaluationOutcome.FAIL
    assert result.reason_code == "required_header_missing"


def test_explicit_applicability_false_is_not_applicable() -> None:
    check = next(item for item in CATALOG.checks if item.check_id == "dns.dnssec")
    result = evaluate_check(
        check,
        (normalized(ObservationOutcome.PASS, {"record_type": "DNSSEC", "applicable": False}),),
        CATALOG,
        context(),
    )
    assert result.outcome is EvaluationOutcome.NOT_APPLICABLE


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
    assert evaluation.asset_authorized is False


def test_asset_authorization_requires_explicit_affirmative_proof() -> None:
    check = next(item for item in CATALOG.checks if item.check_id == "dns.dnssec")
    result = evaluate_check(
        check,
        (
            normalized(
                ObservationOutcome.PASS,
                {"record_type": "DNSSEC", "secure": True, "asset_authorized": True},
            ),
        ),
        CATALOG,
        context(),
    )
    assert result.asset_authorized is True


def test_stale_and_future_evidence_never_drive_posture() -> None:
    check = next(item for item in CATALOG.checks if item.check_id == "dns.dnssec")
    now = context().evaluated_at
    stale = evaluate_check(
        check,
        (
            normalized(
                ObservationOutcome.PASS,
                {"record_type": "DNSSEC", "secure": True},
                collected_at=now - timedelta(days=2),
            ),
        ),
        CATALOG,
        context(),
    )
    future = evaluate_check(
        check,
        (
            normalized(
                ObservationOutcome.PASS,
                {"record_type": "DNSSEC", "secure": True},
                collected_at=now + timedelta(seconds=1),
            ),
        ),
        CATALOG,
        context(),
    )
    assert (stale.outcome, stale.reason_code, stale.fresh) == (
        EvaluationOutcome.UNKNOWN,
        "stale_evidence",
        False,
    )
    assert (future.outcome, future.reason_code, future.fresh) == (
        EvaluationOutcome.ERROR,
        "future_evidence",
        False,
    )
