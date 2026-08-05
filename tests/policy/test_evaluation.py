from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from policy_support import (
    ACTOR,
    ASSESSMENT,
    CATALOG,
    NOW,
    ORGANIZATION,
    SUBJECT,
    observation,
)
from siembiot_worker.policy.catalog import PolicyError, Result, load_catalog
from siembiot_worker.policy.evaluation import (
    SuppressionDecision,
    evaluate_assessment,
    evaluate_check,
    is_applicable,
)
from siembiot_worker.policy.evidence import (
    CheckEvaluation,
    EvidenceError,
    NormalizedObservation,
    ObservationStatus,
)

POLICY_SOURCE = Path(__file__).resolve().parents[2] / "packages" / "policy"


def evaluate(
    check_id: str,
    obs: NormalizedObservation | None = None,
    override: SuppressionDecision | None = None,
) -> CheckEvaluation:
    return evaluate_check(
        CATALOG.by_id(check_id),
        obs,
        catalog=CATALOG,
        organization_id=ORGANIZATION,
        assessment_id=ASSESSMENT,
        subject=SUBJECT,
        evaluated_at=NOW,
        override=override,
    )


# -- rule matching -----------------------------------------------------------


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ("signed_and_delegated", "pass"),
        ("signed_without_delegation", "warning"),
        ("unsigned", "fail"),
        ("unknown", "unknown"),
    ],
)
def test_dnssec_states_map_to_the_documented_results(state: str, expected: str) -> None:
    result = evaluate("A.dnssec_enabled", observation("dns.dnssec", attributes={"state": state}))
    assert result.result == expected


def test_first_matching_rule_wins() -> None:
    # permissive_all is listed before soft_all, so a record with both resolves to fail.
    result = evaluate(
        "B.spf_present",
        observation(
            "email.spf",
            attributes={"present": True, "valid": True, "permissive_all": True, "soft_all": True},
        ),
    )
    assert result.result == "fail"
    assert result.reason_code == "spf_permits_all_senders"


def test_numeric_thresholds_use_at_least_semantics() -> None:
    at_boundary = evaluate(
        "C.certificate_validity",
        observation("tls.certificate", attributes={"expired": False, "days_until_expiry": 30}),
    )
    below = evaluate(
        "C.certificate_validity",
        observation("tls.certificate", attributes={"expired": False, "days_until_expiry": 29}),
    )
    assert at_boundary.result == "pass"
    assert below.result == "warning"


def test_boolean_matching_does_not_coerce_numbers() -> None:
    result = evaluate("A.caa_present", observation("dns.caa", attributes={"present": 1}))
    assert result.result != "pass"


# -- missing and inconclusive evidence ---------------------------------------


def test_absent_observation_yields_unknown_not_pass() -> None:
    result = evaluate("A.dnssec_enabled", None)
    assert result.result == "unknown"
    assert result.reason_code == "observation_missing"


def test_inconclusive_status_yields_unknown_not_absent() -> None:
    result = evaluate("A.caa_present", observation("dns.caa", ObservationStatus.INCONCLUSIVE))
    assert result.result == "unknown"
    assert result.reason_code == "caa_lookup_inconclusive"


def test_proven_absence_is_scored_but_inconclusive_is_not() -> None:
    absent = evaluate("A.caa_present", observation("dns.caa", ObservationStatus.ABSENT))
    inconclusive = evaluate("A.caa_present", observation("dns.caa", ObservationStatus.INCONCLUSIVE))
    assert absent.result == "warning"
    assert absent.score_bearing is True
    assert inconclusive.score_bearing is False


def test_unmatched_observation_is_unknown_rather_than_a_guess() -> None:
    result = evaluate(
        "A.dnssec_enabled", observation("dns.dnssec", attributes={"state": "novel_state"})
    )
    assert result.result == "unknown"
    assert result.reason_code == "no_rule_matched"


# -- applicability -----------------------------------------------------------


def test_always_applicable_check_needs_no_observation() -> None:
    assert is_applicable(CATALOG.by_id("A.dnssec_enabled"), None) is True


def test_requires_observation_check_is_not_applicable_without_one() -> None:
    assert is_applicable(CATALOG.by_id("A.registration_expiry"), None) is False
    assert evaluate("A.registration_expiry", None).result == "not_applicable"


def test_requires_attribute_gates_on_a_truthy_attribute() -> None:
    check = CATALOG.by_id("B.mta_sts_enforced")
    without_mx = observation("email.mta_sts", attributes={"mx_present": False})
    with_mx = observation("email.mta_sts", attributes={"mx_present": True, "mode": "enforce"})
    assert is_applicable(check, without_mx) is False
    assert is_applicable(check, with_mx) is True


def test_not_applicable_observation_status_makes_the_check_not_applicable() -> None:
    result = evaluate(
        "B.dkim_declared_present",
        observation("email.dkim", ObservationStatus.NOT_APPLICABLE),
    )
    assert result.result == "not_applicable"


# -- overrides ---------------------------------------------------------------


def suppression(result: Result = Result.SUPPRESSED, days: int = 30) -> SuppressionDecision:
    return SuppressionDecision(
        "A.caa_present",
        SUBJECT.identifier,
        result,
        "Accepted by the security team",
        ACTOR,
        NOW + timedelta(days=days),
    )


def test_active_suppression_replaces_the_result_but_keeps_the_check_listed() -> None:
    result = evaluate(
        "A.caa_present",
        observation("dns.caa", ObservationStatus.ABSENT),
        override=suppression(),
    )
    assert result.result == "suppressed"
    assert result.score_bearing is False
    assert result.check_id == "A.caa_present"


def test_expired_suppression_no_longer_applies() -> None:
    expired = SuppressionDecision(
        "A.caa_present",
        SUBJECT.identifier,
        Result.SUPPRESSED,
        "Temporary exception",
        ACTOR,
        NOW - timedelta(days=1),
    )
    result = evaluate(
        "A.caa_present", observation("dns.caa", ObservationStatus.ABSENT), override=expired
    )
    assert result.result == "warning"


def test_accepted_risk_override_is_distinct_from_suppression() -> None:
    result = evaluate(
        "A.caa_present",
        observation("dns.caa", ObservationStatus.ABSENT),
        override=suppression(Result.ACCEPTED_RISK),
    )
    assert result.result == "accepted_risk"


def test_override_requires_a_reason() -> None:
    with pytest.raises(ValueError, match="override_requires_reason"):
        SuppressionDecision(
            "A.caa_present", SUBJECT.identifier, Result.SUPPRESSED, "short", ACTOR, NOW
        )


def test_override_cannot_manufacture_a_pass() -> None:
    with pytest.raises(ValueError, match="override_result_must_be"):
        SuppressionDecision(
            "A.caa_present",
            SUBJECT.identifier,
            Result.PASS,
            "Trying to force a pass",
            ACTOR,
            NOW,
        )


# -- whole assessment --------------------------------------------------------


def test_every_catalog_check_is_evaluated_exactly_once() -> None:
    evaluations = evaluate_assessment(
        CATALOG,
        [observation("dns.dnssec", attributes={"state": "unsigned"})],
        organization_id=ORGANIZATION,
        assessment_id=ASSESSMENT,
        subject=SUBJECT,
        evaluated_at=NOW,
    )
    assert len(evaluations) == len(CATALOG.checks)
    assert {item.check_id for item in evaluations} == CATALOG.check_ids


def test_evaluation_is_deterministic_including_identifiers() -> None:
    observations = [observation("dns.dnssec", attributes={"state": "unsigned"})]
    first = evaluate_assessment(
        CATALOG,
        observations,
        organization_id=ORGANIZATION,
        assessment_id=ASSESSMENT,
        subject=SUBJECT,
        evaluated_at=NOW,
    )
    second = evaluate_assessment(
        CATALOG,
        observations,
        organization_id=ORGANIZATION,
        assessment_id=ASSESSMENT,
        subject=SUBJECT,
        evaluated_at=NOW,
    )
    assert [item.evaluation_id for item in first] == [item.evaluation_id for item in second]
    assert [item.result for item in first] == [item.result for item in second]


def test_newest_observation_of_a_type_is_the_one_evaluated() -> None:
    older = observation(
        "dns.dnssec", attributes={"state": "unsigned"}, collected_at=NOW - timedelta(days=1)
    )
    newer = observation("dns.dnssec", attributes={"state": "signed_and_delegated"})
    evaluations = evaluate_assessment(
        CATALOG,
        [older, newer],
        organization_id=ORGANIZATION,
        assessment_id=ASSESSMENT,
        subject=SUBJECT,
        evaluated_at=NOW,
    )
    dnssec = next(item for item in evaluations if item.check_id == "A.dnssec_enabled")
    assert dnssec.result == "pass"


def test_evaluations_carry_the_observations_they_came_from() -> None:
    source = observation("dns.dnssec", attributes={"state": "unsigned"})
    evaluations = evaluate_assessment(
        CATALOG,
        [source],
        organization_id=ORGANIZATION,
        assessment_id=ASSESSMENT,
        subject=SUBJECT,
        evaluated_at=NOW,
    )
    dnssec = next(item for item in evaluations if item.check_id == "A.dnssec_enabled")
    assert dnssec.observation_ids == (source.observation_id,)


# -- catalog integrity -------------------------------------------------------


def test_catalog_rejects_pillar_weights_that_do_not_sum_to_one(tmp_path: Path) -> None:
    import json
    import shutil

    shutil.copytree(POLICY_SOURCE, tmp_path / "policy")
    document = json.loads(
        (tmp_path / "policy" / "methodology" / "v1.0.0.json").read_text(encoding="utf-8")
    )
    document["pillar_weights"]["dns"] = 0.9
    (tmp_path / "policy" / "methodology" / "v1.0.0.json").write_text(
        json.dumps(document), encoding="utf-8"
    )
    with pytest.raises(PolicyError) as error:
        load_catalog(tmp_path / "policy")
    assert error.value.reason == "pillar_weights_do_not_sum_to_one"


def test_observation_with_non_observed_status_cannot_carry_evidence() -> None:
    with pytest.raises(EvidenceError) as error:
        observation("dns.caa", ObservationStatus.ABSENT, {"present": True})
    assert error.value.reason == "non_observed_status_carries_attributes"


def test_every_check_declares_localized_text_and_remediation() -> None:
    for check in CATALOG.checks:
        assert check.title("ro") and check.title("en")
        assert check.rationale_ro and check.rationale_en
        assert check.remediation_template
        assert check.rules
