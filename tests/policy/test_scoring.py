"""Golden vectors for the scoring engine.

Covers boundary values, missing data, errors, caps, coverage floors, confidence
roll-up and methodology versioning — the cases the brief requires before 1.0.
"""

from __future__ import annotations

import pytest
from policy_support import (
    ASSESSMENT,
    CATALOG,
    FULL,
    LOW,
    NOW,
    ORGANIZATION,
    SNAPSHOT,
    all_results,
    evaluation,
    observation,
    with_results,
)
from siembiot_worker.policy.catalog import Pillar, Result
from siembiot_worker.policy.evidence import (
    CheckEvaluation,
    Confidence,
    ConfidenceLevel,
    NormalizedObservation,
)
from siembiot_worker.policy.scoring import (
    INSUFFICIENT_COVERAGE,
    ScoreSnapshot,
    applicable_caps,
    compute_coverage,
    compute_score,
    roll_up_confidence,
    score_pillar,
)


def score(
    evaluations: tuple[CheckEvaluation, ...],
    observations: tuple[NormalizedObservation, ...] = (),
) -> ScoreSnapshot:
    return compute_score(
        CATALOG,
        evaluations,
        observations,
        snapshot_id=SNAPSHOT,
        organization_id=ORGANIZATION,
        assessment_id=ASSESSMENT,
        computed_at=NOW,
    )


# -- boundary values ---------------------------------------------------------


def test_all_pass_scores_one_hundred_and_lands_in_the_top_band() -> None:
    snapshot = score(all_results(Result.PASS))
    assert snapshot.uncapped_score == 100.0
    assert snapshot.score == 100.0
    assert snapshot.band == "resilient"
    assert snapshot.coverage.percentage == 100.0


def test_all_fail_scores_zero_and_lands_in_the_bottom_band() -> None:
    snapshot = score(all_results(Result.FAIL))
    assert snapshot.uncapped_score == 0.0
    assert snapshot.band == "critical"


def test_all_warning_scores_exactly_fifty() -> None:
    snapshot = score(all_results(Result.WARNING))
    assert snapshot.uncapped_score == 50.0
    assert snapshot.band == "exposed"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (100.0, "resilient"),
        (90.0, "resilient"),
        (89.0, "managed"),
        (75.0, "managed"),
        (74.0, "developing"),
        (55.0, "developing"),
        (54.0, "exposed"),
        (30.0, "exposed"),
        (29.0, "critical"),
        (0.0, "critical"),
    ],
)
def test_band_boundaries_are_exact_and_contiguous(value: float, expected: str) -> None:
    assert CATALOG.methodology.band_for(value) == expected


# -- missing data ------------------------------------------------------------


def test_unknown_results_never_contribute_a_factor() -> None:
    snapshot = score(all_results(Result.UNKNOWN))
    assert snapshot.uncapped_score is None
    assert snapshot.band == INSUFFICIENT_COVERAGE
    assert all(pillar.score is None for pillar in snapshot.pillars)


def test_unknown_reduces_coverage_rather_than_scoring_as_failure() -> None:
    unknown_check = "A.caa_present"
    evaluations = with_results(Result.PASS, {unknown_check: Result.UNKNOWN})
    snapshot = score(evaluations)
    assert snapshot.uncapped_score == 100.0
    assert snapshot.coverage.percentage < 100.0
    assert unknown_check in snapshot.coverage.undetermined_checks


def test_error_is_treated_like_unknown_for_coverage_not_like_failure() -> None:
    evaluations = with_results(Result.PASS, {"A.caa_present": Result.ERROR})
    snapshot = score(evaluations)
    assert snapshot.uncapped_score == 100.0
    assert "A.caa_present" in snapshot.coverage.undetermined_checks


def test_not_applicable_leaves_the_denominator_entirely() -> None:
    coverage = compute_coverage(
        with_results(Result.PASS, {"A.caa_present": Result.NOT_APPLICABLE}), CATALOG
    )
    total = sum(check.weight for check in CATALOG.checks)
    excluded = CATALOG.by_id("A.caa_present").weight
    assert coverage.applicable_weight == total - excluded
    assert coverage.percentage == 100.0


def test_insufficient_coverage_replaces_the_band_not_the_number() -> None:
    unknown_ids = {check.check_id for check in CATALOG.checks[:16]}
    evaluations = with_results(Result.PASS, dict.fromkeys(unknown_ids, Result.UNKNOWN))
    snapshot = score(evaluations)
    assert snapshot.coverage.sufficient is False
    assert snapshot.band == INSUFFICIENT_COVERAGE
    assert snapshot.score is not None


# -- suppression and accepted risk -------------------------------------------


@pytest.mark.parametrize("result", [Result.SUPPRESSED, Result.ACCEPTED_RISK])
def test_suppressed_and_accepted_risk_never_become_a_pass(result: Result) -> None:
    evaluations = with_results(Result.FAIL, {"A.caa_present": result})
    snapshot = score(evaluations)
    contributions = {
        item.check_id: item for pillar in snapshot.pillars for item in pillar.contributions
    }
    assert contributions["A.caa_present"].factor is None
    assert contributions["A.caa_present"].result == str(result)
    assert snapshot.uncapped_score == 0.0


def test_accepted_risk_is_covered_evidence_but_leaves_the_scoring_denominator() -> None:
    evaluations = with_results(Result.PASS, {"A.caa_present": Result.ACCEPTED_RISK})
    # An accepted risk is a decision the organization made, not data we failed to
    # collect, so it stays in the coverage denominator and does not read as a blind spot.
    coverage = compute_coverage(evaluations, CATALOG)
    assert "A.caa_present" not in coverage.undetermined_checks
    assert coverage.applicable_weight == sum(check.weight for check in CATALOG.checks)
    assert coverage.percentage == 100.0

    # It is nonetheless excluded from the score itself rather than counted as a pass.
    dns = next(pillar for pillar in score(evaluations).pillars if pillar.pillar is Pillar.DNS)
    accepted = next(item for item in dns.contributions if item.check_id == "A.caa_present")
    assert accepted.factor is None
    assert dns.scored_checks == len(CATALOG.for_pillar(Pillar.DNS)) - 1


# -- caps --------------------------------------------------------------------


def test_expired_certificate_cap_lowers_the_score_and_names_its_trigger() -> None:
    evaluations = with_results(Result.PASS, {"C.certificate_validity": Result.FAIL})
    snapshot = score(evaluations)
    assert snapshot.uncapped_score is not None
    assert snapshot.uncapped_score > 54.0
    assert snapshot.score == 54.0
    assert [cap.cap_id for cap in snapshot.caps_applied] == ["expired_certificate"]
    assert snapshot.caps_applied[0].triggering_check_ids == ("C.certificate_validity",)


def test_a_cap_can_only_lower_never_raise() -> None:
    evaluations = with_results(Result.FAIL, {"C.certificate_validity": Result.FAIL})
    snapshot = score(evaluations)
    assert snapshot.uncapped_score == 0.0
    assert snapshot.score == 0.0


def test_lowest_ceiling_wins_when_several_caps_fire() -> None:
    evaluations = with_results(
        Result.PASS,
        {
            "C.certificate_validity": Result.FAIL,
            "C.certificate_hostname": Result.FAIL,
        },
    )
    snapshot = score(evaluations)
    assert {cap.cap_id for cap in snapshot.caps_applied} == {
        "expired_certificate",
        "certificate_hostname_mismatch",
    }
    assert snapshot.score == 54.0


def test_low_confidence_failure_does_not_trigger_a_cap() -> None:
    evaluations = tuple(
        evaluation(check.check_id, Result.PASS)
        if check.check_id != "C.certificate_validity"
        else evaluation(check.check_id, Result.FAIL, confidence=LOW)
        for check in CATALOG.checks
    )
    assert applicable_caps(evaluations, CATALOG) == ()
    capped = score(evaluations).score
    assert capped is not None
    assert capped > 54.0


def test_a_warning_never_triggers_a_cap() -> None:
    evaluations = with_results(Result.PASS, {"C.certificate_validity": Result.WARNING})
    assert applicable_caps(evaluations, CATALOG) == ()


def test_shared_hosting_style_uncertainty_cannot_cap_a_score() -> None:
    uncertain = Confidence(0.4, 0.9, 1.0, ("shared_hosting_observation",))
    evaluations = tuple(
        evaluation(check.check_id, Result.PASS)
        if check.check_id != "C.https_available"
        else evaluation(check.check_id, Result.FAIL, confidence=uncertain)
        for check in CATALOG.checks
    )
    assert applicable_caps(evaluations, CATALOG) == ()


# -- pillars -----------------------------------------------------------------


def test_pillar_score_uses_only_score_bearing_checks() -> None:
    evaluations = tuple(
        evaluation(check.check_id, Result.PASS)
        for check in CATALOG.for_pillar(Pillar.DNS)
        if check.check_id != "A.caa_present"
    ) + (evaluation("A.caa_present", Result.UNKNOWN),)
    pillar = score_pillar(Pillar.DNS, 0.2, evaluations, CATALOG)
    assert pillar.score == 100.0
    assert pillar.scored_checks == 3
    assert pillar.excluded_checks == 1


def test_pillar_with_no_scored_checks_is_null_not_zero() -> None:
    evaluations = tuple(
        evaluation(check.check_id, Result.UNKNOWN) for check in CATALOG.for_pillar(Pillar.DNS)
    )
    assert score_pillar(Pillar.DNS, 0.2, evaluations, CATALOG).score is None


def test_overall_reweights_across_only_the_pillars_that_scored() -> None:
    reputation_ids = {check.check_id for check in CATALOG.for_pillar(Pillar.REPUTATION)}
    evaluations = with_results(Result.PASS, dict.fromkeys(reputation_ids, Result.UNKNOWN))
    snapshot = score(evaluations)
    assert snapshot.uncapped_score == 100.0
    reputation = next(p for p in snapshot.pillars if p.pillar is Pillar.REPUTATION)
    assert reputation.score is None


def test_weight_contribution_is_visible_for_every_check() -> None:
    snapshot = score(all_results(Result.PASS))
    listed = {item.check_id for pillar in snapshot.pillars for item in pillar.contributions}
    assert listed == CATALOG.check_ids


# -- monotonicity and sensitivity --------------------------------------------


def test_improving_one_check_never_lowers_the_score() -> None:
    baseline = score(all_results(Result.FAIL)).uncapped_score
    assert baseline is not None
    for check in CATALOG.checks:
        improved = score(with_results(Result.FAIL, {check.check_id: Result.WARNING}))
        assert improved.uncapped_score is not None
        assert improved.uncapped_score >= baseline


def test_degrading_one_check_never_raises_the_score() -> None:
    baseline = score(all_results(Result.PASS)).uncapped_score
    assert baseline is not None
    for check in CATALOG.checks:
        degraded = score(with_results(Result.PASS, {check.check_id: Result.FAIL}))
        assert degraded.uncapped_score is not None
        assert degraded.uncapped_score <= baseline


def test_a_heavier_check_moves_the_score_at_least_as_much_as_a_lighter_one() -> None:
    heavy = max(CATALOG.for_pillar(Pillar.WEB_TLS), key=lambda check: check.weight)
    light = min(CATALOG.for_pillar(Pillar.WEB_TLS), key=lambda check: check.weight)
    heavy_score = score(with_results(Result.PASS, {heavy.check_id: Result.FAIL})).uncapped_score
    light_score = score(with_results(Result.PASS, {light.check_id: Result.FAIL})).uncapped_score
    assert heavy_score is not None
    assert light_score is not None
    assert heavy_score <= light_score


# -- reproducibility ---------------------------------------------------------


def test_identical_inputs_produce_byte_identical_snapshots() -> None:
    first = score(all_results(Result.PASS)).as_dict()
    second = score(all_results(Result.PASS)).as_dict()
    assert first == second


def test_snapshot_records_the_policy_digest_that_produced_it() -> None:
    snapshot = score(all_results(Result.PASS))
    assert snapshot.policy_digest == CATALOG.digest
    assert snapshot.methodology_version == CATALOG.methodology.version


def test_evidence_digest_changes_when_evidence_changes() -> None:
    first = score(all_results(Result.PASS), (observation("dns.caa", attributes={"present": True}),))
    second = score(
        all_results(Result.PASS), (observation("dns.caa", attributes={"present": False}),)
    )
    assert first.evidence_digest != second.evidence_digest


def test_projection_is_marked_and_does_not_pretend_to_be_original() -> None:
    snapshot = compute_score(
        CATALOG,
        all_results(Result.PASS),
        (),
        snapshot_id=SNAPSHOT,
        organization_id=ORGANIZATION,
        assessment_id=ASSESSMENT,
        computed_at=NOW,
        is_projection=True,
    )
    assert snapshot.as_dict()["is_projection"] is True


# -- confidence --------------------------------------------------------------


def test_confidence_rollup_takes_the_weakest_dimension() -> None:
    combined = roll_up_confidence(all_results(Result.PASS, LOW))
    assert combined.attribution == 0.3
    assert combined.level(0.8, 0.5) is ConfidenceLevel.LOW


def test_one_low_confidence_check_lowers_the_whole_snapshot() -> None:
    evaluations = tuple(
        evaluation(check.check_id, Result.PASS, confidence=FULL if index else LOW)
        for index, check in enumerate(CATALOG.checks)
    )
    assert roll_up_confidence(evaluations).level(0.8, 0.5) is ConfidenceLevel.LOW


def test_confidence_reasons_are_preserved_across_the_rollup() -> None:
    combined = roll_up_confidence(all_results(Result.PASS, LOW))
    assert "attribution_uncertain" in combined.reasons
