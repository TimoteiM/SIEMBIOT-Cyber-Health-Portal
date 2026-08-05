from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID, uuid4

import pytest
from policy_support import ACTOR, ASSESSMENT, CATALOG, NOW, ORGANIZATION, SUBJECT, with_results
from siembiot_worker.policy.catalog import Result
from siembiot_worker.policy.evidence import Subject, SubjectKind
from siembiot_worker.policy.findings import (
    Finding,
    FindingState,
    apply_suppression,
    attribute_change,
    derive_findings,
    expire_suppressions,
    fingerprint,
    reconcile,
)

LATER = NOW + timedelta(days=7)
SECOND_ASSESSMENT = uuid4()


def findings_for(
    overrides: dict[str, Result],
    at: datetime = NOW,
    assessment: UUID = ASSESSMENT,
) -> tuple[Finding, ...]:
    return derive_findings(
        CATALOG,
        with_results(Result.PASS, overrides),
        organization_id=ORGANIZATION,
        assessment_id=assessment,
        observed_at=at,
    )


# -- derivation --------------------------------------------------------------


def test_passing_checks_create_no_findings() -> None:
    assert findings_for({}) == ()


def test_failures_and_warnings_both_create_findings() -> None:
    findings = findings_for({"A.dnssec_enabled": Result.FAIL, "A.caa_present": Result.WARNING})
    assert {item.check_id for item in findings} == {"A.dnssec_enabled", "A.caa_present"}


def test_unknown_and_error_do_not_create_findings() -> None:
    findings = findings_for({"A.dnssec_enabled": Result.UNKNOWN, "A.caa_present": Result.ERROR})
    assert findings == ()


def test_suppressed_and_accepted_risk_still_produce_visible_findings() -> None:
    findings = findings_for(
        {"A.dnssec_enabled": Result.SUPPRESSED, "A.caa_present": Result.ACCEPTED_RISK}
    )
    states = {item.check_id: item.state for item in findings}
    assert states["A.dnssec_enabled"] is FindingState.SUPPRESSED
    assert states["A.caa_present"] is FindingState.ACCEPTED_RISK
    assert all(item.is_visible for item in findings)


def test_finding_carries_severity_class_and_evidence_from_the_catalog() -> None:
    finding = findings_for({"C.https_available": Result.FAIL})[0]
    check = CATALOG.by_id("C.https_available")
    assert finding.severity == str(check.severity)
    assert finding.public_safety_class == str(check.public_safety_class)
    assert finding.evidence


def test_private_only_findings_are_labelled_as_such() -> None:
    finding = findings_for({"C.cookie_attributes": Result.WARNING})[0]
    assert finding.public_safety_class == "private_only"


# -- fingerprints ------------------------------------------------------------


def test_fingerprint_is_stable_across_assessments() -> None:
    first = findings_for({"A.dnssec_enabled": Result.FAIL})[0]
    second = findings_for({"A.dnssec_enabled": Result.FAIL}, at=LATER, assessment=uuid4())[0]
    assert first.fingerprint == second.fingerprint
    assert first.finding_id == second.finding_id


def test_fingerprint_differs_per_tenant() -> None:
    left = fingerprint(ORGANIZATION, SUBJECT, "A.dnssec_enabled")
    right = fingerprint(uuid4(), SUBJECT, "A.dnssec_enabled")
    assert left != right


def test_fingerprint_differs_per_subject_and_check() -> None:
    other_subject = Subject(SubjectKind.DOMAIN, "other.example.test")
    assert fingerprint(ORGANIZATION, SUBJECT, "A.dnssec_enabled") != fingerprint(
        ORGANIZATION, other_subject, "A.dnssec_enabled"
    )
    assert fingerprint(ORGANIZATION, SUBJECT, "A.dnssec_enabled") != fingerprint(
        ORGANIZATION, SUBJECT, "A.caa_present"
    )


def test_material_evidence_key_separates_distinct_issues_on_one_check() -> None:
    assert fingerprint(ORGANIZATION, SUBJECT, "B.spf_present", "spf_absent") != fingerprint(
        ORGANIZATION, SUBJECT, "B.spf_present", "spf_permits_all_senders"
    )


# -- reconciliation ----------------------------------------------------------


def test_a_finding_that_disappears_is_resolved_not_deleted() -> None:
    previous = findings_for({"A.dnssec_enabled": Result.FAIL})
    merged = reconcile(previous, (), assessment_id=SECOND_ASSESSMENT, observed_at=LATER)
    assert len(merged) == 1
    assert merged[0].state is FindingState.RESOLVED
    assert merged[0].resolved_at == LATER
    assert merged[0].history[-1].to_state == "resolved"


def test_a_reappearing_finding_is_marked_regressed() -> None:
    previous = findings_for({"A.dnssec_enabled": Result.FAIL})
    resolved = reconcile(previous, (), assessment_id=SECOND_ASSESSMENT, observed_at=LATER)
    again = findings_for({"A.dnssec_enabled": Result.FAIL}, at=LATER)
    merged = reconcile(resolved, again, assessment_id=SECOND_ASSESSMENT, observed_at=LATER)
    assert merged[0].state is FindingState.REGRESSED


def test_a_persisting_finding_keeps_its_first_seen_date() -> None:
    previous = findings_for({"A.dnssec_enabled": Result.FAIL})
    current = findings_for({"A.dnssec_enabled": Result.FAIL}, at=LATER)
    merged = reconcile(previous, current, assessment_id=SECOND_ASSESSMENT, observed_at=LATER)
    assert merged[0].first_seen_at == NOW
    assert merged[0].last_seen_at == LATER


def test_reconciliation_is_order_independent() -> None:
    previous = findings_for({"A.dnssec_enabled": Result.FAIL, "A.caa_present": Result.WARNING})
    current = findings_for({"A.caa_present": Result.WARNING}, at=LATER)
    forward = reconcile(previous, current, assessment_id=SECOND_ASSESSMENT, observed_at=LATER)
    backward = reconcile(
        tuple(reversed(previous)), current, assessment_id=SECOND_ASSESSMENT, observed_at=LATER
    )
    assert [item.fingerprint for item in forward] == [item.fingerprint for item in backward]


def test_resolved_findings_are_not_resolved_twice() -> None:
    previous = findings_for({"A.dnssec_enabled": Result.FAIL})
    once = reconcile(previous, (), assessment_id=SECOND_ASSESSMENT, observed_at=LATER)
    twice = reconcile(once, (), assessment_id=SECOND_ASSESSMENT, observed_at=LATER)
    assert len(twice[0].history) == len(once[0].history)


# -- suppression -------------------------------------------------------------


def test_suppression_records_reason_actor_and_expiry() -> None:
    finding = findings_for({"A.dnssec_enabled": Result.FAIL})[0]
    suppressed = apply_suppression(
        finding,
        reason="Compensating control in place until migration",
        actor_id=ACTOR,
        now=NOW,
        expires_at=NOW + timedelta(days=30),
        assessment_id=ASSESSMENT,
    )
    assert suppressed.state is FindingState.SUPPRESSED
    assert suppressed.suppression is not None
    assert suppressed.suppression.actor_id == ACTOR
    assert suppressed.history[-1].actor_id == ACTOR


def test_suppression_requires_a_meaningful_reason() -> None:
    finding = findings_for({"A.dnssec_enabled": Result.FAIL})[0]
    with pytest.raises(ValueError, match="suppression_requires_reason"):
        apply_suppression(
            finding,
            reason="x",
            actor_id=ACTOR,
            now=NOW,
            expires_at=NOW + timedelta(days=1),
            assessment_id=ASSESSMENT,
        )


def test_suppression_cannot_be_indefinite() -> None:
    finding = findings_for({"A.dnssec_enabled": Result.FAIL})[0]
    with pytest.raises(ValueError, match="suppression_must_expire"):
        apply_suppression(
            finding,
            reason="Indefinite exception attempt",
            actor_id=ACTOR,
            now=NOW,
            expires_at=NOW,
            assessment_id=ASSESSMENT,
        )


def test_expired_suppression_returns_the_finding_to_open() -> None:
    finding = findings_for({"A.dnssec_enabled": Result.FAIL})[0]
    suppressed = apply_suppression(
        finding,
        reason="Temporary exception granted",
        actor_id=ACTOR,
        now=NOW,
        expires_at=NOW + timedelta(days=1),
        assessment_id=ASSESSMENT,
    )
    expired = expire_suppressions(
        [suppressed], now=NOW + timedelta(days=2), assessment_id=SECOND_ASSESSMENT
    )
    assert expired[0].state is FindingState.OPEN
    assert expired[0].suppression is None


def test_unexpired_suppression_is_left_alone() -> None:
    finding = findings_for({"A.dnssec_enabled": Result.FAIL})[0]
    suppressed = apply_suppression(
        finding,
        reason="Still within the agreed window",
        actor_id=ACTOR,
        now=NOW,
        expires_at=NOW + timedelta(days=30),
        assessment_id=ASSESSMENT,
    )
    unchanged = expire_suppressions([suppressed], now=LATER, assessment_id=SECOND_ASSESSMENT)
    assert unchanged[0].state is FindingState.SUPPRESSED


def test_suppression_survives_reconciliation() -> None:
    finding = findings_for({"A.dnssec_enabled": Result.FAIL})[0]
    suppressed = apply_suppression(
        finding,
        reason="Accepted until the platform migration",
        actor_id=ACTOR,
        now=NOW,
        expires_at=NOW + timedelta(days=90),
        assessment_id=ASSESSMENT,
    )
    current = findings_for({"A.dnssec_enabled": Result.FAIL}, at=LATER)
    merged = reconcile([suppressed], current, assessment_id=SECOND_ASSESSMENT, observed_at=LATER)
    assert merged[0].state is FindingState.SUPPRESSED
    assert merged[0].suppression is not None


# -- score change attribution ------------------------------------------------


def test_same_methodology_delta_is_comparable() -> None:
    attribution = attribute_change(60.0, 75.0, "1.0.0", "1.0.0")
    assert attribution["comparable"] is True
    assert attribution["delta"] == 15.0


def test_methodology_change_is_never_reported_as_remediation() -> None:
    attribution = attribute_change(60.0, 75.0, "1.0.0", "1.1.0")
    assert attribution["comparable"] is False
    assert attribution["reason"] == "methodology_version_differs"
    assert attribution["methodology_changed"] is True


def test_missing_score_is_not_compared() -> None:
    assert attribute_change(None, 75.0, "1.0.0", "1.0.0")["comparable"] is False
