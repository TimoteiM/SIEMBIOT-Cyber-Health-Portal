from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid5

from siembiot_worker.policy.catalog import PolicyCatalog, Result, load_catalog
from siembiot_worker.policy.evidence import (
    CheckEvaluation,
    Confidence,
    NormalizedObservation,
    ObservationStatus,
    Subject,
    SubjectKind,
)

ORGANIZATION = UUID("11111111-1111-4111-8111-111111111111")
ASSESSMENT = UUID("22222222-2222-4222-8222-222222222222")
SNAPSHOT = UUID("33333333-3333-4333-8333-333333333333")
ACTOR = UUID("44444444-4444-4444-8444-444444444444")
NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
HOST = "strong.example.test"
SUBJECT = Subject(SubjectKind.DOMAIN, HOST)
NAMESPACE = UUID("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d")

CATALOG: PolicyCatalog = load_catalog()
FULL = Confidence(1.0, 1.0, 1.0)
LOW = Confidence(0.3, 1.0, 1.0, ("attribution_uncertain",))


def observation(
    observation_type: str,
    status: ObservationStatus = ObservationStatus.OBSERVED,
    attributes: dict[str, object] | None = None,
    *,
    confidence: Confidence = FULL,
    collected_at: datetime = NOW,
    subject: Subject = SUBJECT,
) -> NormalizedObservation:
    return NormalizedObservation(
        observation_id=uuid5(NAMESPACE, f"{ASSESSMENT}:{subject.identifier}:{observation_type}"),
        organization_id=ORGANIZATION,
        assessment_id=ASSESSMENT,
        subject=subject,
        observation_type=observation_type,
        status=status,
        attributes=attributes or {},
        confidence=confidence,
        adapter_id="dns_resilience",
        adapter_version="1.0.0",
        collected_at=collected_at,
    )


def evaluation(
    check_id: str,
    result: Result,
    *,
    confidence: Confidence = FULL,
    weight: float | None = None,
) -> CheckEvaluation:
    check = CATALOG.by_id(check_id)
    return CheckEvaluation(
        evaluation_id=uuid5(NAMESPACE, f"{ASSESSMENT}:{check_id}:{HOST}"),
        organization_id=ORGANIZATION,
        assessment_id=ASSESSMENT,
        check_id=check_id,
        check_version=check.version,
        methodology_version=CATALOG.methodology.version,
        pillar=check.pillar,
        subject=SUBJECT,
        result=str(result),
        weight=check.weight if weight is None else weight,
        severity=str(check.severity),
        confidence=confidence,
        observation_ids=(uuid5(NAMESPACE, check_id),),
        evaluated_at=NOW,
    )


def all_results(result: Result, confidence: Confidence = FULL) -> tuple[CheckEvaluation, ...]:
    """Every catalog check with the same result — the baseline for scoring tests."""
    return tuple(
        evaluation(check.check_id, result, confidence=confidence) for check in CATALOG.checks
    )


def with_results(
    baseline: Result, overrides: dict[str, Result], confidence: Confidence = FULL
) -> tuple[CheckEvaluation, ...]:
    return tuple(
        evaluation(check.check_id, overrides.get(check.check_id, baseline), confidence=confidence)
        for check in CATALOG.checks
    )
