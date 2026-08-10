"""The check evaluation engine.

Pure and deterministic: the same observations under the same catalog always produce
the same evaluations. No model participates, and no rule can invent a pass from
missing data — absence of evidence resolves to unknown, never to success.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID, uuid5

from siembiot_worker.policy.catalog import (
    Check,
    PolicyCatalog,
    Result,
    Rule,
)
from siembiot_worker.policy.evidence import (
    CheckEvaluation,
    Confidence,
    NormalizedObservation,
    ObservationStatus,
    Subject,
)

EVALUATION_NAMESPACE = UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")


@dataclass(frozen=True)
class SuppressionDecision:
    """An authorized, expiring override recorded against one check and subject."""

    check_id: str
    subject_identifier: str
    result: Result
    reason: str
    actor_id: UUID
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.result not in {Result.SUPPRESSED, Result.ACCEPTED_RISK}:
            raise ValueError("override_result_must_be_suppressed_or_accepted_risk")
        if len(self.reason.strip()) < 8:
            raise ValueError("override_requires_reason")

    def is_active(self, now: datetime) -> bool:
        return now < self.expires_at


def _matches(rule: Rule, observation: NormalizedObservation) -> bool:
    if rule.status is not None:
        return str(observation.status) == rule.status
    if rule.attribute is None:
        return True
    if observation.status is not ObservationStatus.OBSERVED:
        return False
    if rule.attribute not in observation.attributes:
        return False
    value = observation.attributes[rule.attribute]
    if rule.equals is not None:
        return _equals(value, rule.equals)
    if rule.at_least is not None:
        return (
            isinstance(value, int | float)
            and not isinstance(value, bool)
            and (value >= rule.at_least)
        )
    if rule.at_most is not None:
        return (
            isinstance(value, int | float)
            and not isinstance(value, bool)
            and (value <= rule.at_most)
        )
    return True


def _equals(value: Any, expected: Any) -> bool:
    if isinstance(expected, bool) or isinstance(value, bool):
        return value is expected
    return bool(value == expected)


def is_applicable(check: Check, observation: NormalizedObservation | None) -> bool:
    rules = check.applicability
    if rules.get("always"):
        return True
    if rules.get("requires_observation"):
        return observation is not None and observation.status is not (
            ObservationStatus.NOT_APPLICABLE
        )
    required = rules.get("requires_attribute")
    if isinstance(required, str):
        if observation is None or observation.status is not ObservationStatus.OBSERVED:
            return False
        return bool(observation.attributes.get(required))
    return observation is not None


def evaluate_check(
    check: Check,
    observation: NormalizedObservation | None,
    *,
    catalog: PolicyCatalog,
    organization_id: UUID,
    assessment_id: UUID,
    subject: Subject,
    evaluated_at: datetime,
    override: SuppressionDecision | None = None,
) -> CheckEvaluation:
    """Apply one check. Rule order is significant: the first match wins."""
    methodology_version = catalog.methodology.version
    identity = uuid5(
        EVALUATION_NAMESPACE,
        f"{assessment_id}:{check.check_id}:{subject.identifier}",
    )

    def build(result: Result, reason_code: str | None, confidence: Confidence) -> CheckEvaluation:
        return CheckEvaluation(
            evaluation_id=identity,
            organization_id=organization_id,
            assessment_id=assessment_id,
            check_id=check.check_id,
            check_version=check.version,
            methodology_version=methodology_version,
            pillar=check.pillar,
            subject=subject,
            result=str(result),
            weight=check.weight,
            severity=str(check.severity),
            confidence=confidence,
            observation_ids=(observation.observation_id,) if observation else (),
            reason_code=reason_code,
            evaluated_at=evaluated_at,
        )

    if override is not None and override.is_active(evaluated_at):
        confidence = observation.confidence if observation else Confidence(1.0, 1.0, 1.0)
        return build(override.result, "operator_override", confidence)

    if not is_applicable(check, observation):
        return build(
            Result.NOT_APPLICABLE,
            "not_applicable_for_subject",
            observation.confidence if observation else Confidence(1.0, 1.0, 1.0),
        )

    if observation is None:
        return build(
            Result.UNKNOWN, "observation_missing", Confidence(1.0, 1.0, 0.0, ("no_evidence",))
        )

    for rule in check.rules:
        if _matches(rule, observation):
            return build(rule.result, rule.reason_code, observation.confidence)

    return build(Result.UNKNOWN, "no_rule_matched", observation.confidence)


def evaluate_assessment(
    catalog: PolicyCatalog,
    observations: Sequence[NormalizedObservation],
    *,
    organization_id: UUID,
    assessment_id: UUID,
    subject: Subject,
    evaluated_at: datetime,
    overrides: Mapping[str, SuppressionDecision] | None = None,
    checks: Sequence[Check] | None = None,
) -> tuple[CheckEvaluation, ...]:
    """Evaluate a set of checks exactly once for one subject.

    `checks` defaults to the whole catalogue, which is what an assessment of the
    authorized domain wants. A discovered host is assessed against the host-scoped
    subset instead: running the zone's DNS and mail checks again for every subdomain
    would repeat one answer under many subjects and read as broader coverage than was
    actually observed.
    """
    by_type: dict[str, NormalizedObservation] = {}
    for observation in observations:
        existing = by_type.get(observation.observation_type)
        if existing is None or observation.collected_at > existing.collected_at:
            by_type[observation.observation_type] = observation
    active = overrides or {}
    return tuple(
        evaluate_check(
            check,
            by_type.get(check.observation_type),
            catalog=catalog,
            organization_id=organization_id,
            assessment_id=assessment_id,
            subject=subject,
            evaluated_at=evaluated_at,
            override=active.get(check.check_id),
        )
        for check in (catalog.checks if checks is None else checks)
    )
