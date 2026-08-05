"""Finding generation and lifecycle.

Findings come only from deterministic evaluations. A fingerprint is stable across
assessments so history survives re-runs, and a finding that is suppressed or accepted
as risk stays listed — it changes treatment, never visibility.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid5

from siembiot_worker.policy.catalog import PolicyCatalog, Result
from siembiot_worker.policy.evidence import CheckEvaluation, Confidence, Subject

FINDING_NAMESPACE = UUID("2f8b1d24-0f4e-4a5f-9c3a-6d5b8e2f1a70")
FINDING_RESULTS = frozenset({Result.FAIL, Result.WARNING, Result.SUPPRESSED, Result.ACCEPTED_RISK})


class FindingState(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    REGRESSED = "regressed"
    SUPPRESSED = "suppressed"
    ACCEPTED_RISK = "accepted_risk"


@dataclass(frozen=True)
class HistoryEntry:
    at: datetime
    from_state: str
    to_state: str
    assessment_id: UUID
    actor_id: UUID | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "at": self.at.isoformat().replace("+00:00", "Z"),
            "from_state": self.from_state,
            "to_state": self.to_state,
            "assessment_id": str(self.assessment_id),
            "actor_id": None if self.actor_id is None else str(self.actor_id),
        }


@dataclass(frozen=True)
class Suppression:
    reason: str
    actor_id: UUID
    created_at: datetime
    expires_at: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "actor_id": str(self.actor_id),
            "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
            "expires_at": self.expires_at.isoformat().replace("+00:00", "Z"),
        }


@dataclass(frozen=True)
class Finding:
    finding_id: UUID
    organization_id: UUID
    fingerprint: str
    check_id: str
    check_version: str
    methodology_version: str
    pillar: str
    subject: Subject
    severity: str
    state: FindingState
    confidence: Confidence
    public_safety_class: str
    first_seen_at: datetime
    last_seen_at: datetime
    evidence: tuple[UUID, ...]
    reason_code: str | None = None
    resolved_at: datetime | None = None
    suppression: Suppression | None = None
    history: tuple[HistoryEntry, ...] = field(default_factory=tuple)

    @property
    def is_visible(self) -> bool:
        """Every state is visible. Suppression changes presentation, never listing."""
        return True

    def as_dict(self, high_minimum: float, medium_minimum: float) -> dict[str, Any]:
        return {
            "contract_version": "v1",
            "finding_id": str(self.finding_id),
            "organization_id": str(self.organization_id),
            "fingerprint": self.fingerprint,
            "check_id": self.check_id,
            "check_version": self.check_version,
            "methodology_version": self.methodology_version,
            "pillar": self.pillar,
            "subject": self.subject.as_dict(),
            "severity": self.severity,
            "state": str(self.state),
            "confidence": self.confidence.as_dict(high_minimum, medium_minimum),
            "public_safety_class": self.public_safety_class,
            "first_seen_at": self.first_seen_at.isoformat().replace("+00:00", "Z"),
            "last_seen_at": self.last_seen_at.isoformat().replace("+00:00", "Z"),
            "resolved_at": None
            if self.resolved_at is None
            else self.resolved_at.isoformat().replace("+00:00", "Z"),
            "evidence": [str(item) for item in self.evidence],
            "suppression": None if self.suppression is None else self.suppression.as_dict(),
            "history": [item.as_dict() for item in self.history],
        }


def fingerprint(
    organization_id: UUID, subject: Subject, check_id: str, material_key: str = ""
) -> str:
    """Stable across assessments: tenant, subject, check and material evidence key only.

    Deliberately excludes assessment id, timestamps and observation ids, so a re-run of
    the same issue matches its own history instead of creating a duplicate.
    """
    parts = (
        str(organization_id),
        str(subject.kind),
        subject.identifier,
        check_id,
        material_key,
    )
    return hashlib.sha256("".join(parts).encode("utf-8")).hexdigest()


def _state_for(result: Result) -> FindingState:
    if result is Result.SUPPRESSED:
        return FindingState.SUPPRESSED
    if result is Result.ACCEPTED_RISK:
        return FindingState.ACCEPTED_RISK
    return FindingState.OPEN


def derive_findings(
    catalog: PolicyCatalog,
    evaluations: Sequence[CheckEvaluation],
    *,
    organization_id: UUID,
    assessment_id: UUID,
    observed_at: datetime,
) -> tuple[Finding, ...]:
    """One finding per evaluation that represents an issue. Passes create nothing."""
    findings: list[Finding] = []
    for evaluation in sorted(evaluations, key=lambda item: item.check_id):
        result = Result(evaluation.result)
        if result not in FINDING_RESULTS:
            continue
        check = catalog.by_id(evaluation.check_id)
        material_key = evaluation.reason_code or ""
        digest = fingerprint(organization_id, evaluation.subject, check.check_id, material_key)
        state = _state_for(result)
        findings.append(
            Finding(
                finding_id=uuid5(FINDING_NAMESPACE, digest),
                organization_id=organization_id,
                fingerprint=digest,
                check_id=check.check_id,
                check_version=check.version,
                methodology_version=catalog.methodology.version,
                pillar=str(check.pillar),
                subject=evaluation.subject,
                severity=str(check.severity),
                state=state,
                confidence=evaluation.confidence,
                public_safety_class=str(check.public_safety_class),
                first_seen_at=observed_at,
                last_seen_at=observed_at,
                evidence=evaluation.observation_ids,
                reason_code=evaluation.reason_code,
                history=(HistoryEntry(observed_at, "absent", str(state), assessment_id),),
            )
        )
    return tuple(findings)


def reconcile(
    previous: Sequence[Finding],
    current: Sequence[Finding],
    *,
    assessment_id: UUID,
    observed_at: datetime,
) -> tuple[Finding, ...]:
    """Merge a new assessment's findings into the existing history.

    A finding that disappears becomes resolved rather than being deleted; one that
    reappears becomes regressed, so the record shows what actually happened.
    """
    by_fingerprint = {item.fingerprint: item for item in previous}
    merged: dict[str, Finding] = {}

    for finding in current:
        existing = by_fingerprint.get(finding.fingerprint)
        if existing is None:
            merged[finding.fingerprint] = finding
            continue
        was_resolved = existing.state is FindingState.RESOLVED
        next_state = FindingState.REGRESSED if was_resolved else existing.state
        if existing.state in {FindingState.OPEN, FindingState.REGRESSED}:
            next_state = existing.state
        if finding.state in {FindingState.SUPPRESSED, FindingState.ACCEPTED_RISK}:
            next_state = finding.state
        history = existing.history
        if next_state is not existing.state:
            history = (
                *history,
                HistoryEntry(observed_at, str(existing.state), str(next_state), assessment_id),
            )
        merged[finding.fingerprint] = replace(
            existing,
            state=next_state,
            last_seen_at=observed_at,
            resolved_at=None,
            evidence=finding.evidence,
            confidence=finding.confidence,
            severity=finding.severity,
            check_version=finding.check_version,
            methodology_version=finding.methodology_version,
            history=history,
        )

    seen = {item.fingerprint for item in current}
    for finding in previous:
        if finding.fingerprint in seen:
            continue
        if finding.state is FindingState.RESOLVED:
            merged.setdefault(finding.fingerprint, finding)
            continue
        merged[finding.fingerprint] = replace(
            finding,
            state=FindingState.RESOLVED,
            resolved_at=observed_at,
            history=(
                *finding.history,
                HistoryEntry(observed_at, str(finding.state), "resolved", assessment_id),
            ),
        )
    return tuple(sorted(merged.values(), key=lambda item: (item.check_id, item.fingerprint)))


def apply_suppression(
    finding: Finding,
    *,
    reason: str,
    actor_id: UUID,
    now: datetime,
    expires_at: datetime,
    accepted_risk: bool = False,
    assessment_id: UUID,
) -> Finding:
    """Suppression requires a reason, an actor and an expiry; none of them are optional."""
    if len(reason.strip()) < 8:
        raise ValueError("suppression_requires_reason")
    if expires_at <= now:
        raise ValueError("suppression_must_expire_in_the_future")
    target = FindingState.ACCEPTED_RISK if accepted_risk else FindingState.SUPPRESSED
    return replace(
        finding,
        state=target,
        suppression=Suppression(reason.strip(), actor_id, now, expires_at),
        history=(
            *finding.history,
            HistoryEntry(now, str(finding.state), str(target), assessment_id, actor_id),
        ),
    )


def expire_suppressions(
    findings: Sequence[Finding], *, now: datetime, assessment_id: UUID
) -> tuple[Finding, ...]:
    """An expired suppression returns the finding to open; it never lapses into a pass."""
    result: list[Finding] = []
    for finding in findings:
        suppression = finding.suppression
        if suppression is None or now < suppression.expires_at:
            result.append(finding)
            continue
        result.append(
            replace(
                finding,
                state=FindingState.OPEN,
                suppression=None,
                history=(
                    *finding.history,
                    HistoryEntry(now, str(finding.state), "open", assessment_id),
                ),
            )
        )
    return tuple(result)


def attribute_change(
    previous_snapshot_score: float | None,
    current_snapshot_score: float | None,
    previous_methodology: str,
    current_methodology: str,
) -> dict[str, Any]:
    """Separate observed control change from methodology effect; never conflate them."""
    if previous_snapshot_score is None or current_snapshot_score is None:
        return {
            "comparable": False,
            "reason": "insufficient_score",
            "delta": None,
            "methodology_changed": previous_methodology != current_methodology,
        }
    if previous_methodology != current_methodology:
        return {
            "comparable": False,
            "reason": "methodology_version_differs",
            "delta": round(current_snapshot_score - previous_snapshot_score, 1),
            "methodology_changed": True,
        }
    return {
        "comparable": True,
        "reason": "same_methodology",
        "delta": round(current_snapshot_score - previous_snapshot_score, 1),
        "methodology_changed": False,
    }
