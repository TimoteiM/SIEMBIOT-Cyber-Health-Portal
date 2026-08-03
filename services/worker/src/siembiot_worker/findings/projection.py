from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from siembiot_worker.findings.events import FindingEvent, FindingEventType


@dataclass(frozen=True)
class FindingProjection:
    finding_id: str
    state: str
    first_seen_at: datetime
    last_event_at: datetime
    review_due: bool
    events: tuple[FindingEvent, ...]


def project_finding(events: tuple[FindingEvent, ...], *, as_of: datetime) -> FindingProjection:
    if not events:
        raise ValueError("empty_finding_history")
    ordered = tuple(sorted(events, key=lambda item: (item.occurred_at, item.event_id)))
    first = ordered[0]
    if first.event_type is not FindingEventType.OBSERVED:
        raise ValueError("finding_history_must_start_observed")
    if any(
        item.finding_id != first.finding_id or item.organization_id != first.organization_id
        for item in ordered
    ):
        raise ValueError("mixed_finding_history")
    state = "open"
    review_at = None
    for item in ordered:
        if item.event_type is FindingEventType.SUPPRESSED:
            state, review_at = "suppressed", item.review_at
        elif item.event_type is FindingEventType.ACCEPTED_RISK:
            state, review_at = "accepted_risk", item.review_at
        elif item.event_type in {FindingEventType.REOPENED, FindingEventType.EXPIRED_REVIEW}:
            state, review_at = "open", None
        elif item.event_type is FindingEventType.REMEDIATION_VERIFIED:
            state, review_at = "verified", None
    return FindingProjection(
        first.finding_id,
        state,
        first.occurred_at,
        ordered[-1].occurred_at,
        review_at is not None and as_of >= review_at,
        ordered,
    )
