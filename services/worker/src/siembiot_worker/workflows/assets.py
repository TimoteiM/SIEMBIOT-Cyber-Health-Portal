"""Asset attribution.

Discovery is not ownership. A name observed in Certificate Transparency or DNS is a
*candidate*: it carries how confident we are that it belongs to this organization and on
what basis, and it stays unreviewed until a person decides. Nothing enters assessment
scope because a log mentioned it.

Two consequences run through this module:

* a candidate's confidence is never rounded up to certainty, and shared-hosting context
  lowers it further, because one tenant's certificate says nothing about another's;
* accepting a candidate is an authorization decision, so it records who made it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

SHARED_HOSTING_CONFIDENCE_CEILING = 0.4


class CandidateState(StrEnum):
    UNREVIEWED = "unreviewed"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class CandidateSource(StrEnum):
    CERTIFICATE_TRANSPARENCY = "certificate_transparency"
    DNS = "dns"
    USER_DECLARED = "user_declared"
    PASSIVE_INTELLIGENCE = "passive_intelligence"


class AttributionBasis(StrEnum):
    AUTHORIZED_DOMAIN = "authorized_domain"
    SUBDOMAIN = "subdomain_of_authorized_domain"
    UNRELATED = "unrelated_name"


class AssetError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class AssetCandidate:
    name: str
    source: CandidateSource
    attribution_confidence: float
    attribution_basis: AttributionBasis
    first_seen_at: datetime
    last_seen_at: datetime
    observation_count: int = 1
    shared_hosting: bool = False
    state: CandidateState = CandidateState.UNREVIEWED

    def __post_init__(self) -> None:
        if not 0.0 <= self.attribution_confidence <= 1.0:
            raise AssetError("confidence_out_of_range")
        if self.last_seen_at < self.first_seen_at:
            raise AssetError("last_seen_before_first_seen")

    @property
    def in_scope(self) -> bool:
        """Only an accepted candidate may be assessed. Unreviewed is not implicit yes."""
        return self.state is CandidateState.ACCEPTED

    @property
    def needs_review(self) -> bool:
        return self.state is CandidateState.UNREVIEWED


@dataclass(frozen=True)
class CandidateDecision:
    candidate_name: str
    decision: CandidateState
    actor_id: UUID
    decided_at: datetime
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.decision is CandidateState.UNREVIEWED:
            raise AssetError("decision_must_accept_or_reject")


def apply_shared_hosting_context(
    candidate: AssetCandidate, *, shared_hosting: bool
) -> AssetCandidate:
    """Lower confidence when the address is shared.

    A certificate or an address shared by many tenants is weak evidence of ownership,
    so it caps confidence rather than merely annotating it. The brief is explicit that
    a shared-hosting observation must never on its own drive a conclusion.
    """
    if not shared_hosting:
        return candidate
    return replace(
        candidate,
        shared_hosting=True,
        attribution_confidence=min(
            candidate.attribution_confidence, SHARED_HOSTING_CONFIDENCE_CEILING
        ),
    )


def merge_observation(existing: AssetCandidate, observed: AssetCandidate) -> AssetCandidate:
    """Fold a new sighting into a known candidate without resetting a human decision.

    A re-sighting updates when it was last seen and how often, and may raise confidence
    if the new basis is stronger. It never returns an accepted or rejected candidate to
    unreviewed, because that would silently undo somebody's decision.
    """
    if existing.name != observed.name:
        raise AssetError("cannot_merge_different_names")
    return replace(
        existing,
        attribution_confidence=max(
            existing.attribution_confidence, observed.attribution_confidence
        ),
        attribution_basis=_stronger_basis(existing.attribution_basis, observed.attribution_basis),
        first_seen_at=min(existing.first_seen_at, observed.first_seen_at),
        last_seen_at=max(existing.last_seen_at, observed.last_seen_at),
        observation_count=existing.observation_count + observed.observation_count,
        shared_hosting=existing.shared_hosting or observed.shared_hosting,
    )


_BASIS_STRENGTH = {
    AttributionBasis.UNRELATED: 0,
    AttributionBasis.SUBDOMAIN: 1,
    AttributionBasis.AUTHORIZED_DOMAIN: 2,
}


def _stronger_basis(left: AttributionBasis, right: AttributionBasis) -> AttributionBasis:
    return left if _BASIS_STRENGTH[left] >= _BASIS_STRENGTH[right] else right


def decide(
    candidate: AssetCandidate,
    decision: CandidateState,
    *,
    actor_id: UUID,
    at: datetime,
    reason: str | None = None,
) -> tuple[AssetCandidate, CandidateDecision]:
    """Accept or reject a candidate, returning the new state and its audit record."""
    if decision is CandidateState.UNREVIEWED:
        raise AssetError("decision_must_accept_or_reject")
    if candidate.state is decision:
        raise AssetError("decision_is_a_no_op")
    return (
        replace(candidate, state=decision),
        CandidateDecision(candidate.name, decision, actor_id, at, reason),
    )


def candidates_from_ct(
    payload: Mapping[str, Any], *, observed_at: datetime
) -> tuple[AssetCandidate, ...]:
    """Turn a Certificate Transparency collection payload into reviewable candidates."""
    raw = payload.get("candidates")
    if not isinstance(raw, list):
        return ()
    candidates: list[AssetCandidate] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        basis = item.get("attribution_basis")
        confidence = item.get("confidence")
        if not isinstance(name, str) or not isinstance(basis, str):
            continue
        if not isinstance(confidence, int | float) or isinstance(confidence, bool):
            continue
        try:
            attribution = AttributionBasis(basis)
        except ValueError:
            continue
        candidates.append(
            AssetCandidate(
                name=name,
                source=CandidateSource.CERTIFICATE_TRANSPARENCY,
                attribution_confidence=float(confidence),
                attribution_basis=attribution,
                first_seen_at=observed_at,
                last_seen_at=observed_at,
                observation_count=int(item.get("observation_count", 1) or 1),
            )
        )
    return tuple(sorted(candidates, key=lambda item: (-item.attribution_confidence, item.name)))


def review_summary(candidates: tuple[AssetCandidate, ...]) -> dict[str, int]:
    """Counts for the review queue. Unreviewed is reported, never assumed away."""
    return {
        "total": len(candidates),
        "unreviewed": sum(1 for item in candidates if item.needs_review),
        "accepted": sum(1 for item in candidates if item.state is CandidateState.ACCEPTED),
        "rejected": sum(1 for item in candidates if item.state is CandidateState.REJECTED),
        "low_confidence": sum(1 for item in candidates if item.attribution_confidence < 0.5),
    }
