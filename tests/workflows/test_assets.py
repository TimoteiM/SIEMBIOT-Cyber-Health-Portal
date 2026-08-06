"""Asset attribution.

The property under test throughout: discovery is not ownership. A candidate never
enters scope by being observed, and a human decision is never silently undone.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from siembiot_worker.workflows.assets import (
    SHARED_HOSTING_CONFIDENCE_CEILING,
    AssetCandidate,
    AssetError,
    AttributionBasis,
    CandidateSource,
    CandidateState,
    apply_shared_hosting_context,
    candidates_from_ct,
    decide,
    merge_observation,
    review_summary,
)

NOW = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
LATER = NOW + timedelta(days=3)
ACTOR = uuid4()


def candidate(
    name: str = "www.example.test",
    confidence: float = 0.9,
    basis: AttributionBasis = AttributionBasis.SUBDOMAIN,
    state: CandidateState = CandidateState.UNREVIEWED,
    seen: datetime = NOW,
) -> AssetCandidate:
    return AssetCandidate(
        name=name,
        source=CandidateSource.CERTIFICATE_TRANSPARENCY,
        attribution_confidence=confidence,
        attribution_basis=basis,
        first_seen_at=seen,
        last_seen_at=seen,
        state=state,
    )


# -- scope -------------------------------------------------------------------


def test_an_unreviewed_candidate_is_not_in_scope() -> None:
    assert candidate().in_scope is False
    assert candidate().needs_review is True


def test_only_an_accepted_candidate_is_in_scope() -> None:
    assert candidate(state=CandidateState.ACCEPTED).in_scope is True
    assert candidate(state=CandidateState.REJECTED).in_scope is False


def test_a_candidate_cannot_claim_impossible_confidence() -> None:
    with pytest.raises(AssetError, match="confidence_out_of_range"):
        candidate(confidence=1.5)
    with pytest.raises(AssetError, match="confidence_out_of_range"):
        candidate(confidence=-0.1)


def test_a_candidate_cannot_be_last_seen_before_it_was_first_seen() -> None:
    with pytest.raises(AssetError, match="last_seen_before_first_seen"):
        AssetCandidate(
            name="x.example.test",
            source=CandidateSource.DNS,
            attribution_confidence=0.5,
            attribution_basis=AttributionBasis.SUBDOMAIN,
            first_seen_at=LATER,
            last_seen_at=NOW,
        )


# -- shared hosting ----------------------------------------------------------


def test_shared_hosting_caps_confidence_rather_than_merely_noting_it() -> None:
    """One tenant's certificate says nothing about another's ownership."""
    capped = apply_shared_hosting_context(candidate(confidence=0.9), shared_hosting=True)
    assert capped.shared_hosting is True
    assert capped.attribution_confidence == SHARED_HOSTING_CONFIDENCE_CEILING


def test_shared_hosting_never_raises_a_lower_confidence() -> None:
    capped = apply_shared_hosting_context(candidate(confidence=0.2), shared_hosting=True)
    assert capped.attribution_confidence == 0.2


def test_dedicated_hosting_leaves_confidence_untouched() -> None:
    unchanged = apply_shared_hosting_context(candidate(confidence=0.9), shared_hosting=False)
    assert unchanged.attribution_confidence == 0.9
    assert unchanged.shared_hosting is False


# -- merging observations ----------------------------------------------------


def test_a_re_sighting_extends_the_window_and_counts() -> None:
    merged = merge_observation(candidate(seen=NOW), candidate(seen=LATER))
    assert merged.first_seen_at == NOW
    assert merged.last_seen_at == LATER
    assert merged.observation_count == 2


def test_a_stronger_basis_wins_when_merging() -> None:
    merged = merge_observation(
        candidate(basis=AttributionBasis.UNRELATED, confidence=0.2),
        candidate(basis=AttributionBasis.AUTHORIZED_DOMAIN, confidence=1.0),
    )
    assert merged.attribution_basis is AttributionBasis.AUTHORIZED_DOMAIN
    assert merged.attribution_confidence == 1.0


def test_a_weaker_later_sighting_does_not_downgrade_a_strong_one() -> None:
    merged = merge_observation(
        candidate(basis=AttributionBasis.AUTHORIZED_DOMAIN, confidence=1.0),
        candidate(basis=AttributionBasis.UNRELATED, confidence=0.2),
    )
    assert merged.attribution_basis is AttributionBasis.AUTHORIZED_DOMAIN


def test_shared_hosting_is_sticky_across_merges() -> None:
    marked = apply_shared_hosting_context(candidate(), shared_hosting=True)
    merged = merge_observation(marked, candidate())
    assert merged.shared_hosting is True


def test_merging_preserves_a_human_decision() -> None:
    """A new sighting must not quietly return a decided candidate to the review queue."""
    for state in (CandidateState.ACCEPTED, CandidateState.REJECTED):
        merged = merge_observation(candidate(state=state), candidate(seen=LATER))
        assert merged.state is state


def test_candidates_with_different_names_cannot_be_merged() -> None:
    with pytest.raises(AssetError, match="cannot_merge_different_names"):
        merge_observation(candidate("a.example.test"), candidate("b.example.test"))


# -- decisions ---------------------------------------------------------------


def test_accepting_a_candidate_records_who_decided() -> None:
    updated, record = decide(
        candidate(), CandidateState.ACCEPTED, actor_id=ACTOR, at=NOW, reason="Ours"
    )
    assert updated.in_scope is True
    assert record.actor_id == ACTOR
    assert record.decision is CandidateState.ACCEPTED
    assert record.reason == "Ours"


def test_rejecting_a_candidate_keeps_it_out_of_scope() -> None:
    updated, record = decide(candidate(), CandidateState.REJECTED, actor_id=ACTOR, at=NOW)
    assert updated.in_scope is False
    assert record.decision is CandidateState.REJECTED


def test_a_decision_cannot_return_a_candidate_to_unreviewed() -> None:
    with pytest.raises(AssetError, match="decision_must_accept_or_reject"):
        decide(candidate(), CandidateState.UNREVIEWED, actor_id=ACTOR, at=NOW)


def test_repeating_a_decision_is_refused_rather_than_duplicating_the_record() -> None:
    with pytest.raises(AssetError, match="decision_is_a_no_op"):
        decide(
            candidate(state=CandidateState.ACCEPTED),
            CandidateState.ACCEPTED,
            actor_id=ACTOR,
            at=NOW,
        )


# -- from collector output ---------------------------------------------------


def test_ct_payload_becomes_reviewable_candidates_ordered_by_confidence() -> None:
    payload = {
        "candidates": [
            {
                "name": "unrelated.hosting.test",
                "confidence": 0.2,
                "attribution_basis": "unrelated_name",
                "observation_count": 1,
            },
            {
                "name": "example.test",
                "confidence": 1.0,
                "attribution_basis": "authorized_domain",
                "observation_count": 3,
            },
        ]
    }
    candidates = candidates_from_ct(payload, observed_at=NOW)
    assert [item.name for item in candidates] == ["example.test", "unrelated.hosting.test"]
    assert all(item.needs_review for item in candidates)
    assert candidates[0].observation_count == 3


def test_malformed_ct_entries_are_skipped_rather_than_guessed() -> None:
    payload = {
        "candidates": [
            "not-a-dict",
            {"name": 5, "confidence": 1.0, "attribution_basis": "authorized_domain"},
            {"name": "x.test", "confidence": "high", "attribution_basis": "authorized_domain"},
            {"name": "y.test", "confidence": 1.0, "attribution_basis": "invented_basis"},
            {
                "name": "z.test",
                "confidence": 0.9,
                "attribution_basis": "subdomain_of_authorized_domain",
            },
        ]
    }
    candidates = candidates_from_ct(payload, observed_at=NOW)
    assert [item.name for item in candidates] == ["z.test"]


def test_a_payload_without_candidates_yields_nothing() -> None:
    assert candidates_from_ct({}, observed_at=NOW) == ()
    assert candidates_from_ct({"candidates": "nope"}, observed_at=NOW) == ()


def test_the_review_summary_reports_what_is_still_unreviewed() -> None:
    summary = review_summary(
        (
            candidate("a.test", state=CandidateState.ACCEPTED),
            candidate("b.test", state=CandidateState.REJECTED),
            candidate("c.test", confidence=0.2),
        )
    )
    assert summary == {
        "total": 3,
        "unreviewed": 1,
        "accepted": 1,
        "rejected": 1,
        "low_confidence": 1,
    }
