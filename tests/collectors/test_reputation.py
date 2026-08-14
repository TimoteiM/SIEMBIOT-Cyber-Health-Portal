"""The reputation collector, and the states it must keep apart.

Golden fixtures only — no provider is contacted here and none can be, because the
collector takes its providers as an argument and the tests hand it objects that answer
from memory. That is not a testing convenience; it is why a blocklist key is not needed
to run the suite, and why nobody's rate limit is spent by CI.

The states below map one-to-one onto what `E.domain_reputation_clean` does with them:

* no providers configured -> inconclusive -> unknown, `reputation_provider_unconfigured`
* every provider says clean -> observed -> pass
* every provider says listed -> observed -> warning, `reputation_listing_present`
* providers disagree -> observed, contested -> unknown, `provider_disagreement`
* every provider unreachable -> inconclusive -> unknown
* one of two unreachable -> observed, partial, the unavailable one named
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "worker" / "src"))

from siembiot_worker.adapters.contract import CollectionStatus  # noqa: E402
from siembiot_worker.collectors.reputation import (  # noqa: E402
    Listing,
    ProviderVerdict,
    ReputationCollector,
    combine,
)

HOST = "primaria-exemplu.ro"


class Fixture:
    """A provider that answers from memory. Satisfies the whole `ReputationProvider`
    protocol, which is short enough that this is not a pretence."""

    def __init__(self, name: str, listing: Listing) -> None:
        self._name = name
        self._listing = listing

    @property
    def name(self) -> str:
        return self._name

    def lookup(self, host: str) -> ProviderVerdict:
        del host
        return ProviderVerdict(self._name, self._listing)


class Broken:
    """A provider that raises. One source failing must not lose the others."""

    @property
    def name(self) -> str:
        return "broken"

    def lookup(self, host: str) -> ProviderVerdict:
        del host
        raise TimeoutError("provider did not answer")


# -- the state that matters most -----------------------------------------------------------


def test_no_provider_configured_is_unavailable_not_clean() -> None:
    """The failure that would matter most, and the one a boolean would have caused.

    A platform with no reputation key must report that it does not know. Reporting
    `not listed` would give every institution a clean reputation result produced by
    nobody having looked -- and it would be indistinguishable, on the page, from a
    genuine all-clear.
    """
    result = ReputationCollector().collect(HOST)

    assert result.status is CollectionStatus.UNAVAILABLE
    assert result.reason_code == "reputation_provider_unconfigured"
    assert result.payload.get("listed") is not False


def test_every_provider_unreachable_is_unavailable_not_clean() -> None:
    """Same principle one layer along: an outage is not an all-clear."""
    result = ReputationCollector((Broken(), Broken())).collect(HOST)

    assert result.status is CollectionStatus.UNAVAILABLE
    assert result.reason_code == "reputation_providers_unreachable"


# -- the ordinary states -------------------------------------------------------------------


def test_all_clean_is_ok_and_not_listed() -> None:
    result = ReputationCollector(
        (Fixture("spamhaus", Listing.NOT_LISTED), Fixture("otx", Listing.NOT_LISTED))
    ).collect(HOST)

    assert result.status is CollectionStatus.OK
    assert result.payload["listed"] is False
    assert result.payload["contested"] is False


def test_all_listed_is_ok_and_listed() -> None:
    result = ReputationCollector(
        (Fixture("spamhaus", Listing.LISTED), Fixture("otx", Listing.LISTED))
    ).collect(HOST)

    assert result.payload["listed"] is True
    assert result.payload["contested"] is False
    assert result.payload["providers_listing"] == ["otx", "spamhaus"]


def test_disagreement_is_carried_through_rather_than_resolved() -> None:
    """Two providers differing about a public institution is information.

    A collector that picked a winner -- by majority, by trusting the more authoritative
    source, by any rule -- would be inventing certainty the sources do not have. The
    policy check turns `contested` into `unknown`, which is the honest answer.
    """
    result = ReputationCollector(
        (Fixture("spamhaus", Listing.LISTED), Fixture("otx", Listing.NOT_LISTED))
    ).collect(HOST)

    assert result.payload["contested"] is True
    assert result.payload["listed"] is True


def test_one_provider_failing_does_not_lose_the_other() -> None:
    result = ReputationCollector((Fixture("spamhaus", Listing.LISTED), Broken())).collect(HOST)

    assert result.status is CollectionStatus.PARTIAL
    assert result.payload["listed"] is True
    assert result.payload["providers_unavailable"] == ["broken"]
    assert result.partial_reasons == ("unavailable:broken",)


def test_an_unreachable_provider_is_not_counted_as_disagreeing() -> None:
    """Otherwise every outage looks like a contested result, and `unknown` -- which is
    meant to be rare and meaningful -- becomes the normal answer."""
    summary = combine(
        (
            ProviderVerdict("spamhaus", Listing.LISTED),
            ProviderVerdict("otx", Listing.UNAVAILABLE),
        )
    )

    assert summary.listed is True
    assert summary.contested is False


def test_more_providers_than_the_cap_is_refused() -> None:
    import pytest

    with pytest.raises(ValueError, match="too_many_reputation_providers"):
        ReputationCollector(tuple(Fixture(f"p{i}", Listing.NOT_LISTED) for i in range(9)))


# -- normalization ------------------------------------------------------------------------


def test_unavailable_normalizes_to_inconclusive_not_absent() -> None:
    """`absent` would read as "no provider lists this domain" -- a clean result. What
    happened is that nobody was asked, and the two must not render the same."""
    from siembiot_worker.policy.evidence import ObservationStatus, Subject, SubjectKind
    from siembiot_worker.policy.normalization import normalize_reputation

    result = ReputationCollector().collect(HOST)
    observations = normalize_reputation(
        result,
        organization_id=uuid4(),
        assessment_id=uuid4(),
        subject=Subject(kind=SubjectKind.DOMAIN, identifier=HOST),
        now=datetime.now(UTC),
        window_seconds=86_400,
    )

    assert len(observations) == 1
    assert observations[0].status is ObservationStatus.INCONCLUSIVE
    assert observations[0].observation_type == "reputation.domain"


def test_a_listing_normalizes_with_the_attributes_the_check_matches_on() -> None:
    """The contract between this collector and the policy catalogue. If these attribute
    names drift, the check silently stops matching and every domain reports unknown."""
    from siembiot_worker.policy.evidence import ObservationStatus, Subject, SubjectKind
    from siembiot_worker.policy.normalization import normalize_reputation

    result = ReputationCollector((Fixture("spamhaus", Listing.LISTED),)).collect(HOST)
    observation = normalize_reputation(
        result,
        organization_id=uuid4(),
        assessment_id=uuid4(),
        subject=Subject(kind=SubjectKind.DOMAIN, identifier=HOST),
        now=datetime.now(UTC),
        window_seconds=86_400,
    )[0]

    assert observation.status is ObservationStatus.OBSERVED
    assert observation.attributes["listed"] is True
    assert "contested" in observation.attributes
