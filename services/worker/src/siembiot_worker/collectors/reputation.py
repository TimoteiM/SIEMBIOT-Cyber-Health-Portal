"""Reputation and abuse signals (pillar E).

**A listing is not a hygiene failure, and this collector is built so it cannot become
one.** Every other collector here measures configuration: what the institution published,
how it is set up, what it chose. Reputation measures an *outcome* — usually abuse,
sometimes a compromised neighbour on shared hosting, sometimes a listing nobody has got
round to withdrawing. Fold the two together and an institution that was configured well
and got attacked scores identically to one configured badly that has not been caught yet,
which destroys the only thing a hygiene score is for.

So `E.domain_reputation_clean` resolves to `warning`, never `fail`, and lives in its own
pillar. That is a decision recorded in the policy catalogue rather than here, and it
should stay there: it is the sort of thing that gets "simplified" later by somebody who
does not know why it was separated.

**Provider-neutral by construction.** This module knows how to ask several providers the
same question and how to combine disagreeing answers. It knows nothing about Spamhaus or
OTX specifically — those are `ReputationProvider` implementations supplied at
construction, which is what lets the whole path be tested with no network at all.

**No provider is wired in yet.** Spamhaus's terms do not address using their data inside
a tool offered to other organisations or displaying results to them, and building against
a guess about somebody else's acceptable-use policy is how a free community tool acquires
a legal problem. The socket is finished; the plug waits for a written answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from siembiot_worker.adapters.contract import (
    CollectionResult,
    CollectionStatus,
    Provenance,
)
from siembiot_worker.collectors.base import Clock, utc_now

#: How many providers may be consulted for one subject. Reputation providers are the
#: only sources here whose answers are opinions rather than measurements, and the value
#: of a third opinion is much lower than the cost of another dependency.
MAX_PROVIDERS = 4


class Listing(StrEnum):
    """What one provider says. `UNAVAILABLE` is not `NOT_LISTED`.

    That distinction is the whole reason this is an enum rather than a boolean. A
    provider that could not be reached has said nothing, and recording silence as a
    clean result is how an unconfigured key becomes a clean bill of health.
    """

    LISTED = "listed"
    NOT_LISTED = "not_listed"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class ProviderVerdict:
    provider: str
    listing: Listing
    #: Free-text only for the operator, never rendered to an institution. A provider's
    #: own wording about why something is listed is theirs, not ours to republish.
    detail: str | None = None


class ReputationProvider(Protocol):
    """One source of reputation opinion.

    Deliberately tiny. Everything a provider needs to do is answer one question about
    one host, which means a fixture satisfies it without pretending to be a network.
    """

    @property
    def name(self) -> str: ...

    def lookup(self, host: str) -> ProviderVerdict: ...


@dataclass(frozen=True)
class ReputationSummary:
    """The combined answer, in the shape the policy check reads.

    `listed` and `contested` are the two attributes `E.domain_reputation_clean` matches
    on, and `contested` exists so that disagreement resolves to `unknown` rather than
    being settled by majority vote. Providers disagreeing about an institution is
    information; averaging it away is not.
    """

    listed: bool
    contested: bool
    providers_consulted: tuple[str, ...]
    providers_listing: tuple[str, ...]
    providers_unavailable: tuple[str, ...]

    @property
    def anybody_answered(self) -> bool:
        return len(self.providers_consulted) > len(self.providers_unavailable)


def combine(verdicts: tuple[ProviderVerdict, ...]) -> ReputationSummary:
    """Combine provider opinions without averaging away a disagreement."""
    listing = tuple(sorted(v.provider for v in verdicts if v.listing is Listing.LISTED))
    clean = tuple(sorted(v.provider for v in verdicts if v.listing is Listing.NOT_LISTED))
    unavailable = tuple(sorted(v.provider for v in verdicts if v.listing is Listing.UNAVAILABLE))

    return ReputationSummary(
        listed=bool(listing),
        # Only among providers that actually answered. A provider that was unreachable
        # has not disagreed with anybody, and treating its silence as dissent would make
        # every outage look like a contested result.
        contested=bool(listing) and bool(clean),
        providers_consulted=tuple(sorted(v.provider for v in verdicts)),
        providers_listing=listing,
        providers_unavailable=unavailable,
    )


class ReputationCollector:
    """Ask every configured provider, and report what they said.

    Not a `Collector` subclass: it makes no network request of its own. Providers own
    their transport, which is what keeps a DNS-based blocklist and an HTTP threat-intel
    API behind one interface without this module knowing which is which.
    """

    def __init__(
        self,
        providers: tuple[ReputationProvider, ...] = (),
        clock: Clock | None = None,
    ) -> None:
        if len(providers) > MAX_PROVIDERS:
            raise ValueError("too_many_reputation_providers")
        self._providers = providers
        self._clock = clock or utc_now

    def collect(self, host: str) -> CollectionResult:
        collected_at = self._clock()
        provenance = Provenance(
            adapter_id="reputation_multi",
            adapter_version="1.0.0",
            collected_at=collected_at,
            observed_at=collected_at,
            from_cache=False,
            source_reference=None,
        )

        if not self._providers:
            # Unconfigured, and said so by name. The policy check turns this into
            # `unknown` with `reputation_provider_unconfigured` rather than a pass: a
            # tool with no reputation key must not report a clean reputation.
            return CollectionResult(
                status=CollectionStatus.UNAVAILABLE,
                provenance=provenance,
                reason_code="reputation_provider_unconfigured",
            )

        verdicts: list[ProviderVerdict] = []
        for provider in self._providers:
            try:
                verdicts.append(provider.lookup(host))
            except Exception:  # noqa: BLE001 - one provider failing must not lose the rest
                verdicts.append(ProviderVerdict(provider.name, Listing.UNAVAILABLE))

        summary = combine(tuple(verdicts))
        payload = {
            "listed": summary.listed,
            "contested": summary.contested,
            "providers_consulted": list(summary.providers_consulted),
            "providers_listing": list(summary.providers_listing),
            "providers_unavailable": list(summary.providers_unavailable),
        }

        if not summary.anybody_answered:
            return CollectionResult(
                status=CollectionStatus.UNAVAILABLE,
                provenance=provenance,
                payload=payload,
                reason_code="reputation_providers_unreachable",
            )

        if summary.providers_unavailable:
            return CollectionResult(
                status=CollectionStatus.PARTIAL,
                provenance=provenance,
                payload=payload,
                reason_code="reputation_provider_partial",
                partial_reasons=tuple(
                    f"unavailable:{name}" for name in summary.providers_unavailable
                ),
            )

        return CollectionResult(status=CollectionStatus.OK, provenance=provenance, payload=payload)
