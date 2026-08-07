"""Cohort statistics, and the size below which a statistic names somebody.

"73% of published domains enforce DMARC" is the kind of sentence this product exists to
make possible. "One of the two published county hospitals does not" is the same sentence
with the anonymity removed, and nobody had to be careless for it to happen -- it is what
a small denominator does on its own.

So a cohort below the threshold produces nothing at all. Not a rounded number, not a
range, not "fewer than five": suppressed entirely, because a suppression that appears
only where the count is small is itself a signal, and an observer who can see which
cohorts are missing learns most of what the suppression was hiding.

The threshold also exists as a CHECK constraint on the table. This module could have a
bug; the constraint means that bug fails loudly at the insert rather than quietly on a
public page.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from siembiot.publication.projection import PUBLISHABLE_RESULTS

#: Kept in step with the CHECK constraint in migration 0015. Five is a judgement, and
#: the reasoning is worth stating so somebody can disagree with the reasoning rather
#: than the number: below five, knowing one member of the cohort and the published
#: proportion is often enough to infer another member's result.
MINIMUM_COHORT_SIZE = 5

SUCCEEDED = "pass"


@dataclass(frozen=True)
class Aggregate:
    check_id: str
    cohort_size: int
    pass_count: int

    @property
    def pass_percentage(self) -> float:
        return round(self.pass_count / self.cohort_size * 100, 1)


def aggregate_checks(
    profiles: Iterable[dict[str, str]], *, minimum: int = MINIMUM_COHORT_SIZE
) -> tuple[Aggregate, ...]:
    """Count outcomes per check across published profiles, dropping thin cohorts.

    `profiles` is one mapping of check_id to result per published profile. Only results
    that were publishable in the first place are counted, so a check that could not be
    evaluated does not quietly shrink its own denominator relative to the others -- each
    check gets the cohort that actually has an answer for it.
    """
    totals: dict[str, list[int]] = {}
    for profile in profiles:
        for check_id, result in profile.items():
            if result not in PUBLISHABLE_RESULTS:
                continue
            entry = totals.setdefault(check_id, [0, 0])
            entry[0] += 1
            if result == SUCCEEDED:
                entry[1] += 1

    return tuple(
        Aggregate(check_id=check_id, cohort_size=size, pass_count=passes)
        for check_id, (size, passes) in sorted(totals.items())
        if size >= minimum
    )
