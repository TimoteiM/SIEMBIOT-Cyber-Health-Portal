"""Turning a private assessment into a public profile, by allowlist.

The direction matters more than anything else here. A denylist -- "copy the row, remove
the private fields" -- fails open: a column added to `findings` next year is published
by default, by whoever adds it, who is not thinking about publication at the time. An
allowlist fails closed: a new column is invisible until somebody names it here, in a
file whose entire subject is what may be made public.

So nothing is copied. Every field of a public profile is constructed explicitly from
named inputs, and the dataclasses below are the complete list of what a published
profile can contain. There is no dict passthrough anywhere in this module, and adding
one would defeat it.

What may be published about a *check* is not decided here either. The policy catalogue
already classifies every check, and that classification is versioned with the
methodology and reviewed alongside it. Keeping a second list in this file would let the
two disagree, and the way that disagreement would surface is a check the catalogue calls
private appearing on a public page.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache

from siembiot.check_metadata import load_check_metadata

#: The only class of check that may appear on a named institution's public profile.
#: `public_aggregate` -- if the catalogue ever uses it -- would mean countable but not
#: attributable, and is deliberately absent here rather than treated as a weaker
#: `public_profile`.
PUBLIC_PROFILE_CLASS = "public_profile"

#: Results that describe the domain. `unknown` and `error` describe our collection
#: instead -- a resolver that timed out is a fact about us -- and publishing them beside
#: real outcomes would attribute our failure to somebody else's infrastructure.
#: `not_applicable`, `suppressed` and `accepted_risk` are private judgements about scope
#: and risk acceptance, and are nobody else's business.
PUBLISHABLE_RESULTS = frozenset({"pass", "fail", "warning"})

#: Ownership states from which a profile may be published. Passive observation runs
#: against unverified domains on purpose -- it reads only what is already published --
#: but attaching a security posture to an institution's name is a different act, and
#: doing it for a domain nobody proved they control is publishing about a third party.
PUBLISHABLE_OWNERSHIP = frozenset({"verified"})


class ProjectionRefusedError(RuntimeError):
    """Publication was declined. Always names the reason, never a generic failure."""


@dataclass(frozen=True)
class ProfileCheck:
    check_id: str
    result: str


@dataclass(frozen=True)
class Profile:
    """The complete contents of a public profile.

    If a field is not here it cannot be published, and adding one is a visible change to
    a file about publication rather than an invisible consequence of a change elsewhere.
    """

    registrable_domain: str
    #: None where coverage was too low. The public side withholds for the same reason
    #: the private side does, and more so: a caveat does not survive being screenshotted.
    band: str | None
    coverage_percentage: float
    methodology_version: str
    policy_digest: str
    observed_at: datetime
    checks: tuple[ProfileCheck, ...]


@lru_cache(maxsize=8)
def publishable_check_ids(methodology_version: str = "1.0.0") -> frozenset[str]:
    """Checks the catalogue permits on a public profile.

    Read from the catalogue every time rather than copied, so reclassifying a check to
    `private_only` takes it off public pages by editing the policy that says so.
    """
    metadata = load_check_metadata(methodology_version)
    return frozenset(
        check_id
        for check_id, entry in metadata.items()
        if entry.public_safety_class == PUBLIC_PROFILE_CLASS
    )


def project_profile(
    *,
    registrable_domain: str,
    ownership_state: str,
    has_active_consent: bool,
    is_taken_down: bool,
    band: str | None,
    coverage_sufficient: bool,
    coverage_percentage: float,
    methodology_version: str,
    policy_digest: str,
    observed_at: datetime,
    evaluations: dict[str, str],
) -> Profile:
    """Build the public profile for one domain, or refuse and say why.

    Every refusal below is checked before anything is constructed, so a partially built
    profile never exists to be accidentally written.
    """
    if is_taken_down:
        # First, and outranking consent. A takedown is somebody outside the tenant
        # saying this should not be public; letting the tenant's own switch override it
        # would make the moderation control advisory.
        raise ProjectionRefusedError(f"{registrable_domain}: a takedown is recorded")

    if not has_active_consent:
        raise ProjectionRefusedError(f"{registrable_domain}: no active consent")

    if ownership_state not in PUBLISHABLE_OWNERSHIP:
        raise ProjectionRefusedError(
            f"{registrable_domain}: control is {ownership_state}, not verified"
        )

    permitted = publishable_check_ids(methodology_version)
    checks = tuple(
        ProfileCheck(check_id=check_id, result=result)
        for check_id, result in sorted(evaluations.items())
        # Both conditions, and neither is redundant: the first keeps private checks off
        # the page, the second keeps our own collection failures from being reported as
        # findings about the domain.
        if check_id in permitted and result in PUBLISHABLE_RESULTS
    )

    return Profile(
        registrable_domain=registrable_domain,
        # Withheld rather than caveated, exactly as everywhere else. A published band
        # drawn from a fraction of the surface is a claim about an institution that the
        # evidence does not support.
        band=band if coverage_sufficient else None,
        coverage_percentage=round(coverage_percentage, 2),
        methodology_version=methodology_version,
        policy_digest=policy_digest,
        observed_at=observed_at,
        checks=checks,
    )
