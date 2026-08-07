"""Publishing: what may leave the tenant boundary, and what must never.

The database makes the guarantee (see migration 0015: a separate schema and a role with
no access to anything else). This package decides what is *put* there, and every choice
in it is made so that the failure mode is publishing too little.
"""

from siembiot.publication.projection import (
    PUBLISHABLE_RESULTS,
    Profile,
    ProfileCheck,
    ProjectionRefusedError,
    project_profile,
    publishable_check_ids,
)
from siembiot.publication.release import (
    MINIMUM_COHORT_SIZE,
    Aggregate,
    aggregate_checks,
)
from siembiot.publication.review import ReviewMissingError, require_approved_review
from siembiot.publication.store import (
    last_published_at,
    publish_domain,
    withdraw_domain,
)

__all__ = [
    "MINIMUM_COHORT_SIZE",
    "PUBLISHABLE_RESULTS",
    "Aggregate",
    "Profile",
    "ProfileCheck",
    "ProjectionRefusedError",
    "ReviewMissingError",
    "aggregate_checks",
    "last_published_at",
    "project_profile",
    "publish_domain",
    "publishable_check_ids",
    "require_approved_review",
    "withdraw_domain",
]
