"""What a support grant lets platform staff do, and what it must never let them do.

Row-level security has always let a live grant *read* a customer's rows, but the
application refused every action because it resolved a role from memberships alone. The
capability was therefore reachable at one layer and unusable at the other -- the same
shape migration 0016 fixed for listing the organizations a grant covers.

Making it usable widens what platform staff can do to somebody else's institution, so
the boundary needs pinning rather than describing. The rule: support can see everything
and change nothing, and in particular cannot widen the scope it then operates in.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "api" / "src"))

from siembiot.authorization import ROLE_ACTIONS, Action, Role, is_allowed  # noqa: E402

#: Actions that decide what may be probed, or who may act. Holding any of them would let
#: platform staff enlarge their own scope, at which point a support grant stops being
#: support access and becomes control of an institution nobody elected them to run.
SCOPE_WIDENING = frozenset(
    {
        Action.DOMAIN_MANAGE,
        Action.DOMAIN_VERIFY,
        Action.AUTHORIZATION_MANAGE,
        Action.ASSET_DECIDE,
        Action.EMERGENCY_CONTROL_MANAGE,
        Action.MEMBERSHIP_INVITE,
        Action.MEMBERSHIP_CHANGE,
        Action.MEMBERSHIP_REVOKE,
        Action.ORGANIZATION_UPDATE,
    }
)


def test_support_can_never_widen_its_own_scope() -> None:
    for action in SCOPE_WIDENING:
        assert not is_allowed(Role.PLATFORM_SUPPORT, action), action


def test_support_can_read_what_it_is_there_to_diagnose() -> None:
    for action in (
        Action.ORGANIZATION_READ,
        Action.DOMAIN_READ,
        Action.ASSESSMENT_READ,
        Action.AUDIT_READ,
        Action.ASSET_READ,
    ):
        assert is_allowed(Role.PLATFORM_SUPPORT, action), action


def test_support_may_re_run_an_assessment_but_only_within_existing_authorization() -> None:
    """Diagnosing a customer's problem usually means reproducing it, so running is
    allowed. What bounds it is the absence of the scope actions: a run can only ever
    cover the domains and authorizations the organization itself already granted."""
    assert is_allowed(Role.PLATFORM_SUPPORT, Action.ASSESSMENT_RUN)
    assert not is_allowed(Role.PLATFORM_SUPPORT, Action.AUTHORIZATION_MANAGE)
    assert not is_allowed(Role.PLATFORM_SUPPORT, Action.DOMAIN_VERIFY)


def test_support_holds_no_action_an_owner_does_not() -> None:
    """A grant is a subset of what the organization can already do for itself. Anything
    outside that would be an authority the customer could not have delegated, because
    they never had it."""
    assert ROLE_ACTIONS[Role.PLATFORM_SUPPORT] <= ROLE_ACTIONS[Role.ORGANIZATION_OWNER]


def test_every_action_is_decided_rather_than_defaulted() -> None:
    """A new action added to the product must be considered for this role explicitly.
    Without this, `is_allowed` returning False by omission would look identical to a
    deliberate exclusion -- and the opposite mistake, a permissive default, would hand
    platform staff a capability nobody chose to give them."""
    decided = ROLE_ACTIONS[Role.PLATFORM_SUPPORT] | SCOPE_WIDENING

    undecided = set(Action) - decided
    assert not undecided, (
        f"{sorted(action.value for action in undecided)} is neither granted to "
        "platform_support nor listed as scope-widening; decide which it is"
    )
