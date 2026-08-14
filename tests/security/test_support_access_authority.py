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


#: Actions the database refuses a support grant whatever this table says.
#:
#: A different reason from scope-widening, so a different list. Row-level security gates
#: SELECT on `app_has_tenant_access`, which a support grant satisfies, and gates INSERT
#: and UPDATE on `app_has_active_membership`, which it does not. Granting these in the
#: application produced a 500 from a row-level security violation rather than a refusal
#: -- each layer individually doing as it was told, and neither reporting that they
#: disagreed.
REFUSED_BY_THE_DATABASE = frozenset(
    {
        Action.ASSESSMENT_RUN,
        Action.ASSESSMENT_CANCEL,
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


def test_support_may_not_run_an_assessment() -> None:
    """This used to assert the opposite, on the reasoning that diagnosing a customer's
    problem usually means reproducing it.

    The database never agreed. `assessments` gates INSERT on `app_has_active_membership`,
    which a support grant does not satisfy, so the grant in this table bought nothing but
    a 500 -- discovered by a platform administrator clicking "run" and getting an
    unexplained internal error.

    Resolved towards the database rather than away from it: it is the backstop, it is
    stricter, and widening it would have meant relaxing tenant isolation to make a
    convenience work. A support engineer who needs a run asks the institution to press
    the button, which is also the only version of this that leaves an honest audit trail.
    """
    assert not is_allowed(Role.PLATFORM_SUPPORT, Action.ASSESSMENT_RUN)
    assert not is_allowed(Role.PLATFORM_SUPPORT, Action.ASSESSMENT_CANCEL)
    # Still readable: support exists to diagnose, and diagnosis needs the evidence.
    assert is_allowed(Role.PLATFORM_SUPPORT, Action.ASSESSMENT_READ)


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
    decided = ROLE_ACTIONS[Role.PLATFORM_SUPPORT] | SCOPE_WIDENING | REFUSED_BY_THE_DATABASE

    undecided = set(Action) - decided
    assert not undecided, (
        f"{sorted(action.value for action in undecided)} is neither granted to "
        "platform_support, nor listed as scope-widening, nor listed as refused by "
        "the database; decide which it is"
    )


def test_support_access_is_read_only() -> None:
    """The sentence the database has been enforcing all along.

    Row-level security on the tenant tables gates SELECT on `app_has_tenant_access`,
    which a support grant satisfies, and gates INSERT and UPDATE on
    `app_has_active_membership`, which it does not. The application's role table used to
    grant `assessment.run` and `assessment.cancel` to platform support anyway, and the
    two layers disagreeing produced the worst outcome available: a 500 from a row-level
    security violation, where a working run or an honest refusal were both better.

    Naming the property -- *support access is read-only* -- turns that from something
    two files have to keep agreeing about into something one test can check. Any write
    action added to this role fails here rather than at three in the morning as an
    unexplained 500.
    """
    write_actions = {action for action in Action if not str(action).endswith(".read")}
    granted = ROLE_ACTIONS[Role.PLATFORM_SUPPORT]

    assert granted, "platform support has no actions at all; this test is checking nothing"
    assert not (granted & write_actions), (
        f"platform support holds write actions {sorted(granted & write_actions)}. The "
        "database refuses these for a support grant, so granting them here produces a "
        "500 rather than a refusal. If support genuinely needs one, the row-level "
        "security policy has to change first -- and that is a decision about tenant "
        "isolation, not a permissions tweak."
    )


def test_a_member_role_still_holds_write_actions() -> None:
    """The other half, so the test above cannot pass by the action list being empty or
    every action being named `.read` by accident."""
    write_actions = {action for action in Action if not str(action).endswith(".read")}

    assert ROLE_ACTIONS[Role.ORGANIZATION_OWNER] & write_actions, (
        "no role holds a write action, so the read-only assertion above proves nothing"
    )
