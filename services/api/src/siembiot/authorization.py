from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    ORGANIZATION_OWNER = "organization_owner"
    SECURITY_ADMIN = "security_admin"
    ANALYST = "analyst"
    VIEWER_AUDITOR = "viewer_auditor"
    MATURITY_CONTRIBUTOR = "maturity_contributor"


class Action(StrEnum):
    ORGANIZATION_READ = "organization.read"
    ORGANIZATION_UPDATE = "organization.update"
    MEMBERSHIP_READ = "membership.read"
    MEMBERSHIP_INVITE = "membership.invite"
    MEMBERSHIP_CHANGE = "membership.change"
    MEMBERSHIP_REVOKE = "membership.revoke"
    AUDIT_READ = "audit.read"


ROLE_ACTIONS: dict[Role, frozenset[Action]] = {
    Role.ORGANIZATION_OWNER: frozenset(Action),
    Role.SECURITY_ADMIN: frozenset(
        {
            Action.ORGANIZATION_READ,
            Action.ORGANIZATION_UPDATE,
            Action.MEMBERSHIP_READ,
            Action.MEMBERSHIP_INVITE,
            Action.MEMBERSHIP_CHANGE,
            Action.MEMBERSHIP_REVOKE,
            Action.AUDIT_READ,
        }
    ),
    Role.ANALYST: frozenset({Action.ORGANIZATION_READ, Action.MEMBERSHIP_READ}),
    Role.VIEWER_AUDITOR: frozenset(
        {Action.ORGANIZATION_READ, Action.MEMBERSHIP_READ, Action.AUDIT_READ}
    ),
    Role.MATURITY_CONTRIBUTOR: frozenset({Action.ORGANIZATION_READ}),
}


def is_allowed(role: Role | str, action: Action | str) -> bool:
    try:
        parsed_role = Role(role)
        parsed_action = Action(action)
    except ValueError:
        return False
    return parsed_action in ROLE_ACTIONS.get(parsed_role, frozenset())
