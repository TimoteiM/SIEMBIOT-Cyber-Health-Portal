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
    DOMAIN_READ = "domain.read"
    DOMAIN_MANAGE = "domain.manage"
    DOMAIN_VERIFY = "domain.verify"
    AUTHORIZATION_READ = "authorization.read"
    AUTHORIZATION_MANAGE = "authorization.manage"
    EMERGENCY_CONTROL_READ = "emergency_control.read"
    EMERGENCY_CONTROL_MANAGE = "emergency_control.manage"
    ASSESSMENT_READ = "assessment.read"
    ASSESSMENT_RUN = "assessment.run"
    ASSESSMENT_CANCEL = "assessment.cancel"
    ASSET_READ = "asset.read"
    # Accepting an asset decides what may be assessed, so it is a scope decision
    # rather than a reporting one and is held at the same level as domain management.
    ASSET_DECIDE = "asset.decide"


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
            Action.DOMAIN_READ,
            Action.DOMAIN_MANAGE,
            Action.DOMAIN_VERIFY,
            Action.AUTHORIZATION_READ,
            Action.AUTHORIZATION_MANAGE,
            Action.EMERGENCY_CONTROL_READ,
            Action.EMERGENCY_CONTROL_MANAGE,
            Action.ASSESSMENT_READ,
            Action.ASSESSMENT_RUN,
            Action.ASSESSMENT_CANCEL,
            Action.ASSET_READ,
            Action.ASSET_DECIDE,
        }
    ),
    # An analyst may run and cancel an assessment within policy and review findings,
    # but deciding what belongs in scope stays with the roles that manage domains.
    Role.ANALYST: frozenset(
        {
            Action.ORGANIZATION_READ,
            Action.MEMBERSHIP_READ,
            Action.DOMAIN_READ,
            Action.AUTHORIZATION_READ,
            Action.EMERGENCY_CONTROL_READ,
            Action.ASSESSMENT_READ,
            Action.ASSESSMENT_RUN,
            Action.ASSESSMENT_CANCEL,
            Action.ASSET_READ,
        }
    ),
    Role.VIEWER_AUDITOR: frozenset(
        {
            Action.ORGANIZATION_READ,
            Action.MEMBERSHIP_READ,
            Action.AUDIT_READ,
            Action.DOMAIN_READ,
            Action.AUTHORIZATION_READ,
            Action.EMERGENCY_CONTROL_READ,
            Action.ASSESSMENT_READ,
            Action.ASSET_READ,
        }
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
