"""Identity boundary, tenant isolation and role enforcement.

Authentication now terminates upstream, so these tests cover the seam rather than a
login flow: an identity is accepted only when the upstream layer proves it, and every
authorization guarantee from Milestone 1 still holds behind it.
"""

from __future__ import annotations

from typing import Any, cast
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from siembiot.authorization import Action, Role, is_allowed
from siembiot.config import Settings
from siembiot.identity import (
    DevelopmentIdentityResolver,
    TrustedGatewayIdentityResolver,
    build_identity_resolver,
)
from siembiot.main import create_app

BASE_URL = "https://portal.example.test"
# Only the length matters to the resolver, so the fixture says exactly that rather
# than carrying a credential-shaped literal into the repository.
GATEWAY_PROOF = "g" * 40


def settings(database_url: str) -> Settings:
    return Settings(
        environment="test",
        public_base_url=BASE_URL,
        database_url=database_url.replace("postgresql://", "postgresql+psycopg://"),
    )


def identity_headers(subject: str, email: str, name: str = "Utilizator Test") -> dict[str, str]:
    return {
        "X-SIEMBIOT-Identity-Issuer": "https://idp.example.test",
        "X-SIEMBIOT-Identity-Subject": subject,
        "X-SIEMBIOT-Identity-Email": email,
        "X-SIEMBIOT-Identity-Name": name,
    }


def client_for(
    postgres_database: dict[str, str],
    subject: str | None = None,
    email: str | None = None,
) -> TestClient:
    """A client whose every request carries an upstream-asserted identity."""
    headers = (
        identity_headers(subject, email or f"{subject}@example.test") if subject is not None else {}
    )
    return TestClient(
        create_app(
            settings=settings(postgres_database["app_url"]),
            identity_resolver=DevelopmentIdentityResolver(),
        ),
        base_url=BASE_URL,
        headers=headers,
    )


def session_of(client: TestClient) -> dict[str, Any]:
    response = client.get("/api/v1/session")
    assert response.status_code == 200, response.text
    return cast(dict[str, Any], response.json())


def state_change_headers() -> dict[str, str]:
    return {"Origin": BASE_URL}


# -- the identity seam -------------------------------------------------------


def test_request_without_an_asserted_identity_is_unauthenticated(
    postgres_database: dict[str, str],
) -> None:
    with client_for(postgres_database) as client:
        response = client.get(f"/api/v1/organizations/{uuid4()}")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


def test_identity_headers_alone_cannot_authenticate_past_the_gateway(
    postgres_database: dict[str, str],
) -> None:
    """The point of the shared secret: a direct caller cannot forge an identity."""
    app = create_app(
        settings=settings(postgres_database["app_url"]),
        identity_resolver=TrustedGatewayIdentityResolver(GATEWAY_PROOF),
    )
    with TestClient(app, base_url=BASE_URL) as client:
        forged = client.get(
            f"/api/v1/organizations/{uuid4()}",
            headers=identity_headers(str(uuid4()), "attacker@example.test"),
        )
        assert forged.status_code == 401

        wrong_secret = client.get(
            "/api/v1/session",
            headers={
                **identity_headers(str(uuid4()), "attacker@example.test"),
                "X-SIEMBIOT-Gateway-Secret": "w" * 40,
            },
        )
        assert wrong_secret.status_code == 401


def test_gateway_identity_is_accepted_when_the_secret_matches(
    postgres_database: dict[str, str],
) -> None:
    app = create_app(
        settings=settings(postgres_database["app_url"]),
        identity_resolver=TrustedGatewayIdentityResolver(GATEWAY_PROOF),
    )
    subject = str(uuid4())
    with TestClient(app, base_url=BASE_URL) as client:
        response = client.get(
            "/api/v1/session",
            headers={
                **identity_headers(subject, f"{subject}@example.test"),
                "X-SIEMBIOT-Gateway-Secret": GATEWAY_PROOF,
            },
        )
    assert response.status_code == 200
    assert response.json()["user"]["email"] == f"{subject}@example.test"


def test_development_resolver_is_refused_outside_development() -> None:
    with pytest.raises(RuntimeError, match="required outside development"):
        build_identity_resolver("production", None)
    with pytest.raises(RuntimeError, match="required outside development"):
        build_identity_resolver("staging", None)


def test_resolver_selection_matches_the_environment() -> None:
    assert isinstance(build_identity_resolver("development", None), DevelopmentIdentityResolver)
    assert isinstance(
        build_identity_resolver("production", GATEWAY_PROOF), TrustedGatewayIdentityResolver
    )


def test_a_short_gateway_secret_is_refused() -> None:
    with pytest.raises(RuntimeError, match="at least 32 characters"):
        TrustedGatewayIdentityResolver("too-short")


@pytest.mark.parametrize(
    "headers",
    [
        {"X-SIEMBIOT-Identity-Subject": "subject-only"},
        {
            "X-SIEMBIOT-Identity-Issuer": "https://idp.example.test",
            "X-SIEMBIOT-Identity-Subject": "s",
            "X-SIEMBIOT-Identity-Email": "not-an-email",
        },
        {
            "X-SIEMBIOT-Identity-Issuer": "https://idp.example.test",
            "X-SIEMBIOT-Identity-Subject": "x" * 300,
            "X-SIEMBIOT-Identity-Email": "long@example.test",
        },
    ],
)
def test_malformed_identity_assertions_are_rejected(
    postgres_database: dict[str, str], headers: dict[str, str]
) -> None:
    with client_for(postgres_database) as client:
        response = client.get("/api/v1/session", headers=headers)
    assert response.status_code == 401


def test_the_same_upstream_identity_maps_to_one_stable_local_user(
    postgres_database: dict[str, str],
) -> None:
    subject = str(uuid4())
    with client_for(postgres_database, subject) as client:
        first = session_of(client)["user"]["id"]
        # A changed display name and e-mail must update, not fork, the account.
        client.headers.update(identity_headers(subject, f"renamed-{subject}@example.test", "Nou"))
        second = session_of(client)
    assert first == second["user"]["id"]
    assert second["user"]["email"] == f"renamed-{subject}@example.test"


def test_the_same_subject_from_a_different_issuer_is_a_different_user(
    postgres_database: dict[str, str],
) -> None:
    subject = str(uuid4())
    with client_for(postgres_database, subject) as client:
        first = session_of(client)["user"]["id"]
        client.headers.update(
            {
                **identity_headers(subject, f"other-{subject}@example.test"),
                "X-SIEMBIOT-Identity-Issuer": "https://other-idp.example.test",
            }
        )
        second = session_of(client)["user"]["id"]
    assert first != second


# -- authorization still applies ---------------------------------------------


def test_rbac_matrix_is_deny_by_default() -> None:
    assert is_allowed(Role.ORGANIZATION_OWNER, Action.MEMBERSHIP_CHANGE)
    assert is_allowed(Role.SECURITY_ADMIN, Action.MEMBERSHIP_INVITE)
    assert not is_allowed(Role.ANALYST, Action.MEMBERSHIP_CHANGE)
    assert not is_allowed(Role.VIEWER_AUDITOR, Action.ORGANIZATION_UPDATE)
    assert not is_allowed("future_role", Action.ORGANIZATION_READ)
    assert not is_allowed(Role.ORGANIZATION_OWNER, "future.action")
    assert is_allowed(Role.ORGANIZATION_OWNER, Action.DOMAIN_MANAGE)
    assert is_allowed(Role.SECURITY_ADMIN, Action.AUTHORIZATION_MANAGE)
    assert is_allowed(Role.ANALYST, Action.DOMAIN_READ)
    assert not is_allowed(Role.ANALYST, Action.DOMAIN_MANAGE)
    assert not is_allowed(Role.VIEWER_AUDITOR, Action.EMERGENCY_CONTROL_MANAGE)


def test_cross_tenant_idor_forged_tenant_and_role_escalation_are_denied(
    postgres_database: dict[str, str],
) -> None:
    with (
        client_for(postgres_database, str(uuid4())) as owner_client,
        client_for(postgres_database, str(uuid4())) as other_client,
        client_for(postgres_database, str(uuid4())) as analyst_client,
    ):
        analyst_session = session_of(analyst_client)
        owner_org = owner_client.post(
            "/api/v1/organizations",
            json={"name": "Organizația A", "slug": f"org-a-{uuid4().hex[:8]}"},
            headers=state_change_headers(),
        ).json()
        other_org = other_client.post(
            "/api/v1/organizations",
            json={"name": "Organizația B", "slug": f"org-b-{uuid4().hex[:8]}"},
            headers=state_change_headers(),
        ).json()

        cross_tenant = owner_client.get(
            f"/api/v1/organizations/{other_org['id']}",
            headers={"X-Organization-ID": owner_org["id"]},
        )
        assert cross_tenant.status_code in {403, 404}

        with psycopg.connect(postgres_database["owner_url"]) as owner:
            membership = owner.execute(
                "INSERT INTO memberships (organization_id, user_id, role, status) "
                "VALUES (%s, %s, 'analyst', 'active') RETURNING id::text",
                (owner_org["id"], analyst_session["user"]["id"]),
            ).fetchone()
            assert membership is not None
            membership_id = membership[0]

        escalation = analyst_client.patch(
            f"/api/v1/organizations/{owner_org['id']}/memberships/{membership_id}",
            json={"role": "organization_owner"},
            headers=state_change_headers(),
        )
        assert escalation.status_code == 403

        with psycopg.connect(postgres_database["owner_url"]) as owner:
            owner.execute(
                "UPDATE memberships SET status = 'revoked', revoked_at = now() WHERE id = %s",
                (membership_id,),
            )
        revoked = analyst_client.get(f"/api/v1/organizations/{owner_org['id']}")
        assert revoked.status_code in {403, 404}


@pytest.mark.parametrize(
    "origin", ["https://evil.example", "null", "https://portal.example.test.evil"]
)
def test_forged_origins_are_rejected(postgres_database: dict[str, str], origin: str) -> None:
    with client_for(postgres_database, str(uuid4())) as client:
        response = client.post(
            "/api/v1/organizations",
            json={"name": "Denied", "slug": f"denied-{uuid4().hex[:8]}"},
            headers={"Origin": origin},
        )
    assert response.status_code == 403


def test_a_state_change_without_an_origin_header_is_rejected(
    postgres_database: dict[str, str],
) -> None:
    with client_for(postgres_database, str(uuid4())) as client:
        response = client.post(
            "/api/v1/organizations",
            json={"name": "Denied", "slug": f"denied-{uuid4().hex[:8]}"},
        )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "origin_rejected"


def test_invitation_membership_and_audit_lifecycle(postgres_database: dict[str, str]) -> None:
    analyst_email = f"analyst-{uuid4()}@example.test"
    with (
        client_for(postgres_database, str(uuid4())) as owner_client,
        client_for(postgres_database, str(uuid4()), analyst_email) as analyst_client,
    ):
        analyst_session = session_of(analyst_client)
        organization = owner_client.post(
            "/api/v1/organizations",
            json={"name": "Echipă", "slug": f"echipa-{uuid4().hex[:8]}"},
            headers=state_change_headers(),
        ).json()
        invitation = owner_client.post(
            f"/api/v1/organizations/{organization['id']}/invitations",
            json={"email": analyst_email, "role": "analyst"},
            headers=state_change_headers(),
        )
        assert invitation.status_code == 201
        duplicate = owner_client.post(
            f"/api/v1/organizations/{organization['id']}/invitations",
            json={"email": analyst_email, "role": "analyst"},
            headers=state_change_headers(),
        )
        assert duplicate.status_code == 409

        accepted = analyst_client.post(
            "/api/v1/invitations/accept",
            json={"token": invitation.json()["acceptance_token"]},
            headers=state_change_headers(),
        )
        assert accepted.status_code == 200
        assert analyst_client.get(f"/api/v1/organizations/{organization['id']}").status_code == 200

        members = owner_client.get(f"/api/v1/organizations/{organization['id']}/memberships").json()
        analyst_membership = next(
            member for member in members if member["user_id"] == analyst_session["user"]["id"]
        )
        denied_invite = analyst_client.post(
            f"/api/v1/organizations/{organization['id']}/invitations",
            json={"email": f"other-{uuid4()}@example.test", "role": "analyst"},
            headers=state_change_headers(),
        )
        assert denied_invite.status_code == 403

        audits = owner_client.get(f"/api/v1/organizations/{organization['id']}/audit-events")
        assert audits.status_code == 200
        actions = {event["action"] for event in audits.json()}
        assert "organization.created" in actions
        assert "membership.invited" in actions
        assert "membership.invitation_accepted" in actions
        for event in audits.json():
            assert event["organization_id"] == organization["id"]
            assert event["request_id"]
            assert event["correlation_id"]
            assert event["actor"]["id"]
            assert event["resource"]["id"]
            assert event["outcome"] in {"success", "denied", "failure"}

        revoked = owner_client.delete(
            f"/api/v1/organizations/{organization['id']}/memberships/{analyst_membership['id']}",
            headers=state_change_headers(),
        )
        assert revoked.status_code == 204
        assert analyst_client.get(f"/api/v1/organizations/{organization['id']}").status_code == 403
