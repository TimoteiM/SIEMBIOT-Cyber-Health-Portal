from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import psycopg
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from siembiot.authorization import Action, Role, is_allowed
from siembiot.config import Settings
from siembiot.main import create_app


@dataclass
class FakeOIDCClient:
    issuer: str = "https://idp.example.test"
    nonce: str | None = None
    subject: str = "owner-subject"
    email: str = "owner@example.test"
    nonce_override: str | None = None

    def authorization_url(
        self, *, state: str, nonce: str, code_challenge: str, redirect_uri: str
    ) -> str:
        self.nonce = nonce
        return (
            "https://idp.example.test/authorize?"
            f"state={state}&nonce={nonce}&code_challenge={code_challenge}"
            f"&redirect_uri={redirect_uri}"
        )

    def exchange_code(self, *, code: str, code_verifier: str, redirect_uri: str) -> dict[str, Any]:
        assert code == "valid-code"
        assert len(code_verifier) >= 43
        assert redirect_uri == "https://portal.example.test/api/v1/auth/callback"
        assert self.nonce is not None
        return {
            "iss": self.issuer,
            "sub": self.subject,
            "email": self.email,
            "name": "Utilizator Test",
            "nonce": self.nonce_override or self.nonce,
            "exp": int(datetime.now(UTC).timestamp()) + 300,
        }

    def logout_url(self, *, post_logout_redirect_uri: str) -> str | None:
        return (
            f"https://idp.example.test/logout?post_logout_redirect_uri={post_logout_redirect_uri}"
        )


def settings(database_url: str) -> Settings:
    return Settings(
        environment="test",
        public_base_url="https://portal.example.test",
        database_url=database_url.replace("postgresql://", "postgresql+psycopg://"),
        oidc_issuer="https://idp.example.test",
        oidc_client_id="siembiot-test",
        oidc_client_secret=None,
        session_encryption_key=Fernet.generate_key().decode("ascii"),
        session_ttl_seconds=3600,
    )


def client_for(postgres_database: dict[str, str], oidc: FakeOIDCClient) -> TestClient:
    return TestClient(
        create_app(settings=settings(postgres_database["app_url"]), oidc_client=oidc),
        base_url="https://portal.example.test",
    )


def login(client: TestClient) -> dict[str, Any]:
    start = client.get("/api/v1/auth/login", follow_redirects=False)
    assert start.status_code == 307
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    callback = client.get(
        "/api/v1/auth/callback",
        params={"state": state, "code": "valid-code"},
        follow_redirects=False,
    )
    assert callback.status_code == 303
    session = client.get("/api/v1/session")
    assert session.status_code == 200
    return cast(dict[str, Any], session.json())


def security_headers(session: dict[str, Any]) -> dict[str, str]:
    return {
        "Origin": "https://portal.example.test",
        "X-CSRF-Token": session["csrf_token"],
    }


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


def test_unauthenticated_private_access_is_rejected(postgres_database: dict[str, str]) -> None:
    with client_for(postgres_database, FakeOIDCClient()) as client:
        response = client.get(f"/api/v1/organizations/{uuid4()}")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


def test_oidc_session_cookie_and_logout_lifecycle(postgres_database: dict[str, str]) -> None:
    with client_for(postgres_database, FakeOIDCClient()) as client:
        start = client.get("/api/v1/auth/login", follow_redirects=False)
        state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
        callback = client.get(
            "/api/v1/auth/callback",
            params={"state": state, "code": "valid-code"},
            follow_redirects=False,
        )
        cookie = callback.headers["set-cookie"]
        assert "__Host-siembiot_session=" in cookie
        assert "HttpOnly" in cookie
        assert "Secure" in cookie
        assert "SameSite=lax" in cookie
        assert "Path=/" in cookie
        assert "Domain=" not in cookie

        current = client.get("/api/v1/session")
        assert current.status_code == 200
        assert "access_token" not in str(current.json())
        assert "refresh_token" not in str(current.json())

        denied = client.post("/api/v1/auth/logout")
        assert denied.status_code == 403
        valid = client.post(
            "/api/v1/auth/logout", headers=security_headers(current.json()), follow_redirects=False
        )
        assert valid.status_code == 200
        assert valid.json()["logout_url"].startswith("https://idp.example.test/logout")
        assert client.get("/api/v1/session").status_code == 401


def test_expired_session_is_rejected(
    postgres_database: dict[str, str],
) -> None:
    with client_for(postgres_database, FakeOIDCClient(subject=str(uuid4()))) as client:
        login(client)
        cookie = client.cookies.get("__Host-siembiot_session")
        assert cookie is not None
        with psycopg.connect(postgres_database["owner_url"]) as owner:
            owner.execute("UPDATE sessions SET expires_at = now() - interval '1 second'")
        response = client.get("/api/v1/session")
        assert response.status_code == 401


def test_oidc_state_is_one_time_and_nonce_is_verified(postgres_database: dict[str, str]) -> None:
    with client_for(postgres_database, FakeOIDCClient(subject=str(uuid4()))) as client:
        start = client.get("/api/v1/auth/login", follow_redirects=False)
        state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
        first = client.get(
            "/api/v1/auth/callback",
            params={"state": state, "code": "valid-code"},
            follow_redirects=False,
        )
        assert first.status_code == 303
        replay = client.get(
            "/api/v1/auth/callback",
            params={"state": state, "code": "valid-code"},
            follow_redirects=False,
        )
        assert replay.status_code == 400
        assert replay.json()["error"]["code"] == "invalid_oidc_state"

    bad_oidc = FakeOIDCClient(subject=str(uuid4()), nonce_override="forged-nonce")
    with client_for(postgres_database, bad_oidc) as client:
        start = client.get("/api/v1/auth/login", follow_redirects=False)
        state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
        rejected = client.get(
            "/api/v1/auth/callback",
            params={"state": state, "code": "valid-code"},
            follow_redirects=False,
        )
        assert rejected.status_code == 400
        assert rejected.json()["error"]["code"] == "invalid_identity"


def test_cross_tenant_idor_forged_tenant_and_role_escalation_are_denied(
    postgres_database: dict[str, str],
) -> None:
    owner_oidc = FakeOIDCClient(subject=str(uuid4()), email=f"{uuid4()}@example.test")
    other_oidc = FakeOIDCClient(subject=str(uuid4()), email=f"{uuid4()}@example.test")
    analyst_oidc = FakeOIDCClient(subject=str(uuid4()), email=f"{uuid4()}@example.test")
    with (
        client_for(postgres_database, owner_oidc) as owner_client,
        client_for(postgres_database, other_oidc) as other_client,
        client_for(postgres_database, analyst_oidc) as analyst_client,
    ):
        owner_session = login(owner_client)
        other_session = login(other_client)
        analyst_session = login(analyst_client)
        owner_org = owner_client.post(
            "/api/v1/organizations",
            json={"name": "Organizația A", "slug": f"org-a-{uuid4().hex[:8]}"},
            headers=security_headers(owner_session),
        ).json()
        other_org = other_client.post(
            "/api/v1/organizations",
            json={"name": "Organizația B", "slug": f"org-b-{uuid4().hex[:8]}"},
            headers=security_headers(other_session),
        ).json()

        cross_tenant = owner_client.get(
            f"/api/v1/organizations/{other_org['id']}",
            headers={"X-Organization-ID": owner_org["id"]},
        )
        assert cross_tenant.status_code in {403, 404}

        with psycopg.connect(postgres_database["owner_url"]) as owner:
            analyst_user_id = analyst_session["user"]["id"]
            membership = owner.execute(
                "INSERT INTO memberships (organization_id, user_id, role, status) "
                "VALUES (%s, %s, 'analyst', 'active') RETURNING id::text",
                (owner_org["id"], analyst_user_id),
            ).fetchone()
            assert membership is not None
            membership_id = membership[0]

        escalation = analyst_client.patch(
            f"/api/v1/organizations/{owner_org['id']}/memberships/{membership_id}",
            json={"role": "organization_owner"},
            headers=security_headers(analyst_session),
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
    with client_for(postgres_database, FakeOIDCClient(subject=str(uuid4()))) as client:
        session = login(client)
        response = client.post(
            "/api/v1/organizations",
            json={"name": "Denied", "slug": f"denied-{uuid4().hex[:8]}"},
            headers={"Origin": origin, "X-CSRF-Token": session["csrf_token"]},
        )
        assert response.status_code == 403


def test_invitation_membership_and_audit_lifecycle(postgres_database: dict[str, str]) -> None:
    owner_oidc = FakeOIDCClient(subject=str(uuid4()), email=f"owner-{uuid4()}@example.test")
    analyst_email = f"analyst-{uuid4()}@example.test"
    analyst_oidc = FakeOIDCClient(subject=str(uuid4()), email=analyst_email)
    with (
        client_for(postgres_database, owner_oidc) as owner_client,
        client_for(postgres_database, analyst_oidc) as analyst_client,
    ):
        owner_session = login(owner_client)
        analyst_session = login(analyst_client)
        organization = owner_client.post(
            "/api/v1/organizations",
            json={"name": "Echipă", "slug": f"echipa-{uuid4().hex[:8]}"},
            headers=security_headers(owner_session),
        ).json()
        invitation = owner_client.post(
            f"/api/v1/organizations/{organization['id']}/invitations",
            json={"email": analyst_email, "role": "analyst"},
            headers=security_headers(owner_session),
        )
        assert invitation.status_code == 201
        duplicate = owner_client.post(
            f"/api/v1/organizations/{organization['id']}/invitations",
            json={"email": analyst_email, "role": "analyst"},
            headers=security_headers(owner_session),
        )
        assert duplicate.status_code == 409

        accepted = analyst_client.post(
            "/api/v1/invitations/accept",
            json={"token": invitation.json()["acceptance_token"]},
            headers=security_headers(analyst_session),
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
            headers=security_headers(analyst_session),
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
            headers=security_headers(owner_session),
        )
        assert revoked.status_code == 204
        assert analyst_client.get(f"/api/v1/organizations/{organization['id']}").status_code == 403
