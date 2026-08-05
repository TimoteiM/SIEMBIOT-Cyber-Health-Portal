from __future__ import annotations

import psycopg
from fastapi.testclient import TestClient
from siembiot.auth import current_principal, require_trusted_origin
from siembiot.config import Settings
from siembiot.identity import NullIdentityResolver
from siembiot.main import create_app
from test_domains import MutableTXTResolver, seed_owner


def test_org_emergency_controls_are_tenant_scoped_and_audited(
    postgres_database: dict[str, str],
) -> None:
    organization_id, principal = seed_owner(postgres_database["owner_url"])
    other_id, _ = seed_owner(postgres_database["owner_url"])
    settings = Settings(
        environment="test",
        public_base_url="https://portal.example.test",
        database_url=postgres_database["app_url"].replace("postgresql://", "postgresql+psycopg://"),
    )
    app = create_app(
        settings=settings,
        txt_resolver=MutableTXTResolver(),
        identity_resolver=NullIdentityResolver(),
    )
    app.dependency_overrides[current_principal] = lambda: principal
    app.dependency_overrides[require_trusted_origin] = lambda: principal
    with TestClient(app, base_url="https://portal.example.test") as client:
        created = client.post(
            f"/api/v1/organizations/{organization_id}/emergency-controls",
            json={
                "scope": "operation_class",
                "operation_class": "https_verification",
                "reason": "Emergency verification traffic suspension",
            },
        )
        assert created.status_code == 201
        assert created.json()["active"] is True
        assert (
            client.get(f"/api/v1/organizations/{organization_id}/emergency-controls").json()[0][
                "reason"
            ]
            == "Emergency verification traffic suspension"
        )
        assert client.get(f"/api/v1/organizations/{other_id}/emergency-controls").status_code == 403

        audits = client.get(f"/api/v1/organizations/{organization_id}/audit-events").json()
        assert any(event["action"] == "emergency_control.activated" for event in audits)


def test_global_control_requires_phishing_resistant_platform_admin(
    postgres_database: dict[str, str],
) -> None:
    _, principal = seed_owner(postgres_database["owner_url"])
    settings = Settings(
        environment="test",
        public_base_url="https://portal.example.test",
        database_url=postgres_database["app_url"].replace("postgresql://", "postgresql+psycopg://"),
    )
    app = create_app(settings=settings, identity_resolver=NullIdentityResolver())
    app.dependency_overrides[current_principal] = lambda: principal
    app.dependency_overrides[require_trusted_origin] = lambda: principal
    payload = {
        "scope": "global",
        "reason": "Emergency platform-wide network suspension",
    }
    with TestClient(app, base_url="https://portal.example.test") as client:
        assert client.post("/api/v1/emergency-controls", json=payload).status_code == 403
        with psycopg.connect(postgres_database["owner_url"]) as owner:
            owner.execute(
                "UPDATE users SET platform_role = 'platform_admin', "
                "mfa_assurance = 'phishing_resistant' WHERE id = %s",
                (str(principal.user_id),),
            )
        created = client.post("/api/v1/emergency-controls", json=payload)
        assert created.status_code == 201
        assert created.json()["scope"] == "global"
        deactivated = client.post(
            f"/api/v1/emergency-controls/{created.json()['id']}/deactivate",
            json={"reason": "Platform incident reviewed and cleared"},
        )
        assert deactivated.status_code == 200
        assert deactivated.json()["active"] is False


def test_read_only_role_cannot_activate_emergency_control(
    postgres_database: dict[str, str],
) -> None:
    organization_id, principal = seed_owner(postgres_database["owner_url"], role="viewer_auditor")
    settings = Settings(
        environment="test",
        public_base_url="https://portal.example.test",
        database_url=postgres_database["app_url"].replace("postgresql://", "postgresql+psycopg://"),
    )
    app = create_app(settings=settings, identity_resolver=NullIdentityResolver())
    app.dependency_overrides[current_principal] = lambda: principal
    app.dependency_overrides[require_trusted_origin] = lambda: principal
    with TestClient(app, base_url="https://portal.example.test") as client:
        denied = client.post(
            f"/api/v1/organizations/{organization_id}/emergency-controls",
            json={
                "scope": "organization",
                "reason": "Unauthorized emergency control request",
            },
        )
        assert denied.status_code == 403
