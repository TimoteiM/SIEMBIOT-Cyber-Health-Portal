from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

EXPECTED_TABLES = {
    "alembic_version",
    "audit_events",
    "assessment_authorizations",
    "authorization_targets",
    "domain_challenges",
    "domain_verification_events",
    "domains",
    "emergency_controls",
    "evaluation_evidence",
    "check_evaluations",
    "finding_events",
    "finding_occurrences",
    "findings",
    "invitations",
    "memberships",
    "network_operations",
    "normalized_observations",
    "oidc_login_transactions",
    "organizations",
    "sessions",
    "support_access_grants",
    "scope_manifests",
    "raw_artifacts",
    "score_attributions",
    "score_snapshots",
    "snapshot_evaluations",
    "users",
}
ROOT = Path(__file__).resolve().parents[2]


def seed_tenant(owner_url: str) -> tuple[str, str]:
    organization_id = str(uuid4())
    user_id = str(uuid4())
    slug = f"tenant-{organization_id[:12]}"
    with psycopg.connect(owner_url) as owner:
        owner.execute(
            "INSERT INTO users (id, oidc_issuer, oidc_subject, email, display_name) "
            "VALUES (%s, %s, %s, %s, %s)",
            (user_id, "https://idp.example.test", user_id, f"{user_id}@example.test", "Test User"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Tenant', %s, %s)",
            (organization_id, slug, user_id),
        )
        owner.execute(
            "INSERT INTO memberships (organization_id, user_id, role, status) "
            "VALUES (%s, %s, 'organization_owner', 'active')",
            (organization_id, user_id),
        )
    return organization_id, user_id


def test_empty_database_upgrades_to_head(postgres_database: dict[str, str]) -> None:
    with psycopg.connect(postgres_database["owner_url"]) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
            )
        }
    assert EXPECTED_TABLES <= tables


def test_application_role_cannot_bypass_tenant_rls(postgres_database: dict[str, str]) -> None:
    org_a, user_a = seed_tenant(postgres_database["owner_url"])
    org_b, _ = seed_tenant(postgres_database["owner_url"])

    with psycopg.connect(postgres_database["app_url"]) as app:
        assert app.execute("SELECT id FROM organizations").fetchall() == []
        app.execute("SELECT set_config('app.user_id', %s, false)", (user_a,))
        app.execute("SELECT set_config('app.organization_id', %s, false)", (org_a,))
        assert app.execute("SELECT id::text FROM organizations").fetchall() == [(org_a,)]
        assert (
            app.execute("SELECT id::text FROM organizations WHERE id = %s", (org_b,)).fetchone()
            is None
        )


def test_revoked_membership_removes_rls_access(postgres_database: dict[str, str]) -> None:
    organization_id, user_id = seed_tenant(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        owner.execute(
            "UPDATE memberships SET status = 'revoked', revoked_at = now() "
            "WHERE organization_id = %s AND user_id = %s",
            (organization_id, user_id),
        )
    with psycopg.connect(postgres_database["app_url"]) as app:
        app.execute("SELECT set_config('app.organization_id', %s, false)", (organization_id,))
        app.execute("SELECT set_config('app.user_id', %s, false)", (user_id,))
        assert app.execute("SELECT id FROM organizations").fetchall() == []


def test_application_role_cannot_mutate_audit(postgres_database: dict[str, str]) -> None:
    org_id, user_id = seed_tenant(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["app_url"]) as app:
        app.execute("SELECT set_config('app.organization_id', %s, false)", (org_id,))
        app.execute("SELECT set_config('app.user_id', %s, false)", (user_id,))
        event = app.execute(
            "INSERT INTO audit_events "
            "(organization_id, actor_type, actor_id, action, resource_type, resource_id, "
            "request_id, correlation_id, outcome, context) "
            "VALUES (%s, 'user', %s, 'security.tested', 'organization', %s, "
            "'01K1X6HBFM6W2Y0M76K5G5HT3C', '01K1X6HBFM6W2Y0M76K5G5HT3C', "
            "'success', '{}'::jsonb) RETURNING id",
            (org_id, user_id, org_id),
        ).fetchone()
        assert event is not None
        event_id = event[0]
        app.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("UPDATE audit_events SET outcome = 'failure' WHERE id = %s", (event_id,))
        app.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("DELETE FROM audit_events WHERE id = %s", (event_id,))


def test_platform_admin_requires_explicit_grant_and_phishing_resistant_mfa(
    postgres_database: dict[str, str],
) -> None:
    organization_id, approver_id = seed_tenant(postgres_database["owner_url"])
    platform_user_id = str(uuid4())
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        owner.execute(
            "INSERT INTO users (id, oidc_issuer, oidc_subject, email, display_name, platform_role) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Support', 'platform_admin')",
            (platform_user_id, platform_user_id, f"{platform_user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO support_access_grants "
            "(organization_id, platform_user_id, reason, approved_by_user_id, expires_at) "
            "VALUES (%s, %s, 'Investigate customer-requested incident', %s, "
            "now() + interval '1 hour')",
            (organization_id, platform_user_id, approver_id),
        )
    with psycopg.connect(postgres_database["app_url"]) as app:
        app.execute("SELECT set_config('app.organization_id', %s, false)", (organization_id,))
        app.execute("SELECT set_config('app.user_id', %s, false)", (platform_user_id,))
        assert app.execute("SELECT id FROM organizations").fetchall() == []
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        owner.execute(
            "UPDATE users SET mfa_assurance = 'phishing_resistant' WHERE id = %s",
            (platform_user_id,),
        )
    with psycopg.connect(postgres_database["app_url"]) as app:
        app.execute("SELECT set_config('app.organization_id', %s, false)", (organization_id,))
        app.execute("SELECT set_config('app.user_id', %s, false)", (platform_user_id,))
        assert app.execute("SELECT id::text FROM organizations").fetchall() == [(organization_id,)]


def test_global_audit_events_are_actor_isolated(postgres_database: dict[str, str]) -> None:
    first_user_id = str(uuid4())
    second_user_id = str(uuid4())
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        for user_id in (first_user_id, second_user_id):
            owner.execute(
                "INSERT INTO users (id, oidc_issuer, oidc_subject, email, display_name) "
                "VALUES (%s, 'https://idp.example.test', %s, %s, 'Audit actor')",
                (user_id, user_id, f"{user_id}@example.test"),
            )
            owner.execute(
                "INSERT INTO audit_events "
                "(actor_type, actor_id, action, resource_type, resource_id, request_id, "
                "correlation_id, outcome, context) VALUES "
                "('user', %s, 'session.created', 'session', %s, "
                "'01K1X6HBFM6W2Y0M76K5G5HT3C', '01K1X6HBFM6W2Y0M76K5G5HT3C', "
                "'success', '{}'::jsonb)",
                (user_id, user_id),
            )

    with psycopg.connect(postgres_database["app_url"]) as app:
        app.execute("SELECT set_config('app.user_id', %s, false)", (first_user_id,))
        rows = app.execute(
            "SELECT actor_id FROM audit_events WHERE organization_id IS NULL ORDER BY actor_id"
        ).fetchall()

    assert rows == [(first_user_id,)]


def test_development_downgrade_and_reupgrade(postgres_database: dict[str, str]) -> None:
    environment = os.environ.copy()
    environment["SIEMBIOT_DATABASE_URL"] = (
        "postgresql+psycopg://siembiot_owner:placeholder@127.0.0.1:55432/siembiot_test"
    )
    command = [sys.executable, "-m", "alembic", "-c", "services/api/alembic.ini"]
    subprocess.run([*command, "downgrade", "base"], cwd=ROOT, env=environment, check=True)  # noqa: S603
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        assert owner.execute("SELECT to_regclass('public.organizations')").fetchone() == (None,)
    subprocess.run([*command, "upgrade", "head"], cwd=ROOT, env=environment, check=True)  # noqa: S603
