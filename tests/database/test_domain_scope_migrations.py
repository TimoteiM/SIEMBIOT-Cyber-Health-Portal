from __future__ import annotations

from uuid import uuid4

import psycopg
import pytest
from psycopg import sql


def seed_tenant(owner_url: str) -> tuple[str, str]:
    organization_id = str(uuid4())
    user_id = str(uuid4())
    with psycopg.connect(owner_url) as owner:
        owner.execute(
            "INSERT INTO users (id, oidc_issuer, oidc_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Domain owner')",
            (user_id, user_id, f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Domain tenant', %s, %s)",
            (organization_id, f"domain-{organization_id[:12]}", user_id),
        )
        owner.execute(
            "INSERT INTO memberships (organization_id, user_id, role) "
            "VALUES (%s, %s, 'organization_owner')",
            (organization_id, user_id),
        )
    return organization_id, user_id


def insert_domain(owner_url: str, organization_id: str, user_id: str, name: str) -> str:
    with psycopg.connect(owner_url) as owner:
        row = owner.execute(
            "INSERT INTO domains "
            "(organization_id, canonical_name, unicode_display, registrable_domain, "
            "created_by_user_id) "
            "VALUES (%s, %s, %s, %s, %s) RETURNING id::text",
            (organization_id, name, name, name, user_id),
        ).fetchone()
    assert row is not None
    return str(row[0])


def test_domain_rows_are_isolated_by_forced_rls(postgres_database: dict[str, str]) -> None:
    org_a, user_a = seed_tenant(postgres_database["owner_url"])
    org_b, user_b = seed_tenant(postgres_database["owner_url"])
    domain_a = insert_domain(postgres_database["owner_url"], org_a, user_a, "a.example.com")
    domain_b = insert_domain(postgres_database["owner_url"], org_b, user_b, "b.example.com")

    with psycopg.connect(postgres_database["app_url"]) as app:
        app.execute("SELECT set_config('app.user_id', %s, false)", (user_a,))
        app.execute("SELECT set_config('app.organization_id', %s, false)", (org_a,))
        assert app.execute("SELECT id::text FROM domains").fetchall() == [(domain_a,)]
        assert app.execute("SELECT id FROM domains WHERE id = %s", (domain_b,)).fetchone() is None


def test_only_one_active_challenge_per_domain_and_method(
    postgres_database: dict[str, str],
) -> None:
    organization_id, user_id = seed_tenant(postgres_database["owner_url"])
    domain_id = insert_domain(
        postgres_database["owner_url"], organization_id, user_id, "challenge.example.com"
    )
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        values = (organization_id, domain_id, bytes(32), user_id)
        owner.execute(
            "INSERT INTO domain_challenges "
            "(organization_id, domain_id, method, token_digest, expires_at, created_by_user_id) "
            "VALUES (%s, %s, 'dns_txt', %s, now() + interval '10 minutes', %s)",
            values,
        )
        with pytest.raises(psycopg.errors.UniqueViolation):
            owner.execute(
                "INSERT INTO domain_challenges "
                "(organization_id, domain_id, method, token_digest, expires_at, "
                "created_by_user_id) "
                "VALUES (%s, %s, 'dns_txt', %s, now() + interval '10 minutes', %s)",
                values,
            )


def test_verification_events_and_manifests_are_immutable_for_application_role(
    postgres_database: dict[str, str],
) -> None:
    organization_id, user_id = seed_tenant(postgres_database["owner_url"])
    domain_id = insert_domain(
        postgres_database["owner_url"], organization_id, user_id, "immutable.example.com"
    )
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        authorization_row = owner.execute(
            "INSERT INTO assessment_authorizations "
            "(organization_id, authorized_by_user_id, policy_version, consent_version, "
            "consent_text_digest, valid_from, valid_until) "
            "VALUES (%s, %s, 'policy-v1', 'consent-v1', %s, now(), now() + interval '1 day') "
            "RETURNING id::text",
            (organization_id, user_id, bytes(32)),
        ).fetchone()
        assert authorization_row is not None
        authorization_id = authorization_row[0]
        event_row = owner.execute(
            "INSERT INTO domain_verification_events "
            "(organization_id, domain_id, event_type, outcome, reason_code) "
            "VALUES (%s, %s, 'challenge_created', 'success', 'created') RETURNING id::text",
            (organization_id, domain_id),
        ).fetchone()
        assert event_row is not None
        event_id = event_row[0]
        manifest_row = owner.execute(
            "INSERT INTO scope_manifests "
            "(organization_id, authorization_id, manifest_version, canonical_payload, "
            "payload_hash, signature, key_id, algorithm) "
            "VALUES (%s, %s, 'v1', '{}'::jsonb, %s, %s, 'dev-key', 'EdDSA') RETURNING id::text",
            (organization_id, authorization_id, bytes([1]) * 32, bytes([2]) * 64),
        ).fetchone()
        assert manifest_row is not None
        manifest_id = manifest_row[0]

    with psycopg.connect(postgres_database["app_url"]) as app:
        app.execute("SELECT set_config('app.user_id', %s, false)", (user_id,))
        app.execute("SELECT set_config('app.organization_id', %s, false)", (organization_id,))
        for table, record_id in (
            ("domain_verification_events", event_id),
            ("scope_manifests", manifest_id),
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(
                    sql.SQL("UPDATE {} SET organization_id = organization_id WHERE id = %s").format(
                        sql.Identifier(table)
                    ),
                    (record_id,),
                )
            app.rollback()
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(
                    sql.SQL("DELETE FROM {} WHERE id = %s").format(sql.Identifier(table)),
                    (record_id,),
                )
            app.rollback()
