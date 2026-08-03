from __future__ import annotations

from uuid import UUID, uuid4

import psycopg
import pytest


def seed_scope(owner_url: str, label: str) -> tuple[str, str, str, str]:
    org, user = str(uuid4()), str(uuid4())
    with psycopg.connect(owner_url) as owner:
        owner.execute(
            "INSERT INTO users (id,oidc_issuer,oidc_subject,email,display_name) VALUES (%s,'https://idp.example.test',%s,%s,'Evidence user')",
            (user, user, f"{user}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id,name,slug,created_by_user_id) VALUES (%s,'Evidence tenant',%s,%s)",
            (org, f"evidence-{label}-{org[:8]}", user),
        )
        owner.execute(
            "INSERT INTO memberships (organization_id,user_id,role) VALUES (%s,%s,'organization_owner')",
            (org, user),
        )
        domain_row = owner.execute(
            "INSERT INTO domains (organization_id,canonical_name,unicode_display,registrable_domain,created_by_user_id) VALUES (%s,%s,%s,%s,%s) RETURNING id::text",
            (org, f"{label}.example.test", f"{label}.example.test", f"{label}.example.test", user),
        ).fetchone()
        assert domain_row is not None
        domain = domain_row[0]
        authorization_row = owner.execute(
            "INSERT INTO assessment_authorizations (organization_id,authorized_by_user_id,policy_version,consent_version,consent_text_digest,valid_from,valid_until) VALUES (%s,%s,'v1','v1',%s,now(),now()+interval '1 day') RETURNING id::text",
            (org, user, bytes(32)),
        ).fetchone()
        assert authorization_row is not None
        authorization = authorization_row[0]
        manifest_row = owner.execute(
            "INSERT INTO scope_manifests (organization_id,authorization_id,manifest_version,canonical_payload,payload_hash,signature,key_id,algorithm) VALUES (%s,%s,'v1','{}',%s,%s,'fixture-key','EdDSA') RETURNING id::text",
            (org, authorization, UUID(org).bytes * 2, UUID(user).bytes * 4),
        ).fetchone()
        assert manifest_row is not None
        manifest = manifest_row[0]
    return org, user, domain, manifest


def insert_observation(
    owner_url: str, org: str, asset: str, manifest: str, *, mode: str = "fixture"
) -> str:
    digest = bytes.fromhex("ab" * 32)
    with psycopg.connect(owner_url) as owner:
        row = owner.execute(
            "INSERT INTO normalized_observations (organization_id,asset_id,scope_manifest_id,evidence_mode,normalized_hash,hash_version,schema_version,observation_type,source_evidence_id,payload,observed_at,source_confidence,attribution_confidence,publishable,real_world) VALUES (%s,%s,%s,%s,%s,'sha256-v1','v1','dns.dnssec',%s,'{}',now(),1,1,%s,%s) RETURNING id::text",
            (
                org,
                asset,
                manifest,
                mode,
                digest,
                "sha256:" + "a" * 64,
                mode == "live",
                mode == "live",
            ),
        ).fetchone()
    assert row is not None
    return str(row[0])


def test_evidence_tables_are_present(postgres_database: dict[str, str]) -> None:
    expected = {
        "raw_artifacts",
        "normalized_observations",
        "check_evaluations",
        "evaluation_evidence",
        "score_snapshots",
        "snapshot_evaluations",
        "score_attributions",
        "findings",
        "finding_occurrences",
        "finding_events",
    }
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        actual = {
            row[0]
            for row in owner.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")
        }
    assert expected <= actual


def test_application_role_rls_and_hash_lookup_are_tenant_scoped(
    postgres_database: dict[str, str],
) -> None:
    org_a, user_a, asset_a, manifest_a = seed_scope(postgres_database["owner_url"], "a1")
    org_b, _, asset_b, manifest_b = seed_scope(postgres_database["owner_url"], "b2")
    own = insert_observation(postgres_database["owner_url"], org_a, asset_a, manifest_a)
    other = insert_observation(postgres_database["owner_url"], org_b, asset_b, manifest_b)
    with psycopg.connect(postgres_database["app_url"]) as app:
        assert app.execute("SELECT id FROM normalized_observations").fetchall() == []
        app.execute("SELECT set_config('app.user_id',%s,false)", (user_a,))
        app.execute("SELECT set_config('app.organization_id',%s,false)", (org_a,))
        assert app.execute(
            "SELECT id::text FROM normalized_observations WHERE normalized_hash=%s",
            (bytes.fromhex("ab" * 32),),
        ).fetchall() == [(own,)]
        assert (
            app.execute("SELECT id FROM normalized_observations WHERE id=%s", (other,)).fetchone()
            is None
        )


def test_append_only_records_reject_update_and_delete_for_app_and_owner(
    postgres_database: dict[str, str],
) -> None:
    org, user, asset, manifest = seed_scope(postgres_database["owner_url"], "c3")
    observation = insert_observation(postgres_database["owner_url"], org, asset, manifest)
    with psycopg.connect(postgres_database["app_url"]) as app:
        app.execute("SELECT set_config('app.user_id',%s,false)", (user,))
        app.execute("SELECT set_config('app.organization_id',%s,false)", (org,))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(
                "UPDATE normalized_observations SET payload='{}' WHERE id=%s", (observation,)
            )
        app.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("DELETE FROM normalized_observations WHERE id=%s", (observation,))
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            owner.execute("DELETE FROM normalized_observations WHERE id=%s", (observation,))


def test_database_rejects_fixture_relabel_and_mixed_mode_lineage(
    postgres_database: dict[str, str],
) -> None:
    org, _, asset, manifest = seed_scope(postgres_database["owner_url"], "d4")
    observation = insert_observation(postgres_database["owner_url"], org, asset, manifest)
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        with pytest.raises(psycopg.errors.CheckViolation):
            owner.execute(
                "INSERT INTO score_snapshots (organization_id,asset_id,scope_manifest_id,evidence_mode,snapshot_hash,policy_hash,methodology_version,scoring_behavior_version,coverage,evidence_confidence,attribution_confidence,publishable,classification) VALUES (%s,%s,%s,'fixture',%s,%s,'1.0.0','1.0.0',100,1,1,true,'PRIVATE')",
                (org, asset, manifest, bytes(32), bytes([1]) * 32),
            )
        owner.rollback()
        evaluation_row = owner.execute(
            "INSERT INTO check_evaluations (organization_id,asset_id,scope_manifest_id,evidence_mode,evaluation_hash,policy_hash,check_id,methodology_version,scoring_behavior_version,outcome,reason_code,evaluated_at,publishable) VALUES (%s,%s,%s,'live',%s,%s,'dns.dnssec','1.0.0','1.0.0','pass','source_outcome',now(),true) RETURNING id",
            (org, asset, manifest, bytes([2]) * 32, bytes([1]) * 32),
        ).fetchone()
        assert evaluation_row is not None
        evaluation = evaluation_row[0]
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            owner.execute(
                "INSERT INTO evaluation_evidence (organization_id,evaluation_id,observation_id,evidence_mode) VALUES (%s,%s,%s,'live')",
                (org, evaluation, observation),
            )
