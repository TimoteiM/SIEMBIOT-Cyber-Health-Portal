"""Database-level guarantees for evidence, scores and findings.

The engines already enforce these rules in Python; these tests prove the database
enforces them too, so a bug or a compromised service cannot rewrite history.
"""

from __future__ import annotations

from uuid import uuid4

import psycopg
import pytest

METHODOLOGY = "1.0.0"
DIGEST = "a" * 64


def seed_tenant(owner_url: str) -> tuple[str, str]:
    organization_id, user_id = str(uuid4()), str(uuid4())
    with psycopg.connect(owner_url) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Test User')",
            (user_id, user_id, f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Tenant', %s, %s)",
            (organization_id, f"tenant-{organization_id[:12]}", user_id),
        )
        owner.execute(
            "INSERT INTO memberships (organization_id, user_id, role, status) "
            "VALUES (%s, %s, 'organization_owner', 'active')",
            (organization_id, user_id),
        )
    return organization_id, user_id


def seed_assessment(owner_url: str) -> dict[str, str]:
    organization_id, user_id = seed_tenant(owner_url)
    domain_id, assessment_id = str(uuid4()), str(uuid4())
    with psycopg.connect(owner_url) as owner:
        owner.execute(
            "INSERT INTO methodology_versions (version, policy_digest, notice) "
            "VALUES (%s, %s, 'test methodology') ON CONFLICT (version) DO NOTHING",
            (METHODOLOGY, DIGEST),
        )
        owner.execute(
            "INSERT INTO domains (id, organization_id, canonical_name, unicode_display, "
            "registrable_domain, ownership_state, created_by_user_id) "
            "VALUES (%s, %s, 'example.test', 'example.test', 'example.test', 'verified', %s)",
            (domain_id, organization_id, user_id),
        )
        owner.execute(
            "INSERT INTO assessments (id, organization_id, domain_id, methodology_version, state) "
            "VALUES (%s, %s, %s, %s, 'collecting')",
            (assessment_id, organization_id, domain_id, METHODOLOGY),
        )
    return {
        "organization_id": organization_id,
        "user_id": user_id,
        "domain_id": domain_id,
        "assessment_id": assessment_id,
    }


def insert_observation(
    connection: psycopg.Connection[tuple[object, ...]],
    fixture: dict[str, str],
    **overrides: object,
) -> str:
    observation_id = str(overrides.pop("id", uuid4()))
    connection.execute(
        "INSERT INTO normalized_observations ("
        "id, organization_id, assessment_id, subject_kind, subject_identifier, "
        "observation_type, status, attributes, attribution_confidence, source_confidence, "
        "freshness_confidence, adapter_id, adapter_version, collected_at, content_hash) "
        "VALUES (%s, %s, %s, 'domain', 'example.test', %s, %s, %s::jsonb, 1.0, 1.0, 1.0, "
        "'dns_resilience', '1.0.0', now(), %s)",
        (
            observation_id,
            fixture["organization_id"],
            fixture["assessment_id"],
            overrides.get("observation_type", "dns.dnssec"),
            overrides.get("status", "observed"),
            overrides.get("attributes", '{"state": "unsigned"}'),
            overrides.get("content_hash", "b" * 64),
        ),
    )
    return observation_id


def insert_evaluation(
    connection: psycopg.Connection[tuple[object, ...]],
    fixture: dict[str, str],
    **overrides: object,
) -> str:
    evaluation_id = str(uuid4())
    connection.execute(
        "INSERT INTO check_evaluations ("
        "id, organization_id, assessment_id, check_id, check_version, methodology_version, "
        "pillar, subject_kind, subject_identifier, result, score_bearing, weight, severity, "
        "attribution_confidence, source_confidence, freshness_confidence, evaluated_at) "
        "VALUES (%s, %s, %s, %s, '1.0.0', %s, 'dns', 'domain', 'example.test', %s, %s, 10, "
        "'medium', 1.0, 1.0, 1.0, now())",
        (
            evaluation_id,
            fixture["organization_id"],
            fixture["assessment_id"],
            overrides.get("check_id", "A.dnssec_enabled"),
            METHODOLOGY,
            overrides.get("result", "fail"),
            overrides.get("score_bearing", True),
        ),
    )
    return evaluation_id


def insert_snapshot(
    connection: psycopg.Connection[tuple[object, ...]],
    fixture: dict[str, str],
    **overrides: object,
) -> str:
    snapshot_id = str(uuid4())
    connection.execute(
        "INSERT INTO score_snapshots ("
        "id, organization_id, assessment_id, methodology_version, is_projection, "
        "policy_digest, evidence_digest, uncapped_score, score, band, coverage_percentage, "
        "coverage_sufficient, document, computed_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 100, true, '{}'::jsonb, now())",
        (
            snapshot_id,
            fixture["organization_id"],
            fixture["assessment_id"],
            METHODOLOGY,
            overrides.get("is_projection", False),
            DIGEST,
            DIGEST,
            overrides.get("uncapped_score", 80),
            overrides.get("score", 54),
            overrides.get("band", "exposed"),
        ),
    )
    return snapshot_id


def insert_finding(
    connection: psycopg.Connection[tuple[object, ...]],
    fixture: dict[str, str],
    **overrides: object,
) -> str:
    finding_id = str(uuid4())
    connection.execute(
        "INSERT INTO findings ("
        "id, organization_id, fingerprint, check_id, check_version, methodology_version, "
        "pillar, subject_kind, subject_identifier, severity, state, public_safety_class, "
        "attribution_confidence, source_confidence, freshness_confidence, first_seen_at, "
        "last_seen_at, resolved_at) "
        "VALUES (%s, %s, %s, 'A.dnssec_enabled', '1.0.0', %s, 'dns', 'domain', 'example.test', "
        "'medium', %s, 'public_profile', 1.0, 1.0, 1.0, now(), now(), %s)",
        (
            finding_id,
            fixture["organization_id"],
            overrides.get("fingerprint", "c" * 64),
            METHODOLOGY,
            overrides.get("state", "open"),
            overrides.get("resolved_at"),
        ),
    )
    return finding_id


# -- append-only evidence ----------------------------------------------------


def test_observations_cannot_be_updated_or_deleted(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        observation_id = insert_observation(owner, fixture)
        owner.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            owner.execute(
                "UPDATE normalized_observations SET status = 'absent' WHERE id = %s",
                (observation_id,),
            )
        owner.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            owner.execute("DELETE FROM normalized_observations WHERE id = %s", (observation_id,))


def test_non_observed_status_cannot_carry_scoreable_attributes(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with (
        psycopg.connect(postgres_database["owner_url"]) as owner,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        insert_observation(owner, fixture, status="absent", attributes='{"present": true}')


def test_absent_observation_without_attributes_is_accepted(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        insert_observation(owner, fixture, status="absent", attributes="{}")


def test_one_observation_per_type_and_subject_per_assessment(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        insert_observation(owner, fixture)
        owner.commit()
        with pytest.raises(psycopg.errors.UniqueViolation):
            insert_observation(owner, fixture)


# -- evaluations -------------------------------------------------------------


@pytest.mark.parametrize(
    ("result", "score_bearing"),
    [("unknown", True), ("pass", False), ("not_applicable", True), ("suppressed", True)],
)
def test_score_bearing_must_match_the_result(
    postgres_database: dict[str, str], result: str, score_bearing: bool
) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with (
        psycopg.connect(postgres_database["owner_url"]) as owner,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        insert_evaluation(owner, fixture, result=result, score_bearing=score_bearing)


def test_an_invented_result_state_is_rejected(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with (
        psycopg.connect(postgres_database["owner_url"]) as owner,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        insert_evaluation(owner, fixture, result="probably_fine", score_bearing=False)


def test_evaluations_cannot_be_rewritten(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        evaluation_id = insert_evaluation(owner, fixture)
        owner.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            owner.execute(
                "UPDATE check_evaluations SET result = 'pass' WHERE id = %s", (evaluation_id,)
            )


# -- snapshots ---------------------------------------------------------------


def test_a_cap_can_never_raise_a_score(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with (
        psycopg.connect(postgres_database["owner_url"]) as owner,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        insert_snapshot(owner, fixture, uncapped_score=50, score=90)


def test_a_completed_score_cannot_be_overwritten(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        snapshot_id = insert_snapshot(owner, fixture)
        owner.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            owner.execute("UPDATE score_snapshots SET score = 95 WHERE id = %s", (snapshot_id,))


def test_a_projection_coexists_with_the_original_snapshot(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        insert_snapshot(owner, fixture, is_projection=False)
        insert_snapshot(owner, fixture, is_projection=True)
        owner.commit()
        count = owner.execute(
            "SELECT count(*) FROM score_snapshots WHERE assessment_id = %s",
            (fixture["assessment_id"],),
        ).fetchone()
        assert count is not None
        assert count[0] == 2


def test_duplicate_original_snapshot_is_rejected(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        insert_snapshot(owner, fixture)
        owner.commit()
        with pytest.raises(psycopg.errors.UniqueViolation):
            insert_snapshot(owner, fixture)


def test_an_invalid_band_is_rejected(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with (
        psycopg.connect(postgres_database["owner_url"]) as owner,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        insert_snapshot(owner, fixture, band="excellent")


# -- findings ----------------------------------------------------------------


def test_resolved_state_requires_a_resolution_timestamp(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with (
        psycopg.connect(postgres_database["owner_url"]) as owner,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        insert_finding(owner, fixture, state="resolved", resolved_at=None)


def test_finding_identity_is_immutable_but_state_may_change(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        finding_id = insert_finding(owner, fixture)
        owner.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            owner.execute(
                "UPDATE findings SET fingerprint = %s WHERE id = %s", ("d" * 64, finding_id)
            )
        owner.rollback()
        owner.execute("UPDATE findings SET state = 'suppressed' WHERE id = %s", (finding_id,))
        owner.commit()
        state = owner.execute("SELECT state FROM findings WHERE id = %s", (finding_id,)).fetchone()
        assert state is not None
        assert state[0] == "suppressed"


def test_one_finding_per_fingerprint_per_tenant(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        insert_finding(owner, fixture)
        owner.commit()
        with pytest.raises(psycopg.errors.UniqueViolation):
            insert_finding(owner, fixture)


def test_the_same_fingerprint_may_exist_for_a_different_tenant(
    postgres_database: dict[str, str],
) -> None:
    first = seed_assessment(postgres_database["owner_url"])
    second = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        insert_finding(owner, first)
        insert_finding(owner, second)
        owner.commit()


def test_suppression_requires_a_reason_and_a_future_expiry(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        finding_id = insert_finding(owner, fixture)
        owner.commit()
        with pytest.raises(psycopg.errors.CheckViolation):
            owner.execute(
                "INSERT INTO finding_suppressions "
                "(id, organization_id, finding_id, reason, actor_user_id, expires_at) "
                "VALUES (%s, %s, %s, 'short', %s, now() + interval '30 days')",
                (str(uuid4()), fixture["organization_id"], finding_id, fixture["user_id"]),
            )
        owner.rollback()
        with pytest.raises(psycopg.errors.CheckViolation):
            owner.execute(
                "INSERT INTO finding_suppressions "
                "(id, organization_id, finding_id, reason, actor_user_id, expires_at) "
                "VALUES (%s, %s, %s, 'A documented compensating control', %s, "
                "now() - interval '1 day')",
                (str(uuid4()), fixture["organization_id"], finding_id, fixture["user_id"]),
            )


def test_finding_history_is_append_only(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        finding_id = insert_finding(owner, fixture)
        history_id = str(uuid4())
        owner.execute(
            "INSERT INTO finding_history "
            "(id, organization_id, finding_id, assessment_id, from_state, to_state) "
            "VALUES (%s, %s, %s, %s, 'absent', 'open')",
            (history_id, fixture["organization_id"], finding_id, fixture["assessment_id"]),
        )
        owner.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            owner.execute("DELETE FROM finding_history WHERE id = %s", (history_id,))


# -- tenant isolation --------------------------------------------------------


def test_findings_and_evidence_are_invisible_across_tenants(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    other_organization, other_user = seed_tenant(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        insert_finding(owner, fixture)
        insert_observation(owner, fixture)
        owner.commit()

    with psycopg.connect(postgres_database["app_url"]) as app:
        app.execute("SELECT set_config('app.organization_id', %s, false)", (other_organization,))
        app.execute("SELECT set_config('app.user_id', %s, false)", (other_user,))
        assert app.execute("SELECT id FROM findings").fetchall() == []
        assert app.execute("SELECT id FROM normalized_observations").fetchall() == []
        assert app.execute("SELECT id FROM score_snapshots").fetchall() == []

        app.execute(
            "SELECT set_config('app.organization_id', %s, false)", (fixture["organization_id"],)
        )
        app.execute("SELECT set_config('app.user_id', %s, false)", (fixture["user_id"],))
        assert len(app.execute("SELECT id FROM findings").fetchall()) == 1
        assert len(app.execute("SELECT id FROM normalized_observations").fetchall()) == 1


def test_application_role_cannot_delete_a_finding(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        finding_id = insert_finding(owner, fixture)
        owner.commit()

    with psycopg.connect(postgres_database["app_url"]) as app:
        app.execute(
            "SELECT set_config('app.organization_id', %s, false)", (fixture["organization_id"],)
        )
        app.execute("SELECT set_config('app.user_id', %s, false)", (fixture["user_id"],))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("DELETE FROM findings WHERE id = %s", (finding_id,))
