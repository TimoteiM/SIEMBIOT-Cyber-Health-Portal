"""Database-level guarantees for orchestration and asset attribution.

The engine's correctness rests on three claims that only the database can actually
enforce across workers: a lease is exclusive, a completed idempotency key is unique,
and attempt history is append-only. These tests attack all three with real connections
rather than trusting the in-process implementation.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import psycopg
import pytest
from siembiot_worker.workflows.engine import StepRecord
from siembiot_worker.workflows.graph import StepState
from siembiot_worker.workflows.lifecycle import AssessmentState, LifecycleError
from siembiot_worker.workflows.postgres_repository import PostgresWorkflowRepository
from sqlalchemy import Connection, create_engine, text

METHODOLOGY = "1.0.0"
DIGEST = "a" * 64


def seed_assessment(owner_url: str) -> dict[str, str]:
    organization_id, user_id = str(uuid4()), str(uuid4())
    domain_id, assessment_id = str(uuid4()), str(uuid4())
    with psycopg.connect(owner_url) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Orchestration user')",
            (user_id, user_id, f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Tenant', %s, %s)",
            (organization_id, f"orch-{organization_id[:12]}", user_id),
        )
        owner.execute(
            "INSERT INTO memberships (organization_id, user_id, role, status) "
            "VALUES (%s, %s, 'organization_owner', 'active')",
            (organization_id, user_id),
        )
        owner.execute(
            "INSERT INTO methodology_versions (version, policy_digest, notice) "
            "VALUES (%s, %s, 'test') ON CONFLICT (version) DO NOTHING",
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
            "VALUES (%s, %s, %s, %s, 'queued')",
            (assessment_id, organization_id, domain_id, METHODOLOGY),
        )
    return {
        "organization_id": organization_id,
        "user_id": user_id,
        "domain_id": domain_id,
        "assessment_id": assessment_id,
    }


def repository(url: str, fixture: dict[str, str]) -> tuple[PostgresWorkflowRepository, Connection]:
    engine = create_engine(url.replace("postgresql://", "postgresql+psycopg://"))
    connection = engine.connect()
    return PostgresWorkflowRepository(connection, UUID(fixture["organization_id"])), connection


# -- leases ------------------------------------------------------------------


def test_only_one_worker_can_hold_a_lease(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    assessment = UUID(fixture["assessment_id"])
    first, first_connection = repository(postgres_database["owner_url"], fixture)
    second, second_connection = repository(postgres_database["owner_url"], fixture)
    expires = datetime.now(UTC) + timedelta(minutes=5)
    worker_a, worker_b = uuid4(), uuid4()
    try:
        assert first.acquire_lease(assessment, "plan", worker_a, expires) is True
        first_connection.commit()

        assert second.acquire_lease(assessment, "plan", worker_b, expires) is False
        second_connection.rollback()
    finally:
        first_connection.close()
        second_connection.close()


def test_an_expired_lease_can_be_reclaimed(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    assessment = UUID(fixture["assessment_id"])
    workflow, connection = repository(postgres_database["owner_url"], fixture)
    try:
        stale = datetime.now(UTC) - timedelta(minutes=1)
        assert workflow.acquire_lease(assessment, "plan", uuid4(), stale) is True
        connection.commit()
        assert (
            workflow.acquire_lease(
                assessment, "plan", uuid4(), datetime.now(UTC) + timedelta(minutes=5)
            )
            is True
        )
        connection.commit()
    finally:
        connection.close()


def test_the_same_worker_may_renew_its_own_lease(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    assessment = UUID(fixture["assessment_id"])
    workflow, connection = repository(postgres_database["owner_url"], fixture)
    worker = uuid4()
    try:
        expires = datetime.now(UTC) + timedelta(minutes=5)
        assert workflow.acquire_lease(assessment, "plan", worker, expires) is True
        assert workflow.acquire_lease(assessment, "plan", worker, expires) is True
        connection.commit()
    finally:
        connection.close()


def test_releasing_a_lease_lets_another_worker_take_it(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    assessment = UUID(fixture["assessment_id"])
    workflow, connection = repository(postgres_database["owner_url"], fixture)
    worker_a, worker_b = uuid4(), uuid4()
    try:
        expires = datetime.now(UTC) + timedelta(minutes=5)
        workflow.acquire_lease(assessment, "plan", worker_a, expires)
        workflow.release_lease(assessment, "plan", worker_a)
        connection.commit()
        assert workflow.acquire_lease(assessment, "plan", worker_b, expires) is True
        connection.commit()
    finally:
        connection.close()


def test_a_lease_is_all_or_nothing(postgres_database: dict[str, str]) -> None:
    """Half a lease -- an owner with no expiry -- would never be reclaimable."""
    fixture = seed_assessment(postgres_database["owner_url"])
    with (
        psycopg.connect(postgres_database["owner_url"]) as owner,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        owner.execute(
            "INSERT INTO assessment_steps "
            "(organization_id, assessment_id, name, state, lease_owner) "
            "VALUES (%s, %s, 'plan', 'pending', %s)",
            (fixture["organization_id"], fixture["assessment_id"], str(uuid4())),
        )


# -- idempotency -------------------------------------------------------------


def test_a_completed_key_cannot_be_recorded_twice(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    assessment = UUID(fixture["assessment_id"])
    workflow, connection = repository(postgres_database["owner_url"], fixture)
    try:
        key = f"key-{uuid4()}"
        assert workflow.record_completed_key(key, assessment, "plan") is True
        connection.commit()
        assert workflow.has_completed_key(key) is True
        assert workflow.record_completed_key(key, assessment, "plan") is False
        connection.commit()
    finally:
        connection.close()


def test_two_workers_racing_to_record_the_same_key_produce_one_winner(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    assessment = UUID(fixture["assessment_id"])
    first, first_connection = repository(postgres_database["owner_url"], fixture)
    second, second_connection = repository(postgres_database["owner_url"], fixture)
    key = f"key-{uuid4()}"
    try:
        assert first.record_completed_key(key, assessment, "plan") is True
        first_connection.commit()
        assert second.record_completed_key(key, assessment, "plan") is False
        second_connection.commit()
    finally:
        first_connection.close()
        second_connection.close()


def test_a_recorded_key_cannot_be_rewritten(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        key = f"key-{uuid4()}"
        owner.execute(
            "INSERT INTO workflow_idempotency_keys "
            "(key, organization_id, assessment_id, step_name) VALUES (%s, %s, %s, 'plan')",
            (key, fixture["organization_id"], fixture["assessment_id"]),
        )
        owner.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            owner.execute(
                "UPDATE workflow_idempotency_keys SET step_name = 'other' WHERE key = %s",
                (key,),
            )


# -- attempt history ---------------------------------------------------------


def test_attempt_history_is_append_only(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    assessment = UUID(fixture["assessment_id"])
    workflow, connection = repository(postgres_database["owner_url"], fixture)
    try:
        workflow.record_attempt(assessment, "collect.dns", 1, "retryable_failure", error="timeout")
        workflow.record_attempt(assessment, "collect.dns", 2, "succeeded")
        connection.commit()
        history = workflow.attempts_for(assessment)
        assert [item["attempt"] for item in history] == [1, 2]
        assert history[0]["error"] == "timeout"
    finally:
        connection.close()

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            owner.execute(
                "UPDATE assessment_step_attempts SET outcome = 'succeeded' "
                "WHERE assessment_id = %s",
                (fixture["assessment_id"],),
            )
        owner.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            owner.execute(
                "DELETE FROM assessment_step_attempts WHERE assessment_id = %s",
                (fixture["assessment_id"],),
            )


def test_recording_the_same_attempt_twice_is_ignored(postgres_database: dict[str, str]) -> None:
    """A replay must not corrupt the record of what already happened."""
    fixture = seed_assessment(postgres_database["owner_url"])
    assessment = UUID(fixture["assessment_id"])
    workflow, connection = repository(postgres_database["owner_url"], fixture)
    try:
        workflow.record_attempt(assessment, "plan", 1, "succeeded")
        workflow.record_attempt(assessment, "plan", 1, "permanent_failure")
        connection.commit()
        history = workflow.attempts_for(assessment)
        assert len(history) == 1
        assert history[0]["outcome"] == "succeeded"
    finally:
        connection.close()


def test_an_invented_attempt_outcome_is_rejected(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with (
        psycopg.connect(postgres_database["owner_url"]) as owner,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        owner.execute(
            "INSERT INTO assessment_step_attempts "
            "(organization_id, assessment_id, step_name, attempt, outcome) "
            "VALUES (%s, %s, 'plan', 1, 'probably_worked')",
            (fixture["organization_id"], fixture["assessment_id"]),
        )


# -- step state --------------------------------------------------------------


def test_step_state_round_trips_through_the_repository(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    assessment = UUID(fixture["assessment_id"])
    workflow, connection = repository(postgres_database["owner_url"], fixture)
    try:
        workflow.upsert_step(
            StepRecord(
                assessment,
                "collect.dns",
                StepState.SUCCEEDED,
                attempts=2,
                idempotency_key="key-1234567890",
                result={"records": 4},
            )
        )
        connection.commit()
        loaded = workflow.load_steps(assessment)["collect.dns"]
        assert loaded.state is StepState.SUCCEEDED
        assert loaded.attempts == 2
        assert loaded.result == {"records": 4}
    finally:
        connection.close()


def test_an_invented_step_state_is_rejected(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with (
        psycopg.connect(postgres_database["owner_url"]) as owner,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        owner.execute(
            "INSERT INTO assessment_steps (organization_id, assessment_id, name, state) "
            "VALUES (%s, %s, 'plan', 'sort_of_running')",
            (fixture["organization_id"], fixture["assessment_id"]),
        )


def test_the_lifecycle_is_enforced_when_setting_assessment_state(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    assessment = UUID(fixture["assessment_id"])
    workflow, connection = repository(postgres_database["owner_url"], fixture)
    try:
        with pytest.raises(LifecycleError, match="illegal_transition"):
            workflow.set_state(assessment, AssessmentState.COMPLETED)
        workflow.set_state(assessment, AssessmentState.PLANNING)
        connection.commit()
        assert workflow.load_state(assessment) is AssessmentState.PLANNING
    finally:
        connection.close()


def test_cancellation_is_a_request_that_survives_a_reconnect(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    assessment = UUID(fixture["assessment_id"])
    workflow, connection = repository(postgres_database["owner_url"], fixture)
    try:
        assert workflow.is_cancellation_requested(assessment) is False
        workflow.request_cancellation(assessment, "authorization revoked")
        connection.commit()
    finally:
        connection.close()

    fresh, fresh_connection = repository(postgres_database["owner_url"], fixture)
    try:
        assert fresh.is_cancellation_requested(assessment) is True
    finally:
        fresh_connection.close()


# -- asset candidates --------------------------------------------------------


def test_a_candidate_is_unique_per_domain(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        for _ in range(1):
            owner.execute(
                "INSERT INTO asset_candidates (organization_id, domain_id, name, source, "
                "attribution_confidence, attribution_basis) "
                "VALUES (%s, %s, 'www.example.test', 'certificate_transparency', 0.9, "
                "'subdomain_of_authorized_domain')",
                (fixture["organization_id"], fixture["domain_id"]),
            )
        owner.commit()
        with pytest.raises(psycopg.errors.UniqueViolation):
            owner.execute(
                "INSERT INTO asset_candidates (organization_id, domain_id, name, source, "
                "attribution_confidence, attribution_basis) "
                "VALUES (%s, %s, 'www.example.test', 'dns', 0.5, 'unrelated_name')",
                (fixture["organization_id"], fixture["domain_id"]),
            )


def test_a_candidate_defaults_to_unreviewed_rather_than_in_scope(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        state = owner.execute(
            "INSERT INTO asset_candidates (organization_id, domain_id, name, source, "
            "attribution_confidence, attribution_basis) "
            "VALUES (%s, %s, 'new.example.test', 'certificate_transparency', 0.9, "
            "'subdomain_of_authorized_domain') RETURNING state",
            (fixture["organization_id"], fixture["domain_id"]),
        ).fetchone()
        assert state is not None
        assert state[0] == "unreviewed"


def test_an_invented_attribution_basis_is_rejected(postgres_database: dict[str, str]) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with (
        psycopg.connect(postgres_database["owner_url"]) as owner,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        owner.execute(
            "INSERT INTO asset_candidates (organization_id, domain_id, name, source, "
            "attribution_confidence, attribution_basis) "
            "VALUES (%s, %s, 'x.example.test', 'dns', 0.9, 'looks_about_right')",
            (fixture["organization_id"], fixture["domain_id"]),
        )


def test_an_asset_decision_is_append_only_and_attributable(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        candidate = owner.execute(
            "INSERT INTO asset_candidates (organization_id, domain_id, name, source, "
            "attribution_confidence, attribution_basis) "
            "VALUES (%s, %s, 'decide.example.test', 'dns', 0.9, "
            "'subdomain_of_authorized_domain') RETURNING id::text",
            (fixture["organization_id"], fixture["domain_id"]),
        ).fetchone()
        assert candidate is not None
        owner.execute(
            "INSERT INTO asset_candidate_decisions "
            "(organization_id, candidate_id, decision, actor_user_id, reason) "
            "VALUES (%s, %s, 'accepted', %s, 'Confirmed ours')",
            (fixture["organization_id"], candidate[0], fixture["user_id"]),
        )
        owner.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            owner.execute(
                "UPDATE asset_candidate_decisions SET decision = 'rejected' "
                "WHERE candidate_id = %s",
                (candidate[0],),
            )


# -- tenant isolation --------------------------------------------------------


def test_orchestration_state_is_invisible_across_tenants(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed_assessment(postgres_database["owner_url"])
    other = seed_assessment(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        owner.execute(
            "INSERT INTO assessment_steps (organization_id, assessment_id, name, state) "
            "VALUES (%s, %s, 'plan', 'succeeded')",
            (fixture["organization_id"], fixture["assessment_id"]),
        )
        owner.execute(
            "INSERT INTO asset_candidates (organization_id, domain_id, name, source, "
            "attribution_confidence, attribution_basis) "
            "VALUES (%s, %s, 'private.example.test', 'dns', 0.9, "
            "'subdomain_of_authorized_domain')",
            (fixture["organization_id"], fixture["domain_id"]),
        )
        owner.commit()

    with psycopg.connect(postgres_database["app_url"]) as app:
        app.execute(
            "SELECT set_config('app.organization_id', %s, false)", (other["organization_id"],)
        )
        app.execute("SELECT set_config('app.user_id', %s, false)", (other["user_id"],))
        assert app.execute("SELECT id FROM assessment_steps").fetchall() == []
        assert app.execute("SELECT id FROM asset_candidates").fetchall() == []

        app.execute(
            "SELECT set_config('app.organization_id', %s, false)",
            (fixture["organization_id"],),
        )
        app.execute("SELECT set_config('app.user_id', %s, false)", (fixture["user_id"],))
        assert len(app.execute("SELECT id FROM assessment_steps").fetchall()) == 1
        assert len(app.execute("SELECT id FROM asset_candidates").fetchall()) == 1


def test_a_contended_lease_is_declined_rather_than_waited_on(
    postgres_database: dict[str, str],
) -> None:
    """A worker that meets a held lease must learn "not mine" promptly.

    Without a lock timeout the loser blocks on the row for as long as the winner's
    transaction lasts. When a run is dispatched more than once -- which the sweep does
    by design, because redelivery is meant to be harmless -- that turns a normal race
    into worker threads parked for the length of somebody else's assessment.
    """
    fixture = seed_assessment(postgres_database["owner_url"])
    assessment = UUID(fixture["assessment_id"])
    holder, holder_connection = repository(postgres_database["owner_url"], fixture)
    contender, contender_connection = repository(postgres_database["owner_url"], fixture)
    expires = datetime.now(UTC) + timedelta(minutes=5)
    try:
        # The winner takes the lease and keeps its transaction open, exactly as a
        # worker part-way through a step would.
        assert holder.acquire_lease(assessment, "plan", uuid4(), expires) is True

        contender_connection.execute(text("SET lock_timeout = 500"))
        started = time.monotonic()
        acquired = contender.acquire_lease(assessment, "plan", uuid4(), expires)
        elapsed = time.monotonic() - started

        assert acquired is False
        assert elapsed < 5.0, f"waited {elapsed:.1f}s for a lease another worker holds"
    finally:
        holder_connection.rollback()
        contender_connection.rollback()
        holder_connection.close()
        contender_connection.close()
