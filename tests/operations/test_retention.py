"""Retention: what gets removed, what never does, and what must be said afterwards.

Evidence accumulated indefinitely because nothing removed it, which is a privacy problem
before it is a storage one. But a sweep that deletes tenant data on a timer is a
dangerous thing to add, so what is tested here is mostly what it must *not* do.

The subtlest requirement is the last one. Deleting the workings while leaving a score
that still carries a policy digest and an evidence digest would invite a reader to
believe the calculation could be checked. It cannot. That has to be said on the record
itself, not in a runbook nobody reads.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import create_engine, text

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "worker" / "src"))

from siembiot_worker.retention import (  # noqa: E402
    RETENTION_SCHEDULE,
    SWEPT_TABLES,
    RetentionClass,
    classified_tables,
    record_run,
    sweep_retention,
)

METHODOLOGY = "1.0.0"
DIGEST = "d" * 64


def _tables(owner_url: str) -> set[str]:
    with psycopg.connect(owner_url, autocommit=True) as owner:
        return {
            name
            for (name,) in owner.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
            )
        }


# -- the schedule must cover everything ----------------------------------------------


def test_every_table_is_classified(postgres_database: dict[str, str]) -> None:
    """The dangerous failure here is silence.

    A table added next year and never classified would simply grow, and nothing would
    say so -- which is exactly how evidence came to accumulate indefinitely in the first
    place. "Not listed" must not be a way of deciding retention by accident.
    """
    unclassified = _tables(postgres_database["owner_url"]) - classified_tables()

    assert not unclassified, (
        f"{sorted(unclassified)} have no retention class. Decide whether each is swept, "
        "kept with the organization, or never removed -- and say so in the schedule."
    )


def test_the_schedule_names_no_table_that_does_not_exist(
    postgres_database: dict[str, str],
) -> None:
    """A typo would make the sweep quietly skip real data while appearing to run."""
    missing = classified_tables() - _tables(postgres_database["owner_url"])

    assert not missing, sorted(missing)


def test_every_swept_column_exists(postgres_database: dict[str, str]) -> None:
    """A wrong column name is the failure that looks most like success: the sweep runs,
    reports no error, and removes nothing at all."""
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        for entry in SWEPT_TABLES:
            found = owner.execute(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name = %s AND column_name = %s",
                (entry.table, entry.age_column),
            ).fetchone()
            assert found, f"{entry.table}.{entry.age_column} does not exist"


# -- what must never be swept ---------------------------------------------------------


def test_the_audit_trail_is_never_swept() -> None:
    """Its rows are chained by hash, so removing one breaks verification of everything
    after it. An accountability record that can be aged out by a nightly job is not an
    accountability record."""
    audit = [entry for entry in RETENTION_SCHEDULE if entry.table == "audit_events"]

    assert audit and audit[0].retention_class is RetentionClass.ACCOUNTABILITY
    assert not audit[0].is_swept
    assert "audit_events" not in {entry.table for entry in SWEPT_TABLES}


def test_no_accountability_or_record_table_is_swept() -> None:
    """An institution's own scores and findings are its record, and the evidence that
    somebody authorized us to touch their systems is our defence. Neither expires
    because a timer said so."""
    for entry in RETENTION_SCHEDULE:
        if entry.retention_class in (RetentionClass.ACCOUNTABILITY, RetentionClass.RECORD):
            assert not entry.is_swept, entry.table


def test_authorizations_outlive_their_own_expiry() -> None:
    """The question later is not "may we probe this?" but "were we allowed to, then?".
    Deleting the signed permission would remove the only answer."""
    entry = next(e for e in RETENTION_SCHEDULE if e.table == "assessment_authorizations")

    assert entry.retention_class is RetentionClass.ACCOUNTABILITY
    assert not entry.is_swept


def test_idempotency_keys_outlive_any_run() -> None:
    """The one swept table where deleting too early is a correctness bug rather than
    lost information: the key is what stops a redelivered message running a step twice."""
    entry = next(e for e in RETENTION_SCHEDULE if e.table == "workflow_idempotency_keys")

    assert entry.period is not None
    assert entry.period >= timedelta(days=30)


def test_nothing_kept_may_reference_something_swept(
    postgres_database: dict[str, str],
) -> None:
    """The structural version of a bug found by running the sweep against real data.

    `domain_verification_events` is accountability data that never goes, and it holds a
    foreign key to the challenge it verified. Sweeping challenges therefore failed on the
    constraint -- but only where a verification had actually happened, so a test database
    with no verifications in it was perfectly green.

    Read from the foreign keys rather than from a list, because the point is to catch the
    next one of these rather than to record this one.
    """
    swept = {entry.table for entry in SWEPT_TABLES}
    kept = {entry.table for entry in RETENTION_SCHEDULE} - swept

    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        references = owner.execute(
            """
            SELECT source.relname AS referencing, target.relname AS referenced
            FROM pg_constraint c
            JOIN pg_class source ON source.oid = c.conrelid
            JOIN pg_class target ON target.oid = c.confrelid
            WHERE c.contype = 'f'
            """
        ).fetchall()

    conflicts = [
        (referencing, referenced)
        for referencing, referenced in references
        if referencing in kept and referenced in swept and referencing != referenced
    ]

    assert not conflicts, (
        f"{conflicts} -- a table that is never removed points at one that is swept. "
        "The sweep will fail on the constraint as soon as a real row exists, and the "
        "kept record would be meaningless without what it references."
    )


# -- the sweep itself -----------------------------------------------------------------


def seed_assessment(owner_url: str, *, observed_days_ago: int) -> tuple[UUID, UUID]:
    organization_id, user_id = uuid4(), uuid4()
    domain_id, assessment_id = uuid4(), uuid4()
    when = datetime.now(UTC) - timedelta(days=observed_days_ago)
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Retention user')",
            (str(user_id), str(user_id), f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Retention', %s, %s)",
            (str(organization_id), f"rt-{organization_id.hex[:12]}", str(user_id)),
        )
        owner.execute(
            "INSERT INTO methodology_versions (version, policy_digest, notice) "
            "VALUES (%s, %s, 'test') ON CONFLICT (version) DO NOTHING",
            (METHODOLOGY, DIGEST),
        )
        owner.execute(
            "INSERT INTO domains (id, organization_id, canonical_name, unicode_display, "
            "registrable_domain, ownership_state, created_by_user_id) "
            "VALUES (%s, %s, 'ret.test', 'ret.test', 'ret.test', 'verified', %s)",
            (str(domain_id), str(organization_id), str(user_id)),
        )
        owner.execute(
            "INSERT INTO assessments (id, organization_id, domain_id, methodology_version, "
            "state, completed_at) VALUES (%s, %s, %s, %s, 'completed', %s)",
            (str(assessment_id), str(organization_id), str(domain_id), METHODOLOGY, when),
        )
        owner.execute(
            "INSERT INTO score_snapshots (id, organization_id, assessment_id, "
            "methodology_version, policy_digest, evidence_digest, score, band, "
            "coverage_percentage, coverage_sufficient, is_projection, document, computed_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, 50, 'developing', 90, true, false, '{}', %s)",
            (
                str(uuid4()),
                str(organization_id),
                str(assessment_id),
                METHODOLOGY,
                DIGEST,
                DIGEST,
                when,
            ),
        )
        owner.execute(
            "INSERT INTO normalized_observations (id, organization_id, assessment_id, "
            "subject_kind, subject_identifier, authorized_domain_id, observation_type, "
            "status, attributes, attribution_confidence, source_confidence, "
            "freshness_confidence, confidence_reasons, adapter_id, adapter_version, "
            "content_hash, collected_at) VALUES (%s, %s, %s, 'domain', 'ret.test', %s, "
            "'dns.caa', 'observed', '{}', 1.0, 1.0, 1.0, '{}', 'dns_resilience', "
            "'1.0.0', %s, %s)",
            (
                str(uuid4()),
                str(organization_id),
                str(assessment_id),
                str(domain_id),
                DIGEST,
                when,
            ),
        )
    return organization_id, assessment_id


def engine_for(postgres_database: dict[str, str]):  # type: ignore[no-untyped-def]
    """Connected as the retention role, not the owner.

    Running these against the owner would prove the sweep works with privileges it does
    not have in production, which is the most comfortable kind of green test and the
    least useful.
    """
    return create_engine(
        postgres_database["retention_url"].replace("postgresql://", "postgresql+psycopg://")
    )


def test_old_evidence_is_removed_and_recent_evidence_is_not(
    postgres_database: dict[str, str],
) -> None:
    old_org, old_assessment = seed_assessment(postgres_database["owner_url"], observed_days_ago=200)
    _, fresh_assessment = seed_assessment(postgres_database["owner_url"], observed_days_ago=3)
    del old_org

    engine = engine_for(postgres_database)
    try:
        with engine.begin() as connection:
            sweep_retention(connection)
        with engine.begin() as connection:
            remaining = {
                str(row[0])
                for row in connection.execute(
                    text("SELECT assessment_id FROM normalized_observations")
                )
            }
    finally:
        engine.dispose()

    assert str(old_assessment) not in remaining
    assert str(fresh_assessment) in remaining


def test_a_score_whose_evidence_is_gone_stops_claiming_to_be_reproducible(
    postgres_database: dict[str, str],
) -> None:
    """The point of the whole feature.

    A snapshot carries a policy digest and an evidence digest so it can be recomputed
    and checked. Once the observations are removed it cannot be, and a row that says
    nothing about that invites a reader to believe otherwise.
    """
    _, assessment_id = seed_assessment(postgres_database["owner_url"], observed_days_ago=200)

    engine = engine_for(postgres_database)
    try:
        with engine.begin() as connection:
            result = sweep_retention(connection)
        with engine.begin() as connection:
            erased = connection.execute(
                text("SELECT evidence_erased_at FROM score_snapshots WHERE assessment_id = :id"),
                {"id": assessment_id},
            ).scalar_one()
    finally:
        engine.dispose()

    assert result.snapshots_marked >= 1
    assert erased is not None


def test_a_score_with_its_evidence_intact_is_not_marked(
    postgres_database: dict[str, str],
) -> None:
    _, assessment_id = seed_assessment(postgres_database["owner_url"], observed_days_ago=3)

    engine = engine_for(postgres_database)
    try:
        with engine.begin() as connection:
            sweep_retention(connection)
        with engine.begin() as connection:
            erased = connection.execute(
                text("SELECT evidence_erased_at FROM score_snapshots WHERE assessment_id = :id"),
                {"id": assessment_id},
            ).scalar_one()
    finally:
        engine.dispose()

    assert erased is None


def test_sweeping_twice_removes_nothing_the_second_time(
    postgres_database: dict[str, str],
) -> None:
    """Idempotence, so a sweep that is retried or run twice by a duplicated scheduler
    is not an event."""
    seed_assessment(postgres_database["owner_url"], observed_days_ago=200)

    engine = engine_for(postgres_database)
    try:
        with engine.begin() as connection:
            first = sweep_retention(connection)
        with engine.begin() as connection:
            second = sweep_retention(connection)
    finally:
        engine.dispose()

    assert first.total > 0
    assert second.total == 0


def test_the_retention_role_cannot_touch_the_audit_trail(
    postgres_database: dict[str, str],
) -> None:
    """Asserted against the database rather than only against the schedule.

    The schedule says audit is never swept, but a schedule is a statement of intent. The
    grant is what actually stops a future sweep -- or a mistake -- from reaching a record
    whose rows are chained by hash and cannot lose one without breaking every check after
    it.
    """
    engine = engine_for(postgres_database)
    try:
        with pytest.raises(Exception) as refused:
            with engine.begin() as connection:
                connection.execute(text("SELECT set_config('app.retention_sweep', 'on', true)"))
                connection.execute(text("DELETE FROM audit_events"))
    finally:
        engine.dispose()

    assert "permission denied" in str(refused.value).lower()


def test_the_retention_role_cannot_alter_a_score(postgres_database: dict[str, str]) -> None:
    """It may record that evidence is gone and nothing else.

    A role that could rewrite a band or a digest while holding a licence to delete the
    evidence for it could change an institution's result and remove the means of
    noticing. The column-level grant is what prevents that.
    """
    seed_assessment(postgres_database["owner_url"], observed_days_ago=200)

    engine = engine_for(postgres_database)
    try:
        with pytest.raises(Exception) as refused:
            with engine.begin() as connection:
                connection.execute(text("SELECT set_config('app.retention_sweep', 'on', true)"))
                connection.execute(text("UPDATE score_snapshots SET band = 'resilient'"))
    finally:
        engine.dispose()

    assert "permission denied" in str(refused.value).lower()


def test_evidence_cannot_be_deleted_without_declaring_a_sweep(
    postgres_database: dict[str, str],
) -> None:
    """The append-only trigger's single exception has to be asked for.

    Holding the grant is not enough. A stray DELETE somewhere in the codebase -- or a
    grant somebody widens later -- still fails, because removal has to be deliberate as
    well as permitted.
    """
    seed_assessment(postgres_database["owner_url"], observed_days_ago=200)

    engine = engine_for(postgres_database)
    try:
        with pytest.raises(Exception) as refused:
            with engine.begin() as connection:
                connection.execute(text("DELETE FROM normalized_observations"))
    finally:
        engine.dispose()

    assert "append-only" in str(refused.value).lower()


def test_a_run_is_recorded_even_when_it_removes_nothing(
    postgres_database: dict[str, str],
) -> None:
    """ "The job ran and found nothing" and "the job did not run" are different facts,
    and only one of them needs investigating."""
    engine = engine_for(postgres_database)
    try:
        with engine.begin() as connection:
            result = sweep_retention(connection)
            record_run(connection, result)
        with engine.begin() as connection:
            row = connection.execute(
                text("SELECT removed, error FROM retention_runs ORDER BY started_at DESC LIMIT 1")
            ).one()
    finally:
        engine.dispose()

    assert row[1] is None
    assert "_snapshots_marked" in row[0]


def test_what_was_removed_is_counted_not_listed(postgres_database: dict[str, str]) -> None:
    """A permanent list of erased identifiers would defeat the erasure."""
    seed_assessment(postgres_database["owner_url"], observed_days_ago=200)

    engine = engine_for(postgres_database)
    try:
        with engine.begin() as connection:
            result = sweep_retention(connection)
            record_run(connection, result)
        with engine.begin() as connection:
            removed = connection.execute(
                text("SELECT removed FROM retention_runs ORDER BY started_at DESC LIMIT 1")
            ).scalar_one()
    finally:
        engine.dispose()

    assert all(isinstance(value, int) for value in removed.values())


@pytest.mark.parametrize("entry", SWEPT_TABLES, ids=lambda entry: entry.table)
def test_a_swept_table_has_a_period_and_a_column(entry: object) -> None:
    """Both, or the sweep would delete everything or nothing."""
    assert getattr(entry, "period", None) is not None
    assert getattr(entry, "age_column", None)


def test_a_run_that_never_produced_evidence_is_not_claimed_to_have_lost_it(
    postgres_database: dict[str, str],
) -> None:
    """Found by running the sweep against a real database rather than a seeded one.

    The first version asked "which snapshots have no observations?", so that evidence
    removed by any route would be marked. It immediately stamped two completed
    assessments that had never produced observations at all -- and a report saying "the
    evidence was removed under retention" about a run that never had any is a worse lie
    than the silence it replaced.
    """
    organization_id, assessment_id = seed_assessment(
        postgres_database["owner_url"], observed_days_ago=200
    )
    del organization_id
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        # A completed, scored assessment with no evidence -- exactly what the demo seed
        # produces, and what a run that failed before normalizing leaves behind.
        # Declared even here: the append-only trigger refuses removal otherwise, which
        # is the guard working rather than an inconvenience to route around.
        owner.execute("SELECT set_config('app.retention_sweep', 'on', false)")
        owner.execute(
            "DELETE FROM normalized_observations WHERE assessment_id = %s", (str(assessment_id),)
        )

    engine = engine_for(postgres_database)
    try:
        with engine.begin() as connection:
            result = sweep_retention(connection)
        with engine.begin() as connection:
            erased = connection.execute(
                text("SELECT evidence_erased_at FROM score_snapshots WHERE assessment_id = :id"),
                {"id": assessment_id},
            ).scalar_one()
    finally:
        engine.dispose()

    assert erased is None
    assert result.snapshots_marked == 0
