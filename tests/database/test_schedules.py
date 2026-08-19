"""What the scheduler will and will not start.

The whole decision lives in `app_due_schedules`, so this is where it is checked. Each
exclusion exists because of a specific way an unattended run could be wrong: at an hour
somebody asked us to avoid, against a domain nobody currently claims control of, or on
top of a run that has not finished.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import psycopg
import pytest

METHODOLOGY = "1.0.0"
DIGEST = "d" * 64


def seed(owner_url: str, **schedule: object) -> dict[str, UUID]:
    organization_id, user_id, domain_id = uuid4(), uuid4(), uuid4()
    fields = {
        "cadence": "daily",
        "mode": "passive_observation",
        "next_run_at": datetime.now(UTC) - timedelta(minutes=5),
        "quiet_hours_start": None,
        "quiet_hours_end": None,
        "timezone": "Europe/Bucharest",
        "ownership_state": "verified",
        **schedule,
    }
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Schedule user')",
            (str(user_id), str(user_id), f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Tenant', %s, %s)",
            (str(organization_id), f"sc-{organization_id.hex[:12]}", str(user_id)),
        )
        owner.execute(
            "INSERT INTO memberships (organization_id, user_id, role, status) "
            "VALUES (%s, %s, 'organization_owner', 'active')",
            (str(organization_id), str(user_id)),
        )
        owner.execute(
            "INSERT INTO methodology_versions (version, policy_digest, notice) "
            "VALUES (%s, %s, 'test') ON CONFLICT (version) DO NOTHING",
            (METHODOLOGY, DIGEST),
        )
        owner.execute(
            "INSERT INTO domains (id, organization_id, canonical_name, unicode_display, "
            "registrable_domain, ownership_state, created_by_user_id) "
            "VALUES (%s, %s, 'sched.test', 'sched.test', 'sched.test', %s, %s)",
            (str(domain_id), str(organization_id), fields["ownership_state"], str(user_id)),
        )
        owner.execute(
            "INSERT INTO assessment_schedules (organization_id, domain_id, cadence, mode, "
            "next_run_at, quiet_hours_start, quiet_hours_end, timezone, created_by_user_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                str(organization_id),
                str(domain_id),
                fields["cadence"],
                fields["mode"],
                fields["next_run_at"],
                fields["quiet_hours_start"],
                fields["quiet_hours_end"],
                fields["timezone"],
                str(user_id),
            ),
        )
    return {"organization_id": organization_id, "user_id": user_id, "domain_id": domain_id}


def due_domain_ids(worker_url: str) -> set[str]:
    with psycopg.connect(worker_url) as worker:
        return {
            str(row[0]) for row in worker.execute("SELECT domain_id FROM app_due_schedules(500)")
        }


# -- what does start ---------------------------------------------------------


def test_a_due_schedule_is_offered(postgres_database: dict[str, str]) -> None:
    fixture = seed(postgres_database["owner_url"])
    assert str(fixture["domain_id"]) in due_domain_ids(postgres_database["worker_url"])


def test_a_schedule_that_is_not_due_yet_is_not_offered(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed(
        postgres_database["owner_url"], next_run_at=datetime.now(UTC) + timedelta(hours=6)
    )
    assert str(fixture["domain_id"]) not in due_domain_ids(postgres_database["worker_url"])


def test_switching_a_schedule_off_stops_it(postgres_database: dict[str, str]) -> None:
    """'off' is an explicit decision and must be honoured, not treated as unconfigured."""
    fixture = seed(postgres_database["owner_url"], cadence="off", next_run_at=None)
    assert str(fixture["domain_id"]) not in due_domain_ids(postgres_database["worker_url"])


# -- quiet hours -------------------------------------------------------------


def test_a_schedule_inside_quiet_hours_waits(postgres_database: dict[str, str]) -> None:
    """A run costs the target real queries. Small at midday is not small at 03:00."""
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        row = owner.execute(
            "SELECT extract(hour FROM now() AT TIME ZONE 'Europe/Bucharest')::int"
        ).fetchone()
    assert row is not None
    current = int(row[0])
    # A window that certainly contains the present hour.
    fixture = seed(
        postgres_database["owner_url"],
        quiet_hours_start=current,
        quiet_hours_end=(current + 2) % 24,
    )
    assert str(fixture["domain_id"]) not in due_domain_ids(postgres_database["worker_url"])


def test_a_schedule_outside_quiet_hours_runs(postgres_database: dict[str, str]) -> None:
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        row = owner.execute(
            "SELECT extract(hour FROM now() AT TIME ZONE 'Europe/Bucharest')::int"
        ).fetchone()
    assert row is not None
    current = int(row[0])
    fixture = seed(
        postgres_database["owner_url"],
        quiet_hours_start=(current + 2) % 24,
        quiet_hours_end=(current + 4) % 24,
    )
    assert str(fixture["domain_id"]) in due_domain_ids(postgres_database["worker_url"])


def test_an_unknown_timezone_does_not_stop_every_other_tenant(
    postgres_database: dict[str, str],
) -> None:
    """A raise inside the sweep's WHERE clause would take the whole pass down.

    One organization's mistyped timezone must not stop scheduling for everybody else,
    so the quiet-hours check falls back to 'not quiet' rather than propagating.
    """
    fixture = seed(
        postgres_database["owner_url"],
        timezone="Not/AReal_Zone",
        quiet_hours_start=0,
        quiet_hours_end=23,
    )
    healthy = seed(postgres_database["owner_url"])

    due = due_domain_ids(postgres_database["worker_url"])
    assert str(healthy["domain_id"]) in due
    assert str(fixture["domain_id"]) in due


def test_equal_quiet_bounds_are_an_empty_window_not_a_silent_day(
    postgres_database: dict[str, str],
) -> None:
    """Reading 08:00-08:00 as twenty-four hours would let one mistyped field stop a
    domain being assessed ever again, with nothing reporting that it had."""
    fixture = seed(postgres_database["owner_url"], quiet_hours_start=8, quiet_hours_end=8)
    assert str(fixture["domain_id"]) in due_domain_ids(postgres_database["worker_url"])


# -- what an unattended run must not do --------------------------------------


def test_an_authorized_schedule_stops_when_control_is_no_longer_proven(
    postgres_database: dict[str, str],
) -> None:
    """Re-verifying is a person's job. Continuing on a timer would mean assessing
    something nobody currently claims."""
    fixture = seed(
        postgres_database["owner_url"],
        mode="authorized_assessment",
        ownership_state="reverification_required",
    )
    assert str(fixture["domain_id"]) not in due_domain_ids(postgres_database["worker_url"])


def test_passive_observation_continues_without_proven_control(
    postgres_database: dict[str, str],
) -> None:
    """It never needed proof of control, so losing it changes nothing about what is
    lawful to read."""
    fixture = seed(
        postgres_database["owner_url"],
        mode="passive_observation",
        ownership_state="reverification_required",
    )
    assert str(fixture["domain_id"]) in due_domain_ids(postgres_database["worker_url"])


def test_a_run_already_in_flight_stops_another_being_stacked(
    postgres_database: dict[str, str],
) -> None:
    """Two concurrent runs would compete for the same evidence rows."""
    fixture = seed(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        owner.execute(
            "INSERT INTO assessments (id, organization_id, domain_id, methodology_version, state) "
            "VALUES (%s, %s, %s, %s, 'collecting')",
            (
                str(uuid4()),
                str(fixture["organization_id"]),
                str(fixture["domain_id"]),
                METHODOLOGY,
            ),
        )
    assert str(fixture["domain_id"]) not in due_domain_ids(postgres_database["worker_url"])


def test_a_settled_run_does_not_block_the_next_one(postgres_database: dict[str, str]) -> None:
    """The exclusion is about work in flight, not about history."""
    fixture = seed(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        owner.execute(
            "INSERT INTO assessments (id, organization_id, domain_id, methodology_version, "
            "state, completed_at) VALUES (%s, %s, %s, %s, 'completed', now())",
            (
                str(uuid4()),
                str(fixture["organization_id"]),
                str(fixture["domain_id"]),
                METHODOLOGY,
            ),
        )
    assert str(fixture["domain_id"]) in due_domain_ids(postgres_database["worker_url"])


# -- schema guarantees -------------------------------------------------------


def test_a_domain_cannot_hold_two_schedules(postgres_database: dict[str, str]) -> None:
    """Two would mean two answers to 'when next', and whichever was read first wins."""
    fixture = seed(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        with pytest.raises(psycopg.errors.UniqueViolation):
            owner.execute(
                "INSERT INTO assessment_schedules (organization_id, domain_id, cadence, "
                "next_run_at, created_by_user_id) VALUES (%s, %s, 'weekly', now(), %s)",
                (
                    str(fixture["organization_id"]),
                    str(fixture["domain_id"]),
                    str(fixture["user_id"]),
                ),
            )


def test_a_cadence_without_a_next_run_is_refused(postgres_database: dict[str, str]) -> None:
    """It would be stored, displayed as active, and never fire."""
    fixture = seed(postgres_database["owner_url"], cadence="off", next_run_at=None)
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        with pytest.raises(psycopg.errors.CheckViolation):
            owner.execute(
                "UPDATE assessment_schedules SET cadence = 'weekly' WHERE domain_id = %s",
                (str(fixture["domain_id"]),),
            )


def test_the_scheduler_view_returns_scheduling_metadata_only(
    postgres_database: dict[str, str],
) -> None:
    """The second cross-tenant read in the system, held to the same shape as the first."""
    seed(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["worker_url"]) as worker:
        cursor = worker.execute("SELECT * FROM app_due_schedules(1)")
        assert cursor.description is not None
        assert [column.name for column in cursor.description] == [
            "schedule_id",
            "organization_id",
            "domain_id",
            "host",
            "mode",
        ]


def test_the_api_role_cannot_read_schedules_across_tenants(
    postgres_database: dict[str, str],
) -> None:
    seed(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["app_url"], autocommit=True) as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("SELECT * FROM app_due_schedules(500)")


# -- verification expiry -----------------------------------------------------


def test_a_verification_past_its_date_expires(postgres_database: dict[str, str]) -> None:
    """A proof that never expires is not a proof of anything current."""
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "worker" / "src"))
    from siembiot_worker.scheduling import expire_stale_verifications
    from sqlalchemy import create_engine, text

    fixture = seed(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        owner.execute(
            "UPDATE domains SET reverification_due_at = now() - interval '1 day' WHERE id = %s",
            (str(fixture["domain_id"]),),
        )

    engine = create_engine(
        postgres_database["owner_url"].replace("postgresql://", "postgresql+psycopg://")
    )
    try:
        with engine.begin() as connection:
            moved = expire_stale_verifications(connection)
            assert moved >= 1
            state = connection.execute(
                text("SELECT ownership_state FROM domains WHERE id = :id"),
                {"id": fixture["domain_id"]},
            ).scalar_one()
    finally:
        engine.dispose()
    assert state == "reverification_required"


def test_expiry_does_not_overwrite_a_state_somebody_chose(
    postgres_database: dict[str, str],
) -> None:
    """A revoked domain is in a state a person put it in; a timer must not relabel it."""
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "worker" / "src"))
    from siembiot_worker.scheduling import expire_stale_verifications
    from sqlalchemy import create_engine, text

    fixture = seed(postgres_database["owner_url"], ownership_state="revoked")
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        owner.execute(
            "UPDATE domains SET reverification_due_at = now() - interval '1 day' WHERE id = %s",
            (str(fixture["domain_id"]),),
        )

    engine = create_engine(
        postgres_database["owner_url"].replace("postgresql://", "postgresql+psycopg://")
    )
    try:
        with engine.begin() as connection:
            expire_stale_verifications(connection)
            state = connection.execute(
                text("SELECT ownership_state FROM domains WHERE id = :id"),
                {"id": fixture["domain_id"]},
            ).scalar_one()
    finally:
        engine.dispose()
    assert state == "revoked"


# -- what the worker may read ------------------------------------------------


def _selectors_seen_by_worker(
    worker_url: str, organization_id: UUID, domain_id: UUID
) -> tuple[str, ...]:
    """Read the declaration the way the assessment task does: as the worker role, with
    the connection bound to one tenant."""
    with psycopg.connect(worker_url) as worker:
        worker.execute(
            "SELECT set_config('app.organization_id', %s, false)", (str(organization_id),)
        )
        row = worker.execute(
            "SELECT declared_dkim_selectors FROM domains WHERE id = %s", (str(domain_id),)
        ).fetchone()
    return tuple(row[0]) if row else ()


def test_the_worker_can_read_a_declaration_made_for_its_tenant(
    postgres_database: dict[str, str],
) -> None:
    """The gap that made the DKIM form do nothing.

    Selectors were stored on the domain and the worker could not see the row: `domains`
    carried only the tenant policy, which requires an active membership, and the worker
    is a service role with none. So a declaration was written, stored, and silently
    ignored -- the run reported `not_applicable` exactly as though nothing had been
    declared, which is indistinguishable from the ordinary case and therefore invisible.

    Nothing caught it because the API was tested as a member and the collector was handed
    selectors directly. This drives the path the worker actually takes.
    """
    fixture = seed(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        owner.execute(
            "UPDATE domains SET declared_dkim_selectors = %s WHERE id = %s",
            (["s1", "google"], str(fixture["domain_id"])),
        )

    seen = _selectors_seen_by_worker(
        postgres_database["worker_url"], fixture["organization_id"], fixture["domain_id"]
    )
    assert seen == ("s1", "google")


def test_the_worker_cannot_read_another_tenants_domain(
    postgres_database: dict[str, str],
) -> None:
    """The policy grants the worker its own tenant and nothing else. Isolation does not
    rest on the task passing the right identifier: a connection bound elsewhere finds no
    rows at all."""
    fixture = seed(postgres_database["owner_url"])
    other = seed(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        owner.execute(
            "UPDATE domains SET declared_dkim_selectors = %s WHERE id = %s",
            (["s1"], str(fixture["domain_id"])),
        )

    seen = _selectors_seen_by_worker(
        postgres_database["worker_url"], other["organization_id"], fixture["domain_id"]
    )
    assert seen == (), "the worker read a domain belonging to another organization"
