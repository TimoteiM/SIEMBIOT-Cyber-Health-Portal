"""The worker's database identity, and the one place it reads across tenants.

Migration 0009 grants the worker something no user has: the right to write inside an
organization without a membership. That is a real widening of the trust boundary, so
these tests attack it directly rather than reading the policies and believing them.

Two claims are load-bearing:

* the worker is still confined to one tenant per connection, exactly like a user;
* the cross-tenant scheduler function returns scheduling metadata and is unreachable
  from the API's role.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import psycopg
import pytest

METHODOLOGY = "1.0.0"
DIGEST = "b" * 64
TERMINAL_STATES = frozenset(
    {"completed", "partially_completed", "failed", "cancelled", "expired", "blocked_by_policy"}
)


def seed_tenant(owner_url: str, *, state: str = "queued") -> dict[str, str]:
    organization_id, user_id = str(uuid4()), str(uuid4())
    domain_id, assessment_id = str(uuid4()), str(uuid4())
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Seam user')",
            (user_id, user_id, f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Tenant', %s, %s)",
            (organization_id, f"seam-{organization_id[:12]}", user_id),
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
            "VALUES (%s, %s, %s, %s, %s, 'verified', %s)",
            (domain_id, organization_id, "seam.test", "seam.test", "seam.test", user_id),
        )
        # A terminal state must carry a completion time -- the schema refuses one
        # without it, so a settled row cannot be silently indistinguishable from a
        # stalled one.
        owner.execute(
            "INSERT INTO assessments (id, organization_id, domain_id, methodology_version, "
            "state, completed_at) VALUES (%s, %s, %s, %s, %s, %s)",
            (
                assessment_id,
                organization_id,
                domain_id,
                METHODOLOGY,
                state,
                datetime.now(UTC) if state in TERMINAL_STATES else None,
            ),
        )
    return {
        "organization_id": organization_id,
        "user_id": user_id,
        "domain_id": domain_id,
        "assessment_id": assessment_id,
    }


# -- tenant confinement ------------------------------------------------------


def test_the_worker_sees_nothing_without_a_tenant(postgres_database: dict[str, str]) -> None:
    """Connecting as the worker is not itself authority to read anything."""
    seed_tenant(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["worker_url"]) as worker:
        visible = worker.execute("SELECT count(*) FROM assessments").fetchone()
        assert visible is not None and visible[0] == 0


def test_the_worker_sees_only_the_tenant_it_was_given(postgres_database: dict[str, str]) -> None:
    mine = seed_tenant(postgres_database["owner_url"])
    seed_tenant(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["worker_url"]) as worker:
        worker.execute(
            "SELECT set_config('app.organization_id', %s, false)", (mine["organization_id"],)
        )
        rows = worker.execute("SELECT id FROM assessments").fetchall()
        assert [str(row[0]) for row in rows] == [mine["assessment_id"]]


def test_a_scoped_worker_still_cannot_read_another_tenants_domains(
    postgres_database: dict[str, str],
) -> None:
    """The narrowest form of the guarantee: scoping is not a hint, it is enforced."""
    mine = seed_tenant(postgres_database["owner_url"])
    theirs = seed_tenant(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["worker_url"]) as worker:
        worker.execute(
            "SELECT set_config('app.organization_id', %s, false)", (mine["organization_id"],)
        )
        found = worker.execute(
            "SELECT count(*) FROM domains WHERE id = %s", (theirs["domain_id"],)
        ).fetchone()
        assert found is not None and found[0] == 0


def test_the_worker_may_write_without_a_membership(postgres_database: dict[str, str]) -> None:
    """The point of the role. No human is acting, so no membership can be required."""
    mine = seed_tenant(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["worker_url"], autocommit=True) as worker:
        worker.execute(
            "SELECT set_config('app.organization_id', %s, false)", (mine["organization_id"],)
        )
        worker.execute(
            "INSERT INTO assessment_steps (organization_id, assessment_id, name, state) "
            "VALUES (%s, %s, 'plan', 'pending')",
            (mine["organization_id"], mine["assessment_id"]),
        )
        worker.execute(
            "UPDATE assessments SET state = 'collecting' WHERE id = %s", (mine["assessment_id"],)
        )
        state = worker.execute(
            "SELECT state FROM assessments WHERE id = %s", (mine["assessment_id"],)
        ).fetchone()
        assert state is not None and state[0] == "collecting"


def test_the_worker_cannot_write_into_another_tenant(postgres_database: dict[str, str]) -> None:
    """Writing is scoped by the same predicate as reading, not merely by convention."""
    mine = seed_tenant(postgres_database["owner_url"])
    theirs = seed_tenant(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["worker_url"], autocommit=True) as worker:
        worker.execute(
            "SELECT set_config('app.organization_id', %s, false)", (mine["organization_id"],)
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            worker.execute(
                "INSERT INTO assessment_steps (organization_id, assessment_id, name, state) "
                "VALUES (%s, %s, 'plan', 'pending')",
                (theirs["organization_id"], theirs["assessment_id"]),
            )


# -- the scheduler's cross-tenant read ---------------------------------------


def test_the_scheduler_sees_due_runs_across_tenants(postgres_database: dict[str, str]) -> None:
    first = seed_tenant(postgres_database["owner_url"])
    second = seed_tenant(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["worker_url"]) as worker:
        found = {
            str(row[0])
            for row in worker.execute("SELECT assessment_id FROM app_due_assessments(500)")
        }
    assert {first["assessment_id"], second["assessment_id"]} <= found


def test_the_scheduler_does_not_dispatch_unauthorized_or_settled_runs(
    postgres_database: dict[str, str],
) -> None:
    """A draft has not been authorized; a completed run has nothing left to do."""
    draft = seed_tenant(postgres_database["owner_url"], state="draft")
    done = seed_tenant(postgres_database["owner_url"], state="completed")
    with psycopg.connect(postgres_database["worker_url"]) as worker:
        found = {
            str(row[0])
            for row in worker.execute("SELECT assessment_id FROM app_due_assessments(500)")
        }
    assert draft["assessment_id"] not in found
    assert done["assessment_id"] not in found


def test_a_run_waiting_out_its_backoff_is_not_due(postgres_database: dict[str, str]) -> None:
    """Otherwise the scheduler re-enqueues it every sweep for nothing."""
    waiting = seed_tenant(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        owner.execute(
            "INSERT INTO assessment_steps (organization_id, assessment_id, name, state, "
            "next_attempt_at) VALUES (%s, %s, 'plan', 'pending', now() + interval '5 minutes')",
            (waiting["organization_id"], waiting["assessment_id"]),
        )
    with psycopg.connect(postgres_database["worker_url"]) as worker:
        found = {
            str(row[0])
            for row in worker.execute("SELECT assessment_id FROM app_due_assessments(500)")
        }
    assert waiting["assessment_id"] not in found


def test_a_run_somebody_is_already_carrying_out_is_not_due(
    postgres_database: dict[str, str],
) -> None:
    """A live lease makes a duplicate dispatch harmless, not free."""
    running = seed_tenant(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        owner.execute(
            "INSERT INTO assessment_steps (organization_id, assessment_id, name, state, "
            "lease_owner, lease_expires_at) VALUES (%s, %s, 'plan', 'running', %s, "
            "now() + interval '5 minutes')",
            (running["organization_id"], running["assessment_id"], uuid4()),
        )
    with psycopg.connect(postgres_database["worker_url"]) as worker:
        found = {
            str(row[0])
            for row in worker.execute("SELECT assessment_id FROM app_due_assessments(500)")
        }
    assert running["assessment_id"] not in found


def test_an_expired_lease_makes_a_run_due_again(postgres_database: dict[str, str]) -> None:
    """How a worker that died mid-run gets picked back up, with nobody intervening."""
    abandoned = seed_tenant(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        owner.execute(
            "INSERT INTO assessment_steps (organization_id, assessment_id, name, state, "
            "lease_owner, lease_expires_at) VALUES (%s, %s, 'plan', 'running', %s, "
            "now() - interval '1 minute')",
            (abandoned["organization_id"], abandoned["assessment_id"], uuid4()),
        )
    with psycopg.connect(postgres_database["worker_url"]) as worker:
        found = {
            str(row[0])
            for row in worker.execute("SELECT assessment_id FROM app_due_assessments(500)")
        }
    assert abandoned["assessment_id"] in found


def test_the_scheduler_returns_scheduling_metadata_only(postgres_database: dict[str, str]) -> None:
    """The function is the whole cross-tenant surface, so its shape is the boundary.

    If a column is ever added here, it becomes readable across every tenant. Evidence
    must never appear in this list.
    """
    seed_tenant(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["worker_url"]) as worker:
        cursor = worker.execute("SELECT * FROM app_due_assessments(1)")
        assert cursor.description is not None
        assert [column.name for column in cursor.description] == [
            "assessment_id",
            "organization_id",
            "domain_id",
            "host",
            "mode",
        ]


def test_the_api_role_cannot_read_across_tenants(postgres_database: dict[str, str]) -> None:
    """PostgreSQL grants EXECUTE to PUBLIC by default; migration 0009 revokes it.

    Without that revoke, a single SQL injection in the API would enumerate every
    organization's assessments and domain names through this function.
    """
    seed_tenant(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["app_url"], autocommit=True) as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("SELECT * FROM app_due_assessments(500)")


def test_asserting_worker_identity_without_the_role_grants_nothing(
    postgres_database: dict[str, str],
) -> None:
    """The reason this is a role and not a session flag.

    Whoever controls the API's connection can already set any session variable. If the
    worker's write permission were a GUC, that would be enough to write into any tenant.
    """
    mine = seed_tenant(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["app_url"], autocommit=True) as app:
        app.execute(
            "SELECT set_config('app.organization_id', %s, false)", (mine["organization_id"],)
        )
        granted = app.execute("SELECT app_is_worker_for(%s)", (mine["organization_id"],)).fetchone()
        assert granted is not None and granted[0] is False
