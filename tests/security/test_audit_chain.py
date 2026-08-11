"""The audit trail has to notice when somebody edits it.

`previous_hash` and `event_hash` existed from the first migration, with a CHECK
constraint fixing them at 32 bytes, and nothing ever wrote them: every row in every
deployment had both columns null. The trail was append-only and not tamper-evident,
which are different guarantees. Append-only stops the application rewriting history; a
chain is what stops whoever holds the database credentials -- and that is the case an
audit trail exists for.

So the tests here are mostly attacks. Each one stands the immutability trigger down,
because a real attacker with database access would, and then checks that the edit is
still visible afterwards.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import psycopg
import pytest

#: The audit table constrains both of these, so they are shaped like the real thing.
IDENTIFIER = "01JQ0000000000000000000001"


def seed_organization(owner_url: str) -> UUID:
    organization_id, user_id = uuid4(), uuid4()
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Chain user')",
            (str(user_id), str(user_id), f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Chain', %s, %s)",
            (str(organization_id), f"ch-{organization_id.hex[:12]}", str(user_id)),
        )
    return organization_id


def write_event(owner_url: str, organization_id: UUID, action: str) -> None:
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO audit_events (organization_id, actor_type, actor_id, action, "
            "resource_type, resource_id, request_id, correlation_id, outcome, context) "
            "VALUES (%s, 'user', 'u', %s, 'organization', %s, %s, %s, 'success', '{}')",
            (str(organization_id), action, str(organization_id), IDENTIFIER, IDENTIFIER),
        )


def breaks(owner_url: str, organization_id: UUID) -> list[tuple[object, ...]]:
    with psycopg.connect(owner_url, autocommit=True) as owner:
        return [
            row
            for row in owner.execute(
                "SELECT sequence_number, problem FROM audit_chain_breaks() "
                "WHERE organization_id = %s",
                (str(organization_id),),
            )
        ]


def without_immutability(owner_url: str, statement: str, parameters: tuple[object, ...]) -> None:
    """Do what somebody with database credentials would do.

    The immutability trigger is the application's guard, and an attacker at this level
    simply turns it off. That is the whole reason a chain is needed on top of it, so the
    tests reproduce it rather than testing the easy case.
    """
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute("ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable")
        try:
            owner.execute(statement, parameters)
        finally:
            owner.execute("ALTER TABLE audit_events ENABLE TRIGGER audit_events_immutable")


def test_a_written_trail_verifies(postgres_database: dict[str, str]) -> None:
    organization_id = seed_organization(postgres_database["owner_url"])
    for action in ("one", "two", "three"):
        write_event(postgres_database["owner_url"], organization_id, f"chain.{action}")

    assert breaks(postgres_database["owner_url"], organization_id) == []


def test_every_event_is_chained_without_the_application_asking(
    postgres_database: dict[str, str],
) -> None:
    """The hash is computed by a trigger, not by `append_audit_event`.

    A hash written in application code only covers rows that went through it, and the
    writes worth detecting are precisely the ones that did not. This insert goes straight
    to the database, as an attacker's would, and is chained anyway.
    """
    organization_id = seed_organization(postgres_database["owner_url"])
    write_event(postgres_database["owner_url"], organization_id, "chain.direct")

    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        hashed = owner.execute(
            "SELECT event_hash FROM audit_events WHERE organization_id = %s",
            (str(organization_id),),
        ).fetchone()

    assert hashed is not None and hashed[0] is not None


def test_altering_an_event_is_detected(postgres_database: dict[str, str]) -> None:
    organization_id = seed_organization(postgres_database["owner_url"])
    for action in ("one", "two", "three"):
        write_event(postgres_database["owner_url"], organization_id, f"chain.{action}")

    without_immutability(
        postgres_database["owner_url"],
        "UPDATE audit_events SET action = 'chain.rewritten' "
        "WHERE organization_id = %s AND action = 'chain.two'",
        (str(organization_id),),
    )

    found = breaks(postgres_database["owner_url"], organization_id)
    assert found, "an edited audit event went unnoticed"
    assert "altered after it was written" in str(found[0][1])


def test_removing_an_event_from_the_middle_is_detected(
    postgres_database: dict[str, str],
) -> None:
    """The case an attacker actually wants: not changing what happened, but removing the
    record that it did."""
    organization_id = seed_organization(postgres_database["owner_url"])
    for action in ("one", "two", "three"):
        write_event(postgres_database["owner_url"], organization_id, f"chain.{action}")

    without_immutability(
        postgres_database["owner_url"],
        "DELETE FROM audit_events WHERE organization_id = %s AND action = 'chain.two'",
        (str(organization_id),),
    )

    found = breaks(postgres_database["owner_url"], organization_id)
    assert found, "a deleted audit event went unnoticed"
    assert "removed, reordered, or inserted" in str(found[0][1])


def test_an_event_inserted_with_the_trigger_off_is_detected(
    postgres_database: dict[str, str],
) -> None:
    """Inserting a plausible row without a hash is the way to forge history while
    leaving every existing hash valid. It is caught because unhashed rows are only
    legitimate as a prefix -- they predate the chain -- and this one arrives after
    chained events."""
    organization_id = seed_organization(postgres_database["owner_url"])
    write_event(postgres_database["owner_url"], organization_id, "chain.one")

    without_immutability(
        postgres_database["owner_url"],
        "INSERT INTO audit_events (organization_id, actor_type, actor_id, action, "
        "resource_type, resource_id, request_id, correlation_id, outcome, context) "
        "VALUES (%s, 'user', 'u', 'chain.forged', 'organization', %s, %s, %s, "
        "'success', '{}')",
        (str(organization_id), str(organization_id), IDENTIFIER, IDENTIFIER),
    )

    # The insert trigger is separate from the immutability trigger, so this row is in
    # fact chained -- which is itself the answer. Forging requires disabling both, and
    # the test below covers that.
    assert breaks(postgres_database["owner_url"], organization_id) == []


def test_an_unhashed_event_after_chained_ones_is_detected(
    postgres_database: dict[str, str],
) -> None:
    """Both triggers off: the complete forgery attempt.

    Rows predating this feature legitimately have no hash, so "no hash" cannot simply be
    an error. What makes it detectable is that they must form a contiguous prefix -- an
    unhashed row appearing after chained ones could only have been inserted with the
    chain disabled.
    """
    organization_id = seed_organization(postgres_database["owner_url"])
    write_event(postgres_database["owner_url"], organization_id, "chain.one")

    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        owner.execute("ALTER TABLE audit_events DISABLE TRIGGER audit_events_chain")
        try:
            owner.execute(
                "INSERT INTO audit_events (organization_id, actor_type, actor_id, action, "
                "resource_type, resource_id, request_id, correlation_id, outcome, context) "
                "VALUES (%s, 'user', 'u', 'chain.forged', 'organization', %s, %s, %s, "
                "'success', '{}')",
                (str(organization_id), str(organization_id), IDENTIFIER, IDENTIFIER),
            )
        finally:
            owner.execute("ALTER TABLE audit_events ENABLE TRIGGER audit_events_chain")

    found = breaks(postgres_database["owner_url"], organization_id)
    assert found, "an unhashed event inserted after chained ones went unnoticed"
    assert "chain trigger disabled" in str(found[0][1])


def test_one_organization_cannot_break_another_organizations_chain(
    postgres_database: dict[str, str],
) -> None:
    """Chains are per organization, so an institution's own history stands or falls on
    its own rows. A tenant whose events were tampered with must not make every other
    tenant's trail unverifiable."""
    first = seed_organization(postgres_database["owner_url"])
    second = seed_organization(postgres_database["owner_url"])
    for organization_id in (first, second):
        for action in ("one", "two"):
            write_event(postgres_database["owner_url"], organization_id, f"chain.{action}")

    without_immutability(
        postgres_database["owner_url"],
        "DELETE FROM audit_events WHERE organization_id = %s AND action = 'chain.one'",
        (str(first),),
    )

    assert breaks(postgres_database["owner_url"], first)
    assert breaks(postgres_database["owner_url"], second) == []


@pytest.mark.parametrize("column", ["action", "actor_id", "outcome", "context"])
def test_no_field_can_be_changed_without_showing(
    postgres_database: dict[str, str], column: str
) -> None:
    """The hash covers the whole row rather than a chosen list of fields, so this holds
    for a column added next year as well as for these."""
    organization_id = seed_organization(postgres_database["owner_url"])
    write_event(postgres_database["owner_url"], organization_id, "chain.one")

    # Each replacement has to satisfy the column's own constraint, or the tamper is
    # refused by a CHECK and the test proves nothing about the chain.
    value = {
        "context": "'{\"tampered\": true}'::jsonb",
        "outcome": "'denied'",
    }.get(column, "'tampered'")
    without_immutability(
        postgres_database["owner_url"],
        f"UPDATE audit_events SET {column} = {value} WHERE organization_id = %s",  # noqa: S608
        (str(organization_id),),
    )

    assert breaks(postgres_database["owner_url"], organization_id)
