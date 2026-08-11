"""Remove one organization and everything held about it.

    python scripts/erase_organization.py --organization <uuid>            # shows the plan
    python scripts/erase_organization.py --organization <uuid> --confirm  # performs it

Retention ages data out on a timer. This is the other obligation: an institution asks to
be removed, and everything about it goes -- its evidence, its scores, its findings, its
answers, its published profile, and the record of who did what inside it.

**Irreversible, and deliberately manual.** No scheduled job runs this and no API endpoint
exposes it. It connects as the owner rather than under a long-lived login of its own,
because the alternative is a credential sitting in a deployment that can delete any
institution's entire history, which is a worse thing to have than an operator typing a
command. Nothing is removed without `--confirm`.

**The tables are derived, never listed.** Every table carrying an `organization_id` is
found in the catalogue and included, and the deletion order comes from the foreign keys.
A list would silently stop covering whatever was added after somebody last edited it, and
an erasure that misses a table has not erased anything -- it has only made the omission
harder to notice.

**The audit trail goes with it, and leaves a mark.** Audit is chained per organization, so
removing one institution's events removes one whole chain and leaves every other chain
verifying exactly as before. What survives is a tombstone written into the platform's own
chain: that this organization existed, and was erased, on this date. Losing the record
that we ever held anything would be its own kind of dishonesty.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import defaultdict
from uuid import UUID

TENANT_COLUMN = "organization_id"

#: Tables whose rows are removed by following the organization's domains rather than an
#: `organization_id`. The published projection is keyed by domain name, because a public
#: page has no business carrying a tenant identifier.
PUBLISHED_TABLES = ("observatory.profiles",)

#: The removal is sanctioned in the same way retention is: the append-only triggers
#: refuse otherwise, and naming the reason at the point of deletion keeps the two
#: distinguishable.
ERASURE_SETTING = "app.tenant_erasure"


def database_url() -> str:
    url = os.environ.get("SIEMBIOT_DATABASE_URL")
    if not url:
        raise SystemExit("SIEMBIOT_DATABASE_URL is required (the owner role)")
    return url.replace("postgresql+psycopg://", "postgresql://")


def tenant_tables(connection: object) -> list[str]:
    """Every table carrying an organization_id, in an order safe to delete in.

    Ordered by the foreign keys between them: a table that references another is emptied
    first. Doing this by hand produces an order that is right on the day it is written
    and wrong after the next migration, and the failure is a constraint violation part
    way through an irreversible operation.
    """
    rows = connection.execute(  # type: ignore[attr-defined]
        """
        SELECT c.table_name
        FROM information_schema.columns c
        JOIN information_schema.tables t
          ON t.table_schema = c.table_schema AND t.table_name = c.table_name
        WHERE c.table_schema = 'public'
          AND c.column_name = %s
          AND t.table_type = 'BASE TABLE'
        """,
        (TENANT_COLUMN,),
    ).fetchall()
    tables = {name for (name,) in rows}

    edges = connection.execute(  # type: ignore[attr-defined]
        """
        SELECT source.relname, target.relname
        FROM pg_constraint k
        JOIN pg_class source ON source.oid = k.conrelid
        JOIN pg_class target ON target.oid = k.confrelid
        WHERE k.contype = 'f'
        """
    ).fetchall()

    # referenced -> those that reference it, restricted to the tables being emptied.
    dependents: dict[str, set[str]] = defaultdict(set)
    for referencing, referenced in edges:
        if referencing in tables and referenced in tables and referencing != referenced:
            dependents[referenced].add(referencing)

    ordered: list[str] = []
    remaining = set(tables)
    while remaining:
        # A table nothing left in the set references can go next.
        free = sorted(name for name in remaining if not (dependents[name] & remaining))
        if not free:
            # A cycle. Reported rather than guessed at, because the alternative is a
            # half-finished erasure.
            raise SystemExit(f"circular references between {sorted(remaining)}")
        ordered.extend(free)
        remaining -= set(free)
    return ordered


def plan(connection: object, organization_id: UUID) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in tenant_tables(connection):
        count = connection.execute(  # type: ignore[attr-defined]
            f"SELECT count(*) FROM {table} WHERE {TENANT_COLUMN} = %s",  # noqa: S608
            (str(organization_id),),
        ).fetchone()[0]
        if count:
            counts[table] = count

    published = connection.execute(  # type: ignore[attr-defined]
        """
        SELECT count(*) FROM observatory.profiles
        WHERE registrable_domain IN (
            SELECT registrable_domain FROM domains WHERE organization_id = %s
        )
        """,
        (str(organization_id),),
    ).fetchone()[0]
    if published:
        counts["observatory.profiles"] = published
    return counts


def erase(connection: object, organization_id: UUID, name: str) -> dict[str, int]:
    removed: dict[str, int] = {}

    connection.execute(f"SELECT set_config('{ERASURE_SETTING}', 'on', true)")  # type: ignore[attr-defined]

    # The published profile first, while the domains that identify it still exist.
    # Reversing these two would leave a public page about an institution that has been
    # erased from everywhere else, which is the worst possible order to fail in.
    published = connection.execute(  # type: ignore[attr-defined]
        """
        DELETE FROM observatory.profiles
        WHERE registrable_domain IN (
            SELECT registrable_domain FROM domains WHERE organization_id = %s
        )
        """,
        (str(organization_id),),
    ).rowcount
    if published:
        removed["observatory.profiles"] = published

    for table in tenant_tables(connection):
        count = connection.execute(  # type: ignore[attr-defined]
            f"DELETE FROM {table} WHERE {TENANT_COLUMN} = %s",  # noqa: S608
            (str(organization_id),),
        ).rowcount
        if count:
            removed[table] = count

    connection.execute(  # type: ignore[attr-defined]
        "DELETE FROM organizations WHERE id = %s", (str(organization_id),)
    )

    # The tombstone goes into the platform's own chain, which is separate from the one
    # just removed. Written after the deletion so it cannot be taken as evidence of an
    # erasure that then failed.
    connection.execute(  # type: ignore[attr-defined]
        """
        INSERT INTO audit_events (organization_id, actor_type, actor_id, action,
                                  resource_type, resource_id, request_id, correlation_id,
                                  outcome, context)
        VALUES (NULL, 'system', 'erase_organization', 'organization.erased',
                'organization', %s, %s, %s, 'success', %s::jsonb)
        """,
        (
            str(organization_id),
            _identifier(organization_id),
            _identifier(organization_id),
            _tombstone(name, removed),
        ),
    )
    return removed


def _identifier(organization_id: UUID) -> str:
    """A stable 26-character value in the shape the audit table requires."""
    return organization_id.hex[:26].upper().ljust(26, "0")


def _tombstone(name: str, removed: dict[str, int]) -> str:
    import json

    # The organization's name and how much was removed, never what it said. A tombstone
    # that quoted the erased data would be a copy of it under another name.
    return json.dumps(
        {"organization_name": name, "rows_removed": dict(sorted(removed.items()))},
        sort_keys=True,
    )


def remaining_references(connection: object, organization_id: UUID) -> dict[str, int]:
    """Anything still naming the organization after the deletion.

    Checked rather than assumed. An erasure that silently missed a table is worse than
    one that failed, because the institution is told it is gone.
    """
    left: dict[str, int] = {}
    for table in tenant_tables(connection):
        count = connection.execute(  # type: ignore[attr-defined]
            f"SELECT count(*) FROM {table} WHERE {TENANT_COLUMN} = %s",  # noqa: S608
            (str(organization_id),),
        ).fetchone()[0]
        if count:
            left[table] = count
    return left


def main() -> int:
    import psycopg

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--organization", required=True, type=UUID)
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="perform the erasure; without it, only the plan is printed",
    )
    arguments = parser.parse_args()

    with psycopg.connect(database_url()) as connection:
        with connection.cursor() as cursor:
            row = cursor.execute(
                "SELECT name FROM organizations WHERE id = %s", (str(arguments.organization),)
            ).fetchone()
            if row is None:
                print(f"no organization {arguments.organization}", file=sys.stderr)
                return 1
            name = row[0]

            counts = plan(cursor, arguments.organization)
            total = sum(counts.values())
            print(f"{name} ({arguments.organization})")
            for table, count in sorted(counts.items()):
                print(f"  {count:>7}  {table}")
            print(f"  {total:>7}  rows in total, across {len(counts)} tables")

            if not arguments.confirm:
                print("\nnothing removed. Re-run with --confirm to erase this organization.")
                return 0

            removed = erase(cursor, arguments.organization, name)
            left = remaining_references(cursor, arguments.organization)
            if left:
                connection.rollback()
                print(f"\nrolled back: rows still reference this organization: {left}")
                return 1

        connection.commit()

    print(f"\nerased {sum(removed.values())} rows. A tombstone records that it happened.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
