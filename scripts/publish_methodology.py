"""Register the policy catalog in the database.

    python scripts/publish_methodology.py
    python scripts/publish_methodology.py --withdraw 1.1.0

Until a version is registered here, no assessment can be created at all: every
assessment, evaluation, finding and score snapshot carries a foreign key to the
methodology version that produced it, so that a report can always be traced back to
exactly the policy it was scored against.

Publishing is deliberately not a migration. A migration would freeze one digest into
the schema history, and the catalog in `packages/policy/` changes on its own schedule.
It is also deliberately append-only in effect: re-publishing a version whose digest has
changed is refused, because the existing rows pointing at that version were scored
against the old policy and silently redefining it would make every past report a lie.

`--withdraw` exists for the one case that refusal handles badly: a version registered
while it was still being drafted, before anything was ever scored against it. It removes
the registration only when **nothing anywhere references it**, and it discovers what
"anywhere" means by reading the foreign keys rather than from a list somebody maintains.
A hardcoded list is how this becomes a data-loss tool the first time a table is added.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "services" / "worker" / "src"))

from siembiot_worker.policy.catalog import load_catalog  # noqa: E402


def database_url() -> str:
    url = os.environ.get("SIEMBIOT_DATABASE_URL")
    if not url:
        raise SystemExit("SIEMBIOT_DATABASE_URL is required (the owner role, not the app role)")
    return url.replace("postgresql://", "postgresql+psycopg://")


#: Every column that points at `methodology_versions`, read from the catalog rather than
#: listed. Discovering them means a table added later is covered without anybody
#: remembering to come back here -- and being wrong in the direction of "we did not know
#: about that reference" is how a withdrawal silently orphans somebody's stored score.
_REFERENCING_COLUMNS = """
    SELECT source.relname AS table_name, attribute.attname AS column_name
    FROM pg_constraint AS constraint_
    JOIN pg_class AS source ON source.oid = constraint_.conrelid
    JOIN pg_class AS target ON target.oid = constraint_.confrelid
    JOIN pg_attribute AS attribute
      ON attribute.attrelid = constraint_.conrelid
     AND attribute.attnum = constraint_.conkey[1]
    WHERE constraint_.contype = 'f' AND target.relname = 'methodology_versions'
"""


def withdraw(version: str) -> int:
    """Remove a registration nothing has ever used.

    Refuses on the first reference found, and names it. The alternative -- deleting and
    letting the foreign keys complain -- would work, but the operator would be reading a
    constraint violation instead of a sentence telling them which report they were about
    to detach from the policy that produced it.
    """
    from sqlalchemy import create_engine, text

    engine = create_engine(database_url())
    try:
        with engine.begin() as connection:
            digest = connection.execute(
                text("SELECT policy_digest FROM methodology_versions WHERE version = :version"),
                {"version": version},
            ).scalar_one_or_none()
            if digest is None:
                print(f"methodology {version} is not published; nothing to withdraw")
                return 0

            references = connection.execute(text(_REFERENCING_COLUMNS)).all()
            for table_name, column_name in references:
                count = connection.execute(
                    text(f"SELECT count(*) FROM {table_name} WHERE {column_name} = :version"),  # noqa: S608
                    {"version": version},
                ).scalar_one()
                if count:
                    print(
                        f"refusing to withdraw {version}: {count} row(s) in {table_name} "
                        f"reference it. Those were scored against this policy, and "
                        f"removing the version they name would leave them describing "
                        f"nothing. Bump the methodology version instead.",
                        file=sys.stderr,
                    )
                    return 1

            connection.execute(
                text("DELETE FROM methodology_versions WHERE version = :version"),
                {"version": version},
            )
        print(
            f"withdrew methodology {version} ({digest[:12]}…); "
            f"checked {len(references)} referencing column(s), all empty"
        )
        return 0
    finally:
        engine.dispose()


def main() -> int:
    from sqlalchemy import create_engine, text

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--withdraw",
        metavar="VERSION",
        help="remove a registration that nothing references (a version drafted, not released)",
    )
    arguments = parser.parse_args()
    if arguments.withdraw:
        return withdraw(arguments.withdraw)

    catalog = load_catalog()
    version = catalog.methodology.version
    engine = create_engine(database_url())
    try:
        with engine.begin() as connection:
            existing = connection.execute(
                text("SELECT policy_digest FROM methodology_versions WHERE version = :version"),
                {"version": version},
            ).scalar_one_or_none()

            if existing == catalog.digest:
                print(f"methodology {version} already published ({catalog.digest[:12]}…)")
                return 0
            if existing is not None:
                print(
                    f"refusing to republish {version}: the catalog digest is now "
                    f"{catalog.digest[:12]}… but {existing[:12]}… is already published.\n"
                    "Assessments already scored against the published digest would be "
                    "silently reattributed. Bump the methodology version instead.",
                    file=sys.stderr,
                )
                return 1

            connection.execute(
                text(
                    """
                    INSERT INTO methodology_versions (version, policy_digest, notice)
                    VALUES (:version, :digest, :notice)
                    """
                ),
                {
                    "version": version,
                    "digest": catalog.digest,
                    "notice": catalog.methodology.notice,
                },
            )
        print(f"published methodology {version} ({catalog.digest[:12]}…)")
        return 0
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
