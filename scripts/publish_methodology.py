"""Register the policy catalog in the database.

    python scripts/publish_methodology.py

Until a version is registered here, no assessment can be created at all: every
assessment, evaluation, finding and score snapshot carries a foreign key to the
methodology version that produced it, so that a report can always be traced back to
exactly the policy it was scored against.

Publishing is deliberately not a migration. A migration would freeze one digest into
the schema history, and the catalog in `packages/policy/` changes on its own schedule.
It is also deliberately append-only in effect: re-publishing a version whose digest has
changed is refused, because the existing rows pointing at that version were scored
against the old policy and silently redefining it would make every past report a lie.
"""

from __future__ import annotations

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


def main() -> int:
    from sqlalchemy import create_engine, text

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
