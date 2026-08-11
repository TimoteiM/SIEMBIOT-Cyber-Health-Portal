"""Back up the database, and prove the backup restores.

    python scripts/backup.py create
    python scripts/backup.py verify artifacts/backups/<name>
    python scripts/backup.py restore artifacts/backups/<name> --into siembiot_restored

This database holds the two things in the product that cannot be reconstructed:
append-only evidence, and the audit trail of who did what. Everything else -- the
policy catalog, the images, the schema -- exists in the repository and can be rebuilt.
Those two cannot, which makes this the last remaining single point of loss.

**A backup nobody has restored is not a backup, it is a file.** So `verify` is not
documentation: it restores into a throwaway database and checks that what came back is
what a working system needs, then throws it away. Running it is the only way to know.

Three things `pg_dump` does not carry, each of which would produce a restore that looks
successful and is not:

*Roles.* Dumps contain grants but not the roles they refer to. Restoring into a fresh
cluster leaves a database nobody can connect to, and the error arrives at the end of a
long restore rather than at the start.

*Passwords.* Deliberately excluded here with `--no-role-passwords`, so a backup file
contains no credential at all. The three passwords already come from the environment,
so a restore takes them from the same place rather than from an archive that then has
to be guarded like a secret.

*Whether it is still enforcing anything.* Row-level security, the FORCE flag on every
tenant table, and the triggers that make evidence append-only are all in the dump -- but
a restore that silently lost them would look identical from the outside. The manifest
records the counts so a restore can be checked rather than assumed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKUP_ROOT = ROOT / "artifacts" / "backups"

#: The container running PostgreSQL. A managed database would use its provider's
#: snapshots instead, and this script would only be the verification half.
DEFAULT_CONTAINER = "siembiot-prod-like-postgres-1"
DEFAULT_DATABASE = "siembiot"
OWNER = "siembiot_owner"

#: Tables whose contents cannot be recomputed from anything else. Counted into the
#: manifest and compared after a restore, because "the restore finished" and "the
#: evidence came back" are different claims.
IRREPLACEABLE_TABLES = (
    "audit_events",
    "normalized_observations",
    "check_evaluations",
    "score_snapshots",
    "findings",
    "finding_history",
    "assessments",
    "domains",
    "organizations",
    "users",
)


@dataclass(frozen=True)
class Manifest:
    """What must still be true after a restore.

    Recorded at backup time rather than derived at restore time: a check that computes
    its own expectation from the restored database will agree with itself no matter
    what was lost.
    """

    created_at: str
    database: str
    schema_version: str
    dump_sha256: str
    roles: list[str]
    row_counts: dict[str, int]
    forced_rls_tables: int
    append_only_triggers: int


class BackupError(RuntimeError):
    pass


def psql(container: str, database: str, sql: str) -> str:
    completed = subprocess.run(
        ["docker", "exec", container, "psql", "-U", OWNER, "-d", database, "-tAc", sql],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise BackupError(f"psql failed: {completed.stderr.strip()[:200]}")
    return completed.stdout.strip()


def count_rows(container: str, database: str, table: str) -> int:
    """Count one table, refusing any name not in the allowlist.

    The name reaches this function from a manifest file during verification, and a
    manifest can come from wherever a backup was copied from. Interpolating it into SQL
    unchecked would make a crafted archive able to run statements as the owner on the
    machine doing the restoring -- which is the one machine that must not be
    compromised by an untrusted backup.
    """
    if table not in IRREPLACEABLE_TABLES:
        raise BackupError(f"refusing to query an unrecognised table: {table!r}")
    return int(psql(container, database, f"SELECT count(*) FROM {table}") or 0)  # noqa: S608


def schema_version(container: str, database: str) -> str:
    return psql(container, database, "SELECT version_num FROM alembic_version") or "unknown"


def collect_manifest(container: str, database: str, dump: Path) -> Manifest:
    counts: dict[str, int] = {}
    for table in IRREPLACEABLE_TABLES:
        counts[table] = count_rows(container, database, table)

    roles = [
        line
        for line in psql(
            container, database, "SELECT rolname FROM pg_roles WHERE rolname LIKE 'siembiot%'"
        ).splitlines()
        if line
    ]

    return Manifest(
        created_at=datetime.now(UTC).isoformat(),
        database=database,
        schema_version=schema_version(container, database),
        dump_sha256=hashlib.sha256(dump.read_bytes()).hexdigest(),
        roles=sorted(roles),
        row_counts=counts,
        forced_rls_tables=int(
            psql(
                container,
                database,
                "SELECT count(*) FROM pg_class WHERE relrowsecurity AND relforcerowsecurity",
            )
            or 0
        ),
        append_only_triggers=int(
            psql(container, database, "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal") or 0
        ),
    )


def create(container: str, database: str) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = BACKUP_ROOT / f"{database}-{stamp}"
    target.mkdir(parents=True, exist_ok=True)

    dump = target / "database.dump"
    # Custom format: compressed, and restorable selectively, which matters when the
    # thing being recovered is one table rather than a whole cluster.
    with dump.open("wb") as handle:
        completed = subprocess.run(
            ["docker", "exec", container, "pg_dump", "-U", OWNER, "-d", database, "-Fc"],
            stdout=handle,
            stderr=subprocess.PIPE,
            check=False,
        )
    if completed.returncode != 0:
        raise BackupError(f"pg_dump failed: {completed.stderr.decode()[:200]}")

    roles = target / "roles.sql"
    # Without passwords on purpose: the backup then holds no credential, and the three
    # passwords come from the environment at restore time exactly as they do at first
    # install. An archive containing password hashes has to be guarded like a secret,
    # and backups are the files most likely to be copied somewhere less careful.
    with roles.open("wb") as handle:
        completed = subprocess.run(
            [
                "docker",
                "exec",
                container,
                "pg_dumpall",
                "-U",
                OWNER,
                "--roles-only",
                "--no-role-passwords",
            ],
            stdout=handle,
            stderr=subprocess.PIPE,
            check=False,
        )
    if completed.returncode != 0:
        raise BackupError(f"pg_dumpall failed: {completed.stderr.decode()[:200]}")

    manifest = collect_manifest(container, database, dump)
    (target / "manifest.json").write_text(
        json.dumps(asdict(manifest), indent=2, sort_keys=True), encoding="utf-8"
    )
    return target


def restore(container: str, backup: Path, into: str, *, drop_existing: bool = False) -> None:
    manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    dump = backup / "database.dump"

    actual = hashlib.sha256(dump.read_bytes()).hexdigest()
    if actual != manifest["dump_sha256"]:
        # Checked before anything is written. A corrupted dump restored over a live
        # database is a worse outcome than no restore at all.
        raise BackupError(
            f"dump digest does not match the manifest: {actual[:12]}… vs "
            f"{manifest['dump_sha256'][:12]}…"
        )

    if drop_existing:
        psql(container, "postgres", f'DROP DATABASE IF EXISTS "{into}"')
    psql(container, "postgres", f'CREATE DATABASE "{into}" OWNER {OWNER}')

    # Roles first: the dump's GRANT statements refer to them, and a restore into a
    # cluster without them ends in a database nobody can connect to -- reported at the
    # end of a long restore rather than at the start.
    roles_sql = (backup / "roles.sql").read_text(encoding="utf-8")
    _feed(container, ["psql", "-U", OWNER, "-d", "postgres"], roles_sql)

    with dump.open("rb") as handle:
        completed = subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                container,
                "pg_restore",
                "-U",
                OWNER,
                "-d",
                into,
                "--no-owner",
            ],
            stdin=handle,
            capture_output=True,
            check=False,
        )
    # pg_restore reports a non-zero status for benign conditions such as a role that
    # already exists, so the verification below is what decides whether it worked.
    if completed.returncode != 0:
        print(f"  pg_restore reported: {completed.stderr.decode()[:200]}")


def _feed(container: str, command: list[str], payload: str) -> None:
    completed = subprocess.run(
        ["docker", "exec", "-i", container, *command],
        input=payload,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0 and "already exists" not in completed.stderr:
        raise BackupError(f"{' '.join(command)} failed: {completed.stderr.strip()[:200]}")


def verify(container: str, backup: Path) -> int:
    """Restore into a throwaway database and check what came back.

    The scratch database is dropped whether or not the checks pass: leaving it behind
    would eventually have somebody connect an application to it.
    """
    manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    scratch = f"siembiot_verify_{datetime.now(UTC).strftime('%H%M%S')}"

    problems: list[str] = []
    try:
        restore(container, backup, scratch, drop_existing=True)

        version = schema_version(container, scratch)
        if version != manifest["schema_version"]:
            problems.append(f"schema version {version} != {manifest['schema_version']}")

        for table, expected in sorted(manifest["row_counts"].items()):
            actual = count_rows(container, scratch, table)
            if actual != expected:
                problems.append(f"{table}: {actual} rows, expected {expected}")

        forced = int(
            psql(
                container,
                scratch,
                "SELECT count(*) FROM pg_class WHERE relrowsecurity AND relforcerowsecurity",
            )
            or 0
        )
        if forced != manifest["forced_rls_tables"]:
            # Enabled but not FORCEd would let the owner read every tenant's rows, and
            # nothing about the restore would look wrong.
            problems.append(
                f"tables with forced row-level security: {forced}, "
                f"expected {manifest['forced_rls_tables']}"
            )

        triggers = int(
            psql(container, scratch, "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal") or 0
        )
        if triggers != manifest["append_only_triggers"]:
            problems.append(
                f"triggers: {triggers}, expected {manifest['append_only_triggers']} "
                "(evidence would no longer be append-only)"
            )

        present = {
            line
            for line in psql(
                container, scratch, "SELECT rolname FROM pg_roles WHERE rolname LIKE 'siembiot%'"
            ).splitlines()
            if line
        }
        missing = set(manifest["roles"]) - present
        if missing:
            problems.append(f"roles missing after restore: {sorted(missing)}")

        # The audit trail is one of the two things here that cannot be reconstructed, and
        # a restore is exactly when it could be quietly replaced. Recomputing the chain in
        # the restored copy checks that what came back is the history that went in --
        # matching row counts would not, since a substituted trail can have the same
        # number of rows.
        broken = [
            line
            for line in psql(
                container,
                scratch,
                "SELECT coalesce(organization_id::text, 'platform') || ' @' || "
                "sequence_number || ': ' || problem FROM audit_chain_breaks()",
            ).splitlines()
            if line
        ]
        if broken:
            problems.extend(f"audit chain broken: {line}" for line in broken)
    finally:
        psql(container, "postgres", f'DROP DATABASE IF EXISTS "{scratch}"')

    if problems:
        for problem in problems:
            print(f"  FAIL  {problem}")
        print(f"\n{len(problems)} problem(s): this backup would not restore a working system")
        return 1

    total = sum(manifest["row_counts"].values())
    print(f"  ok    schema {manifest['schema_version']}")
    print(f"  ok    {total} rows across {len(manifest['row_counts'])} irreplaceable tables")
    print(f"  ok    {manifest['forced_rls_tables']} tables still enforcing tenant isolation")
    print(f"  ok    {manifest['append_only_triggers']} triggers still making evidence append-only")
    print(f"  ok    roles {', '.join(manifest['roles'])}")
    print("  ok    audit chain verifies in the restored copy")
    print("\nrestored and verified")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", default=DEFAULT_CONTAINER)
    parser.add_argument("--database", default=DEFAULT_DATABASE)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("create")
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("backup", type=Path)
    restore_parser = sub.add_parser("restore")
    restore_parser.add_argument("backup", type=Path)
    restore_parser.add_argument("--into", required=True)
    restore_parser.add_argument("--drop-existing", action="store_true")

    args = parser.parse_args()

    try:
        if args.command == "create":
            target = create(args.container, args.database)
            print(f"backup written to {target.relative_to(ROOT)}")
            print(f"verify it before relying on it: python scripts/backup.py verify {target}")
            return 0
        if args.command == "verify":
            return verify(args.container, args.backup)
        restore(args.container, args.backup, args.into, drop_existing=args.drop_existing)
        print(f"restored into {args.into}")
        print("passwords are not in the backup; set them from your secret store")
        return 0
    except BackupError as error:
        print(f"backup failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
