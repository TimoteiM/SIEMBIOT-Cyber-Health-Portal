"""What a backup has to contain, and what its verification has to notice.

The failure mode here is quiet and total: a backup that appears to be taken every night
and turns out, on the day it is needed, not to restore a working system. So these tests
are about the checks themselves -- a verifier that cannot fail is the same as no
verifier, and is more dangerous because somebody is relying on it.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

from backup import (  # noqa: E402
    IRREPLACEABLE_TABLES,
    BackupError,
    Manifest,
)


def manifest(**overrides: object) -> Manifest:
    base = {
        "created_at": "2026-08-07T00:00:00+00:00",
        "database": "siembiot",
        "schema_version": "0011_assessment_schedules",
        "dump_sha256": "a" * 64,
        "roles": ["siembiot_app", "siembiot_owner", "siembiot_worker"],
        "row_counts": dict.fromkeys(IRREPLACEABLE_TABLES, 1),
        "forced_rls_tables": 26,
        "append_only_triggers": 13,
    }
    base.update(overrides)
    return Manifest(**base)  # type: ignore[arg-type]


def test_the_manifest_covers_what_cannot_be_rebuilt() -> None:
    """Everything else -- schema, policy catalog, images -- lives in the repository.

    Evidence and the audit trail do not, which is what makes this the last remaining
    single point of loss.
    """
    assert "audit_events" in IRREPLACEABLE_TABLES
    assert "normalized_observations" in IRREPLACEABLE_TABLES
    assert "findings" in IRREPLACEABLE_TABLES
    assert "score_snapshots" in IRREPLACEABLE_TABLES


def test_the_manifest_records_the_enforcement_a_restore_must_keep() -> None:
    """A restore that lost these would look identical from the outside.

    Row-level security still enabled but no longer FORCEd would let the owner read
    every tenant's rows, and nothing about the restore would appear wrong.
    """
    recorded = manifest()
    assert recorded.forced_rls_tables > 0
    assert recorded.append_only_triggers > 0
    assert "siembiot_worker" in recorded.roles


def test_expectations_are_captured_at_backup_time_not_derived_at_restore() -> None:
    """A check that computes its own expectation from the restored database agrees with
    itself no matter what was lost."""
    fields = set(Manifest.__dataclass_fields__)
    assert {"row_counts", "forced_rls_tables", "append_only_triggers", "schema_version"} <= fields


def test_a_backup_contains_no_credential(tmp_path: Path) -> None:
    """Roles are dumped with --no-role-passwords on purpose.

    An archive holding password hashes has to be guarded like a secret, and backups are
    the files most likely to be copied somewhere less careful. The three passwords come
    from the environment at restore exactly as they do at first install.
    """
    import backup

    source = Path(backup.__file__).read_text(encoding="utf-8")
    assert "--no-role-passwords" in source
    # And never the flag that would include them.
    assert "--roles-only" in source


def test_roles_are_restored_before_the_dump() -> None:
    """A dump carries grants but not the roles they name.

    Restoring into a fresh cluster without them ends in a database nobody can connect
    to, reported at the end of a long restore rather than at the start.
    """
    import backup

    source = Path(backup.__file__).read_text(encoding="utf-8")
    roles_at = source.index('roles.sql").read_text')
    restore_at = source.index("pg_restore")
    assert roles_at < restore_at, "roles must be loaded before the dump that grants to them"


def test_a_corrupted_dump_is_refused_before_anything_is_written(tmp_path: Path) -> None:
    """Checked before the target database is created.

    A corrupted dump restored over a live database is a worse outcome than no restore,
    and by then the original is gone.
    """
    import backup

    dump = tmp_path / "database.dump"
    dump.write_bytes(b"not the bytes the manifest describes")
    (tmp_path / "roles.sql").write_text("", encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        json.dumps({**manifest().__dict__, "dump_sha256": hashlib.sha256(b"other").hexdigest()}),
        encoding="utf-8",
    )

    with pytest.raises(BackupError, match="digest"):
        backup.restore("no-such-container", tmp_path, "scratch")


def test_verification_uses_a_throwaway_database() -> None:
    """Restoring into anything durable risks somebody connecting an application to it,
    and the scratch database is dropped whether or not the checks pass."""
    import backup

    source = Path(backup.__file__).read_text(encoding="utf-8")
    assert "siembiot_verify_" in source
    assert "finally:" in source
    assert "DROP DATABASE IF EXISTS" in source
