"""Where a backup is allowed to live, and the schedule that produces one.

The tooling to take and verify a backup already worked. What was missing was a timer and
a destination, and of those the destination is the one that matters: `artifacts/` sits on
the same machine as the database, so a copy there survives a dropped table and nothing
else. A backup that fails together with its source is a rehearsal, not a backup.

So this refuses more than it does. It will not run without an explicitly configured
destination, and it will not accept one that shares a filesystem with the PostgreSQL data
directory. Both refusals are noisy on purpose: a deployment that silently wrote backups
beside the database would look exactly like a deployment that was backing up correctly,
right up until the moment somebody needed one.

What this cannot do is choose a destination for a deployment. An S3 bucket, an NFS mount
or a second host is infrastructure with credentials attached, and inventing one here would
produce a configuration that looks complete and points nowhere.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

#: Where backups go. No default: a default would be a local path, and a local path is the
#: failure this module exists to prevent.
DESTINATION_VARIABLE = "SIEMBIOT_BACKUP_DESTINATION"

#: The PostgreSQL data directory, when it is visible from this process. Used only to
#: refuse a destination that shares its filesystem.
DATA_DIRECTORY_VARIABLE = "SIEMBIOT_POSTGRES_DATA_DIRECTORY"

NOT_CONFIGURED = "backup_destination_not_configured"
SAME_FILESYSTEM = "backup_destination_shares_filesystem_with_database"
INSIDE_REPOSITORY = "backup_destination_inside_repository"
UNWRITABLE = "backup_destination_unwritable"

#: Schemes treated as off-host by construction. The uploader is supplied by the
#: deployment; this module only decides whether a destination is acceptable.
REMOTE_SCHEMES = ("s3://", "gs://", "azure://", "sftp://", "nfs://")


@dataclass(frozen=True)
class DestinationVerdict:
    destination: str | None
    refusal: str | None

    @property
    def usable(self) -> bool:
        return self.refusal is None


def resolve_destination(
    configured: str | None = None,
    *,
    data_directory: str | None = None,
    repository_root: Path | None = None,
) -> DestinationVerdict:
    """Decide whether backups may be written where the deployment says.

    Checked in this order because the answers get more expensive: configured at all,
    then remote by scheme, then the filesystem comparison that needs to touch the disk.
    """
    target = configured if configured is not None else os.environ.get(DESTINATION_VARIABLE)
    if not target:
        return DestinationVerdict(None, NOT_CONFIGURED)

    if target.startswith(REMOTE_SCHEMES):
        # A remote scheme is off-host by definition. Whether the credentials work is the
        # deployment's problem and is discovered by the verify step, not guessed here.
        return DestinationVerdict(target, None)

    path = Path(target).expanduser()
    root = repository_root or Path(__file__).resolve().parents[4]
    try:
        if path.resolve().is_relative_to(root.resolve()):
            # `artifacts/` and everything else in the working tree is on the developer's
            # machine, and in a container it is inside the image.
            return DestinationVerdict(target, INSIDE_REPOSITORY)
    except (OSError, ValueError):
        pass

    if not path.exists() or not os.access(path, os.W_OK):
        return DestinationVerdict(target, UNWRITABLE)

    directory = data_directory or os.environ.get(DATA_DIRECTORY_VARIABLE)
    if directory and _same_filesystem(path, Path(directory)):
        return DestinationVerdict(target, SAME_FILESYSTEM)

    return DestinationVerdict(target, None)


def _same_filesystem(left: Path, right: Path) -> bool:
    """Whether two paths sit on the same device.

    A weaker check than "the same machine", and it is the strongest one available from
    inside a process: a separate device survives a full disk and a corrupted filesystem,
    which is most of what goes wrong. It does not survive the building burning down, and
    this module does not claim it does -- that is what a remote scheme is for.
    """
    try:
        return left.resolve().stat().st_dev == right.resolve().stat().st_dev
    except OSError:
        # A data directory this process cannot stat is nearly always one on another
        # machine, which is the safe case rather than the unknown one. Refusing here
        # would stop backups on exactly the deployments that already separated their
        # database, which is the wrong way round.
        return False


# -- taking one ------------------------------------------------------------------------

DUMP_UNAVAILABLE = "pg_dump_not_available"
DUMP_FAILED = "pg_dump_failed"
NO_UPLOADER = "no_uploader_for_remote_destination"
WROTE_NOTHING = "pg_dump_produced_no_output"
NO_CREDENTIALS = "backup_credentials_not_configured"

#: Credentials for the dump, and deliberately **not** the worker's own.
#:
#: Every tenant-scoped table carries row-level security with FORCE, which applies to the
#: table owner as well. A dump taken with a role subject to those policies contains the
#: rows that role could see and no others -- and it restores without complaint, because a
#: filtered dump is a valid dump. That is a backup that appears to work and silently
#: omits data, which is the single worst failure available to this module.
#:
#: PostgreSQL does refuse rather than silently filter here: pg_dump errors on an
#: RLS-protected table unless the role can bypass row security. That refusal is a
#: safeguard, not a plan. Naming the credentials separately makes the requirement
#: explicit instead of leaving it to be discovered by a failed nightly job.
CREDENTIALS_VARIABLE = "SIEMBIOT_BACKUP_DATABASE_URL"

#: A dump of this database is minutes of work, not hours. A bound that is generous for a
#: healthy run and still ends a hung one before the next schedule fires.
DUMP_TIMEOUT_SECONDS = 1_800


@dataclass(frozen=True)
class BackupOutcome:
    destination: str | None = None
    size_bytes: int | None = None
    content_sha256: str | None = None
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.error is None


def dump_available() -> bool:
    """Whether `pg_dump` can be run from this process.

    Checked rather than assumed, and reported as a named failure rather than an
    exception: an image missing its client tools is a deployment mistake, and a task that
    crashed nightly would be read as a broken worker rather than as the missing package
    it is.
    """
    return shutil.which("pg_dump") is not None


def credentials() -> str | None:
    """The dump's connection URL, or None when it has not been configured.

    Stripped of the SQLAlchemy driver suffix if one is present: `postgresql+psycopg://`
    is a Python dialect name and pg_dump does not know it, so a URL copied from the
    worker's own settings would otherwise fail with an unhelpful parse error.
    """
    url = os.environ.get(CREDENTIALS_VARIABLE, "").strip()
    return url.replace("postgresql+psycopg://", "postgresql://") or None


def take_backup(
    database_url: str,
    *,
    destination: DestinationVerdict | None = None,
    now: datetime | None = None,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> BackupOutcome:
    """Dump the database and place it at the configured destination.

    The dump goes straight to a file at the destination rather than through memory: a
    database large enough to matter is a database too large to hold twice.

    Local destinations are written here. A remote scheme is refused with a named reason
    rather than silently skipped -- the uploader belongs to the deployment, and a task
    that reported success while writing nowhere would be the worst outcome available.
    """
    verdict = destination or resolve_destination()
    if not verdict.usable or verdict.destination is None:
        return BackupOutcome(verdict.destination, error=verdict.refusal)
    if not dump_available():
        return BackupOutcome(verdict.destination, error=DUMP_UNAVAILABLE)
    if verdict.destination.startswith(REMOTE_SCHEMES):
        return BackupOutcome(verdict.destination, error=NO_UPLOADER)

    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    target = Path(verdict.destination) / f"siembiot-{stamp}.dump"

    try:
        with target.open("wb") as handle:
            completed = runner(
                # Custom format: compressed, and restorable selectively. `--no-owner` so
                # a restore into a differently-named role does not fail on ownership it
                # was never going to reproduce.
                ["pg_dump", "--format=custom", "--no-owner", "--dbname", database_url],
                stdout=handle,
                stderr=subprocess.PIPE,
                timeout=DUMP_TIMEOUT_SECONDS,
                check=False,
            )
    except (OSError, subprocess.SubprocessError):
        target.unlink(missing_ok=True)
        return BackupOutcome(verdict.destination, error=DUMP_FAILED)

    if completed.returncode != 0:
        # A partial file is worse than none: it looks like a backup and restores into
        # half a database.
        target.unlink(missing_ok=True)
        return BackupOutcome(verdict.destination, error=DUMP_FAILED)

    size = target.stat().st_size if target.exists() else 0
    if size == 0:
        target.unlink(missing_ok=True)
        return BackupOutcome(verdict.destination, error=WROTE_NOTHING)

    return BackupOutcome(
        destination=str(target),
        size_bytes=size,
        content_sha256=_digest(target),
        error=None,
    )


def _digest(path: Path) -> str:
    """Read in chunks. The point of streaming the dump to disk is not holding it in
    memory, and hashing it in one read would undo that."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()
