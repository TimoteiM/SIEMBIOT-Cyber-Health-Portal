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

import os
from dataclasses import dataclass
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
