"""Where a backup may be written.

The tooling to take and verify one already worked; `artifacts/` was the problem. A copy
on the same machine as the database survives a dropped table and nothing else, and a
deployment writing there looks identical to one backing up correctly until somebody needs
a restore.

Every test here is a refusal, because that is what this module contributes.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "worker" / "src"))

from siembiot_worker.backups import (  # noqa: E402
    INSIDE_REPOSITORY,
    NOT_CONFIGURED,
    SAME_FILESYSTEM,
    UNWRITABLE,
    resolve_destination,
)


def test_no_destination_means_no_backup() -> None:
    """Fails closed. The alternative is a default, and any default is a local path --
    the exact configuration this exists to prevent."""
    verdict = resolve_destination("")

    assert not verdict.usable
    assert verdict.refusal == NOT_CONFIGURED


def test_a_destination_inside_the_repository_is_refused(tmp_path: Path) -> None:
    """`artifacts/backups` is where the tooling wrote by default, and it is on the
    developer's machine -- or, in a container, inside the image."""
    root = tmp_path / "repo"
    (root / "artifacts").mkdir(parents=True)

    verdict = resolve_destination(str(root / "artifacts"), repository_root=root)

    assert verdict.refusal == INSIDE_REPOSITORY


def test_a_destination_sharing_the_database_filesystem_is_refused(tmp_path: Path) -> None:
    """The check that gives this module its purpose.

    Both paths are in the same temporary directory, so they share a device, which is what
    a backup written next to the data directory looks like.
    """
    destination = tmp_path / "backups"
    data = tmp_path / "pgdata"
    destination.mkdir()
    data.mkdir()

    verdict = resolve_destination(
        str(destination), data_directory=str(data), repository_root=tmp_path / "elsewhere"
    )

    assert verdict.refusal == SAME_FILESYSTEM


def test_an_unwritable_destination_is_refused(tmp_path: Path) -> None:
    """Discovered now rather than at three in the morning when the first backup runs."""
    verdict = resolve_destination(
        str(tmp_path / "does-not-exist"), repository_root=tmp_path / "elsewhere"
    )

    assert verdict.refusal == UNWRITABLE


@pytest.mark.parametrize(
    "destination",
    ["s3://siembiot-backups/nightly", "gs://bucket/path", "sftp://backup.host/srv"],
)
def test_a_remote_destination_is_accepted(destination: str) -> None:
    """Off-host by construction. Whether the credentials work is discovered by the
    verify step rather than guessed here."""
    verdict = resolve_destination(destination)

    assert verdict.usable
    assert verdict.destination == destination


def test_a_separate_local_filesystem_is_accepted(tmp_path: Path) -> None:
    """A mounted volume on another device is a legitimate destination: it survives a
    full disk and a corrupted filesystem, which is most of what goes wrong.

    Simulated by naming a data directory that cannot be stat'ed, which is also what a
    database on another machine looks like from here.
    """
    destination = tmp_path / "elsewhere"
    destination.mkdir()

    verdict = resolve_destination(
        str(destination),
        data_directory="/proc/nonexistent/pgdata",
        repository_root=tmp_path / "repo",
    )

    assert verdict.usable


def test_the_refusal_is_named_rather_than_a_boolean() -> None:
    """An operator seeing "backup did not run" needs to know which of four reasons it
    was; three of them are configuration they can fix in a minute."""
    reasons = {
        resolve_destination("").refusal,
        resolve_destination(str(Path(__file__).parent)).refusal,
    }

    assert None not in reasons
    assert all(isinstance(reason, str) for reason in reasons)
