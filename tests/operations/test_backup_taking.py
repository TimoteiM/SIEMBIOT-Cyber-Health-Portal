"""Taking the backup, as opposed to deciding where it may go.

The destination rules are tested next door. This file is about the run itself, and most
of it is about failure, because the failure this module exists to prevent is not "the
backup crashed" -- a crash is loud and somebody fixes it. It is **a backup that reports
success and is not restorable**: a truncated dump, an empty file, a partial extract.
Every one of those restores without complaint.

So the assertions are on what is left on disk after a failure, not only on the returned
reason. A named error next to a half-written file is not a refusal, it is a trap.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "worker" / "src"))

from siembiot_worker import backups  # noqa: E402
from siembiot_worker.backups import (  # noqa: E402
    DUMP_FAILED,
    DUMP_UNAVAILABLE,
    NO_UPLOADER,
    WROTE_NOTHING,
    DestinationVerdict,
    take_backup,
)

URL = "postgresql://siembiot_owner:secret@db/siembiot"


@pytest.fixture(autouse=True)
def _pg_dump_is_present(monkeypatch: pytest.MonkeyPatch) -> None:
    """Present by default, so every test here is about the dump rather than the tool.

    The one test that cares about absence turns it off explicitly. Without this the
    suite would pass on a developer machine for the wrong reason -- `pg_dump` is not on
    a Windows host, so every case would return `pg_dump_not_available` and assert
    nothing about the code under test.
    """
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")


def usable(path: Path) -> DestinationVerdict:
    return DestinationVerdict(destination=str(path), refusal=None)


def writing(payload: bytes, *, returncode: int = 0) -> Any:
    """A stand-in for pg_dump that writes what it is told and exits how it is told."""

    def runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        kwargs["stdout"].write(payload)
        return subprocess.CompletedProcess(command, returncode, None, b"")

    return runner


# -- the good case, and what it must record ----------------------------------------------


def test_a_successful_dump_is_placed_and_described(tmp_path: Path) -> None:
    outcome = take_backup(URL, destination=usable(tmp_path), runner=writing(b"PGDMP fake"))

    assert outcome.succeeded
    written = Path(outcome.destination or "")
    assert written.parent == tmp_path
    assert written.read_bytes() == b"PGDMP fake"


def test_the_digest_is_of_the_bytes_that_landed(tmp_path: Path) -> None:
    """Not of what was intended. A digest computed from anything but the finished file
    would agree with itself forever and detect no corruption at all."""
    payload = b"PGDMP" + bytes(range(256)) * 40

    outcome = take_backup(URL, destination=usable(tmp_path), runner=writing(payload))

    on_disk = hashlib.sha256(Path(outcome.destination or "").read_bytes()).hexdigest()
    assert outcome.content_sha256 == on_disk
    assert outcome.size_bytes == len(payload)


def test_two_different_dumps_do_not_share_a_digest(tmp_path: Path) -> None:
    """The mutation. If the digest did not depend on the contents -- a constant, a hash
    of the filename, a hash of an empty buffer -- every test above would still pass."""
    first = take_backup(URL, destination=usable(tmp_path), runner=writing(b"PGDMP one"))
    second = take_backup(URL, destination=usable(tmp_path), runner=writing(b"PGDMP two!"))

    assert first.content_sha256 != second.content_sha256


def test_each_run_writes_its_own_file(tmp_path: Path) -> None:
    """A fixed filename would mean the newest backup overwrites the only other copy --
    so a corrupted dump destroys the good one it was meant to succeed."""
    first = take_backup(URL, destination=usable(tmp_path), runner=writing(b"PGDMP one"))
    from datetime import UTC, datetime

    second = take_backup(
        URL,
        destination=usable(tmp_path),
        runner=writing(b"PGDMP two"),
        now=datetime(2030, 1, 1, tzinfo=UTC),
    )

    assert first.destination != second.destination
    assert len(list(tmp_path.iterdir())) == 2


# -- the failures, and the files they must not leave behind -------------------------------


def test_a_failed_dump_leaves_nothing_behind(tmp_path: Path) -> None:
    """The case this file exists for.

    pg_dump writes a valid-looking prefix before it fails -- a connection dropped
    mid-table produces a real header and half the rows. Keeping that file would put a
    restorable-looking artifact in the backup directory, and the next person to need it
    would restore half a database and believe it.
    """
    outcome = take_backup(
        URL,
        destination=usable(tmp_path),
        runner=writing(b"PGDMP half a database", returncode=1),
    )

    assert outcome.error == DUMP_FAILED
    assert list(tmp_path.iterdir()) == []


def test_a_dump_that_wrote_nothing_is_not_a_backup(tmp_path: Path) -> None:
    """Exit zero and an empty file. Reported as a failure rather than as a very small
    backup, and removed for the same reason as the partial one."""
    outcome = take_backup(URL, destination=usable(tmp_path), runner=writing(b""))

    assert outcome.error == WROTE_NOTHING
    assert list(tmp_path.iterdir()) == []


def test_a_crashing_dump_is_a_named_reason_rather_than_an_exception(tmp_path: Path) -> None:
    """A task that raised nightly would be read as a broken worker."""

    def explodes(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        del command, kwargs
        raise OSError("pg_dump vanished")

    outcome = take_backup(URL, destination=usable(tmp_path), runner=explodes)

    assert outcome.error == DUMP_FAILED
    assert list(tmp_path.iterdir()) == []


def test_a_timeout_leaves_no_partial_file(tmp_path: Path) -> None:
    """A hung dump is the likeliest way to get a large, plausible, unusable file."""

    def hangs(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        kwargs["stdout"].write(b"PGDMP most of a database")
        raise subprocess.TimeoutExpired(command, timeout=1)

    outcome = take_backup(URL, destination=usable(tmp_path), runner=hangs)

    assert outcome.error == DUMP_FAILED
    assert list(tmp_path.iterdir()) == []


def test_no_dump_tool_is_reported_by_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An image built without postgresql-client. A deployment mistake that must name
    itself, because from the outside it is indistinguishable from a broken scheduler."""
    monkeypatch.setattr("shutil.which", lambda name: None)

    outcome = take_backup(URL, destination=usable(tmp_path), runner=writing(b"unused"))

    assert outcome.error == DUMP_UNAVAILABLE
    assert list(tmp_path.iterdir()) == []


def test_a_refused_destination_is_never_dumped_to(tmp_path: Path) -> None:
    """The destination rules are not advisory. A refusal has to stop the run, or they
    are documentation."""
    called = False

    def runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        nonlocal called
        called = True
        del command, kwargs
        raise AssertionError("the dump ran against a refused destination")

    outcome = take_backup(
        URL,
        destination=DestinationVerdict(destination=str(tmp_path), refusal="some_refusal"),
        runner=runner,
    )

    assert outcome.error == "some_refusal"
    assert not called


def test_a_remote_destination_is_refused_rather_than_silently_skipped() -> None:
    """The uploader belongs to the deployment. Reporting success while writing nowhere
    is the worst outcome available to this module, so the absence is named."""
    outcome = take_backup(
        URL,
        destination=DestinationVerdict(destination="s3://siembiot-backups/nightly", refusal=None),
        runner=writing(b"unused"),
    )

    assert outcome.error == NO_UPLOADER


# -- the credentials ----------------------------------------------------------------------


def test_the_dump_url_is_stripped_of_the_python_driver(monkeypatch: pytest.MonkeyPatch) -> None:
    """`postgresql+psycopg://` is a SQLAlchemy dialect name. pg_dump does not know it,
    and a URL copied from the worker's own settings is the obvious thing to configure."""
    monkeypatch.setenv(backups.CREDENTIALS_VARIABLE, "postgresql+psycopg://user@host/db")

    assert backups.credentials() == "postgresql://user@host/db"


def test_absent_credentials_are_none_rather_than_an_empty_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty string would be passed to pg_dump as a connection string and produce an
    obscure failure instead of the named one."""
    monkeypatch.setenv(backups.CREDENTIALS_VARIABLE, "   ")

    assert backups.credentials() is None


def test_the_credentials_are_not_the_workers_own(monkeypatch: pytest.MonkeyPatch) -> None:
    """Separate on purpose.

    Every tenant-scoped table carries row-level security with FORCE. A dump taken by a
    role subject to those policies would contain the rows that role can see and would
    restore without complaint -- a backup that appears to work and silently omits data.
    A shared variable would make that the default configuration.
    """
    assert backups.CREDENTIALS_VARIABLE != "SIEMBIOT_WORKER_DATABASE_URL"

    monkeypatch.setenv("SIEMBIOT_WORKER_DATABASE_URL", "postgresql://siembiot_worker@host/db")
    monkeypatch.delenv(backups.CREDENTIALS_VARIABLE, raising=False)

    assert backups.credentials() is None
