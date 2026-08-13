"""The jobs runbook has to describe the jobs that exist.

`docs/operations/jobs.md` is the page somebody reads at three in the morning, and the
failure it was written about is one nobody would have guessed: the platform ran with the
API, the interface and a worker, reported healthy everywhere, and did no work at all
because the scheduler was not running. A runbook that misses a job, or names one that was
renamed, reproduces that exact experience -- an operator reading a page that quietly does
not match the system.

So the strings are checked rather than trusted. Every beat entry, every task name and
every backup refusal code has to appear. This cannot verify that the prose is *true*; it
can guarantee that a job added or renamed in `tasks.py` breaks the build until the
runbook catches up, which is the part attention is worst at.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = ROOT / "docs" / "operations" / "jobs.md"
TASKS = ROOT / "services" / "worker" / "src" / "siembiot_worker" / "tasks.py"

sys.path.insert(0, str(ROOT / "services" / "worker" / "src"))


def runbook() -> str:
    return RUNBOOK.read_text(encoding="utf-8")


def beat_entries() -> set[str]:
    """The schedule's own entry names, read out of the source.

    Parsed from the `beat_schedule` block rather than by importing and building the
    Celery app, which would need a broker to be reachable.
    """
    source = TASKS.read_text(encoding="utf-8")
    block = source[source.index("beat_schedule={") :]
    block = block[: block.index("\n        },")]
    return set(re.findall(r'"([a-z-]+)":\s*\{', block))


def task_names() -> set[str]:
    return set(
        re.findall(r'@app\.task\(name="(siembiot\.[a-z_]+)"', TASKS.read_text(encoding="utf-8"))
    )


def test_the_runbook_exists() -> None:
    assert RUNBOOK.is_file(), f"{RUNBOOK.relative_to(ROOT)} is missing"


def test_the_parse_found_a_schedule() -> None:
    """The guard that makes the two tests below mean anything.

    If the `beat_schedule` block moved or was reformatted, the parser above would return
    an empty set and every "is documented" assertion would pass over nothing.
    """
    entries = beat_entries()

    assert len(entries) >= 5, f"only found {sorted(entries)}; the schedule parser is stale"


def test_every_scheduled_job_is_in_the_runbook() -> None:
    """A job that runs and is not written down is one nobody knows to check."""
    missing = sorted(entry for entry in beat_entries() if entry not in runbook())

    assert not missing, (
        f"{missing} are scheduled and absent from {RUNBOOK.name}. An operator reading "
        "that page would not know they exist, let alone that they had stopped."
    )


def test_every_task_name_is_in_the_runbook() -> None:
    """The names that appear in worker logs. Somebody grepping a log for
    `siembiot.snapshot_quota` has to be able to find out what it is."""
    documented = runbook()
    missing = sorted(name for name in task_names() if name not in documented)

    assert not missing, f"{missing} appear in logs and not in {RUNBOOK.name}"


def test_every_backup_refusal_is_explained() -> None:
    """The backup job refuses more than it succeeds, by design, and every refusal is a
    named reason. A reason with no entry here is a nightly failure with no fix written
    down -- and most of them are a minute of configuration."""
    from siembiot_worker import backups

    codes = {
        value
        for name, value in vars(backups).items()
        if name.isupper()
        and isinstance(value, str)
        and "_" in value
        and not name.endswith("VARIABLE")
    }
    documented = runbook()
    missing = sorted(code for code in codes if code not in documented)

    assert codes, "no refusal codes found; this test is checking nothing"
    assert not missing, f"{missing} can be reported by the backup job and are not explained"


def test_the_runbook_says_the_scheduler_is_required() -> None:
    """The one fact the page exists for.

    Everything else on it is reference material. This is the sentence that would have
    saved the session that prompted writing it, so it is asserted rather than assumed to
    survive editing.
    """
    text = runbook()

    assert "beat-serve" in text, "the runbook does not say how to start the scheduler"
    assert re.search(r"(?i)without it nothing runs|no scheduler means no work", text), (
        "the runbook no longer states that nothing runs without the scheduler"
    )
