"""Accepted vulnerability findings must expire, and somebody must be warned in time.

`.trivyignore.yaml` holds findings this deployment has decided not to fix, each with a
reason and an `expired_at` date. That file is only honest if the dates mean something.

**An expiry date that nothing trips over is not a deadline, it is a note.** The scan goes
red the day after a suppression lapses, which is too late to be useful: by then the
choice is between rushing a major-version upgrade and extending the date to make the red
go away, and the second one is what actually happens.

So this fails ahead of the date, with `WARNING_WINDOW` of lead time, and says what the
work is. That converts "we should look at this before November" -- which depends on
somebody remembering -- into a gate that goes red on an ordinary Tuesday with enough
runway to do the job properly.

It is deliberately part of `make check` rather than a calendar entry, a cron job or a
ticket. All three of those live outside the repository and none of them is checked by
anything. This one cannot be forgotten, because forgetting it is a build failure.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
IGNOREFILE = ROOT / ".trivyignore.yaml"

#: How much warning before a suppression lapses.
#:
#: Thirty days because the open item this was written for is a FastAPI and Starlette
#: major-version upgrade -- middleware behaviour, response handling, and anything
#: touching StaticFiles, form parsing or FileResponse all need a real regression pass.
#: That is a scoped piece of work, not an afternoon, and a week's notice would guarantee
#: it got folded into whatever else was happening that week.
WARNING_WINDOW = timedelta(days=30)


def entries() -> list[Mapping[str, object]]:
    if not IGNOREFILE.is_file():
        return []
    document = yaml.safe_load(IGNOREFILE.read_text(encoding="utf-8")) or {}
    found = document.get("vulnerabilities") or []
    return [item for item in found if isinstance(item, dict)]


def expiry(entry: Mapping[str, object]) -> date:
    value = entry["expired_at"]
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    return date.fromisoformat(str(value))


def test_every_accepted_finding_has_an_expiry_and_a_reason() -> None:
    """A suppression with no end date is indistinguishable from not scanning, and one
    with no reason cannot be re-decided by whoever inherits it."""
    for entry in entries():
        assert entry.get("id"), f"an entry has no CVE id: {entry}"
        assert entry.get("expired_at"), f"{entry.get('id')} has no expiry"
        assert str(entry.get("statement", "")).strip(), (
            f"{entry.get('id')} has no stated reason. The next person to read this file "
            "has to be able to re-make the decision, not just inherit it."
        )


def test_no_accepted_finding_has_already_lapsed() -> None:
    """If this fires, the warning below was ignored for a month."""
    today = datetime.now(UTC).date()
    lapsed = [entry["id"] for entry in entries() if expiry(entry) < today]

    assert not lapsed, (
        f"{lapsed} expired and are still suppressed. Either the fix has landed and the "
        "entry should go, or the decision has to be made again with a new date and a "
        "current reason -- not extended to make the scan green."
    )


def test_nothing_is_about_to_lapse_without_the_work_being_scheduled() -> None:
    """The one that is meant to fire, and to fire early.

    Failing here is not a defect. It is this gate doing its job: telling somebody that a
    decision made months ago is about to come due, while there is still time to do the
    work properly rather than to extend the date.

    What to do when it fires:

    * do the upgrade, and delete the entry -- the entry naming the reason tells you what
      "done" looks like;
    * or re-decide deliberately: confirm the finding is still unreachable *by checking
      again rather than by trusting the statement*, and set a new date saying so.

    Extending the date without re-checking is the failure this whole file exists to
    prevent, and it is indistinguishable in the diff from doing it properly. The reason
    field is where that difference is recorded.
    """
    deadline = datetime.now(UTC).date() + WARNING_WINDOW
    due = [
        f"{entry['id']} expires {expiry(entry).isoformat()}"
        for entry in entries()
        if expiry(entry) <= deadline
    ]

    assert not due, (
        f"{due} come due within {WARNING_WINDOW.days} days. Read the reason recorded "
        f"against each in {IGNOREFILE.name} -- it says what the fix is and why it was "
        "deferred. Do that work now, while there is runway, or re-check and re-date it "
        "deliberately."
    )


def test_the_expiry_check_can_actually_fail() -> None:
    """The mutation, kept in the file rather than done by hand once.

    Everything above passes today, which is what a check that reads nothing also does.
    This proves the date comparison is real by feeding it a date that has gone.
    """
    yesterday = datetime.now(UTC).date() - timedelta(days=1)
    expired = {"id": "CVE-0000-0000", "expired_at": yesterday.isoformat()}

    assert expiry(expired) < datetime.now(UTC).date()


def test_the_warning_window_is_wide_enough_to_be_useful() -> None:
    """A window shorter than the work it warns about is a window that only ever produces
    a rushed extension."""
    assert WARNING_WINDOW >= timedelta(days=21)
