"""Cadence arithmetic and verification expiry.

The failure that matters here is silent: a domain that quietly stops being monitored
looks exactly like a domain with nothing wrong. So these tests care less about the
happy path than about the ways a schedule can stop firing without anybody noticing.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from siembiot_worker.scheduling import (
    CADENCE_INTERVALS,
    CADENCE_OFF,
    SCHEDULE_BATCH_SIZE,
    SchedulingError,
    advance_from,
    next_run_after,
)

NOW = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)


def test_every_offered_cadence_has_an_interval() -> None:
    """A cadence the database accepts but the worker cannot interpret would be stored,
    displayed, and never fire."""
    accepted = {"daily", "weekly", "monthly", "quarterly"}
    assert set(CADENCE_INTERVALS) == accepted


@pytest.mark.parametrize("cadence", ["daily", "weekly", "monthly", "quarterly"])
def test_a_cadence_schedules_into_the_future(cadence: str) -> None:
    scheduled = next_run_after(cadence, NOW)
    assert scheduled is not None and scheduled > NOW


def test_switching_off_schedules_nothing() -> None:
    """'off' is a decision, and the database refuses a next_run_at alongside it."""
    assert next_run_after(CADENCE_OFF, NOW) is None
    assert advance_from(CADENCE_OFF, NOW, NOW) is None


def test_an_unknown_cadence_is_refused_rather_than_defaulted() -> None:
    """Defaulting would turn a typo into a domain assessed on the wrong rhythm, with
    nothing anywhere saying so."""
    with pytest.raises(SchedulingError):
        next_run_after("fortnightly", NOW)


# -- catching up ------------------------------------------------------------


def test_a_run_that_starts_late_does_not_drag_the_next_one_late() -> None:
    """Anchored to the schedule, not to the clock.

    A daily run that fires forty minutes late should still be due at the same time
    tomorrow; otherwise the slot drifts a little further each day until a domain
    scheduled for the morning is being assessed at night.
    """
    due = NOW
    started_late = NOW + timedelta(minutes=40)
    assert advance_from("daily", due, started_late) == due + timedelta(days=1)


def test_a_missed_week_does_not_fire_a_week_of_backlog() -> None:
    """The other direction, which is the one that hurts somebody else.

    If the worker was down for a week, replaying every missed slot would send seven
    days of runs at one domain in a single pass. Catch up to the next slot instead.
    """
    due = NOW
    resumed = NOW + timedelta(days=7)
    following = advance_from("daily", due, resumed)
    assert following is not None
    assert following == resumed + timedelta(days=1)
    assert following > resumed


def test_catching_up_never_schedules_in_the_past() -> None:
    """A next_run_at already behind now would make every pass think it is due."""
    for cadence in CADENCE_INTERVALS:
        for lateness in (timedelta(0), timedelta(days=1), timedelta(days=400)):
            resumed = NOW + lateness
            following = advance_from(cadence, NOW, resumed)
            assert following is not None and following > resumed


def test_the_batch_is_bounded() -> None:
    """A bound, not a policy: the remainder waits for the next pass, so a backlog
    drains steadily instead of arriving as one burst against many targets."""
    assert 0 < SCHEDULE_BATCH_SIZE <= 100
