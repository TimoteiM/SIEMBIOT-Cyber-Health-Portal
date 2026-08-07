"""Turning a cadence into runs, and letting a verification expire.

Two jobs the platform was missing, and they fail in opposite directions, so each is
written to fail the safe way.

**Creating due runs.** Getting this wrong twice over means either a domain silently
stops being monitored, or the same domain is assessed repeatedly. The first is worse
and quieter: nobody notices an absence. So `next_run_at` advances only after a run has
actually been created, and the due query refuses to stack a second run on a domain that
still has one in flight.

**Expiring a verification.** Control of a domain is the fact most likely to have
changed since anyone last looked, and a proof that never expires is not a proof of
anything current. Expiry moves the domain to `reverification_required`, which is a
prompt rather than a punishment: passive observation continues, because it never needed
proof of control, while authorized assessment stops until a person re-verifies.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

#: How far ahead each cadence schedules. Months are approximated in days on purpose:
#: the product promise is "about monthly", and calendar arithmetic would drift a run
#: onto the 31st and then skip February without anybody intending it.
CADENCE_INTERVALS: dict[str, timedelta] = {
    "daily": timedelta(days=1),
    "weekly": timedelta(days=7),
    "monthly": timedelta(days=30),
    "quarterly": timedelta(days=91),
}

CADENCE_OFF = "off"

#: How many schedules one pass will start. Anything left over waits for the next pass,
#: so a backlog drains steadily instead of arriving as one burst against many targets.
SCHEDULE_BATCH_SIZE = 25


class SchedulingError(ValueError):
    pass


def next_run_after(cadence: str, moment: datetime) -> datetime | None:
    """When a schedule should next fire, or None when it is switched off."""
    if cadence == CADENCE_OFF:
        return None
    interval = CADENCE_INTERVALS.get(cadence)
    if interval is None:
        raise SchedulingError(f"unknown cadence {cadence!r}")
    return moment + interval


def advance_from(cadence: str, previous: datetime, now: datetime) -> datetime | None:
    """The next firing time after a run that was due at `previous`.

    Anchored to the schedule rather than to the clock, so a run that starts late does
    not push every later run late with it. But a schedule that has been paused, or a
    worker that was down for a week, must not then fire a week's worth of backlog at
    somebody's DNS -- so anything already in the past is caught up to the next slot
    from now instead of replayed.
    """
    interval = CADENCE_INTERVALS.get(cadence)
    if cadence == CADENCE_OFF or interval is None:
        return None
    candidate = previous + interval
    if candidate > now:
        return candidate
    return now + interval


@dataclass(frozen=True)
class DueSchedule:
    schedule_id: UUID
    organization_id: UUID
    domain_id: UUID
    host: str
    mode: str


def due_schedules(connection: Any, limit: int = SCHEDULE_BATCH_SIZE) -> tuple[DueSchedule, ...]:
    """Schedules that should start a run now.

    The whole decision -- cadence, quiet hours, ownership state, no run already in
    flight -- lives in `app_due_schedules`, so it is applied identically no matter who
    asks, and so it can be read in one place during review.
    """
    from sqlalchemy import text

    rows = connection.execute(
        text("SELECT * FROM app_due_schedules(:limit)"), {"limit": limit}
    ).mappings()
    return tuple(
        DueSchedule(
            schedule_id=row["schedule_id"],
            organization_id=row["organization_id"],
            domain_id=row["domain_id"],
            host=row["host"],
            mode=row["mode"],
        )
        for row in rows
    )


def expire_stale_verifications(connection: Any, now: datetime | None = None) -> int:
    """Move domains past their re-verification date out of the verified state.

    Returns how many were moved. Only `verified` domains are touched: a domain that
    was revoked, or has already been asked to re-verify, is in a state somebody chose
    and this must not overwrite it.
    """
    from sqlalchemy import text

    result = connection.execute(
        text(
            """
            UPDATE domains
            SET ownership_state = 'reverification_required',
                updated_at = now()
            WHERE ownership_state = 'verified'
              AND reverification_due_at IS NOT NULL
              AND reverification_due_at <= :now
            """
        ),
        {"now": now or datetime.now(UTC)},
    )
    return int(result.rowcount or 0)
