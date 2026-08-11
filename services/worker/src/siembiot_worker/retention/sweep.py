"""Applying the retention schedule.

Deliberately dull. This deletes tenant data on a timer, so the qualities worth having
are boring ones: it only ever touches tables the schedule names, it works in bounded
batches so a first run against years of accumulation cannot hold a lock for an hour, and
a partial run is safe because the next one finishes the job.

The one interesting step is the last: after observations are removed, every score
computed from them is stamped `evidence_erased_at`. Deleting the workings and leaving
the conclusion looking checkable is the version of this feature that would mislead
people, so it is done in the same transaction as the deletion that caused it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text

from siembiot_worker.retention.policy import SWEPT_TABLES, TableRetention

log = logging.getLogger("siembiot.retention")

#: Rows removed per statement. A first sweep against a long-neglected database can face
#: millions of rows, and one unbounded DELETE would hold locks for the length of it.
#: Repeating a small statement is slower in total and never blocks anything for long.
BATCH_SIZE = 5_000

#: How many batches one table gets per run. Whatever is left waits for the next sweep,
#: which is the point of running it on a schedule rather than to completion.
MAX_BATCHES = 200

#: The table whose removal makes a score unreproducible.
OBSERVATION_TABLE = "normalized_observations"


@dataclass
class SweepResult:
    removed: dict[str, int] = field(default_factory=dict)
    snapshots_marked: int = 0
    incomplete: tuple[str, ...] = ()

    @property
    def total(self) -> int:
        return sum(self.removed.values())


def _delete_batches(
    connection: Any, entry: TableRetention, now: datetime, collect: str | None = None
) -> tuple[int, bool, set[str]]:
    """Remove aged rows from one table. Returns how many, whether it finished, and --
    where `collect` names a column -- the distinct values it removed.

    The identifier is interpolated because a table name cannot be a bind parameter --
    and it is safe here for a reason worth stating rather than assuming: `entry` comes
    from the schedule in this repository, never from a request. A test asserts every
    swept table is one the database actually has, so a typo fails there instead of
    becoming a strange query at three in the morning.
    """
    if entry.age_column is None or entry.period is None:
        # Unreachable via SWEPT_TABLES, which filters on exactly this. Raised rather
        # than asserted because an assertion disappears under -O, and the failure it
        # would leave behind is a DELETE with no WHERE clause.
        raise ValueError(f"{entry.table} is not a swept table")
    cutoff = now - entry.period
    removed = 0
    collected: set[str] = set()
    returning = f" RETURNING {collect}" if collect else ""

    for _ in range(MAX_BATCHES):
        result = connection.execute(
            text(
                f"""
                DELETE FROM {entry.table}
                WHERE ctid IN (
                    SELECT ctid FROM {entry.table}
                    WHERE {entry.age_column} < :cutoff
                    LIMIT :batch
                ){returning}
                """  # noqa: S608 - identifiers come from the schedule, never from input
            ),
            {"cutoff": cutoff, "batch": BATCH_SIZE},
        )
        if collect:
            rows = result.fetchall()
            collected.update(str(row[0]) for row in rows)
            deleted = len(rows)
        else:
            deleted = result.rowcount
        removed += deleted
        if deleted < BATCH_SIZE:
            return removed, True, collected
    return removed, False, collected


def _mark_erased_snapshots(connection: Any, orphaned: set[str], now: datetime) -> int:
    """Stamp the scores whose evidence this sweep removed.

    Only those. The first version asked the more general question -- "which snapshots
    have no observations?" -- so that evidence removed by any other route would also be
    marked. Run against a real database it immediately stamped two assessments that had
    never produced observations at all, declaring evidence erased that was never
    collected. A report saying "the evidence was removed under retention" about a run
    that never had any is a worse lie than the silence it replaced.

    So the claim is now made only where it is true by construction: these are the
    assessments this transaction deleted observations from, and they have none left.
    """
    if not orphaned:
        return 0

    marked = connection.execute(
        text(
            """
            UPDATE score_snapshots AS s
            SET evidence_erased_at = :now
            WHERE s.evidence_erased_at IS NULL
              AND s.assessment_id = ANY(CAST(:assessment_ids AS uuid[]))
              AND NOT EXISTS (
                  SELECT 1 FROM normalized_observations o
                  WHERE o.assessment_id = s.assessment_id
              )
            """
        ),
        {"now": now, "assessment_ids": sorted(orphaned)},
    ).rowcount
    return int(marked)


def sweep_retention(connection: Any, now: datetime | None = None) -> SweepResult:
    """Apply the schedule once.

    Everything happens in the caller's transaction: the deletions and the stamping of
    the snapshots they orphaned are one atomic change, so there is no window in which
    the workings are gone and the score still claims to be checkable.
    """
    moment = now or datetime.now(UTC)

    # Declare the sweep before touching anything. The evidence tables carry append-only
    # triggers, and this is the single exception they permit: without it every delete
    # below is refused. It is asked for explicitly and per transaction so that removal is
    # deliberate -- a stray DELETE elsewhere in the codebase still fails, whatever grants
    # it happens to hold.
    connection.execute(text("SELECT set_config('app.retention_sweep', 'on', true)"))

    result = SweepResult()
    incomplete: list[str] = []

    orphaned: set[str] = set()
    for entry in SWEPT_TABLES:
        # Only the observation sweep reports what it took, and only so the scores that
        # depended on it can be told the truth afterwards.
        collect = "assessment_id" if entry.table == OBSERVATION_TABLE else None
        removed, finished, collected = _delete_batches(connection, entry, moment, collect)
        orphaned |= collected
        if removed:
            result.removed[entry.table] = removed
        if not finished:
            # Reported rather than retried here. A table with more than a batch limit of
            # expired rows is either a first run or a sign that the schedule is not
            # keeping up, and both are things somebody should see.
            incomplete.append(entry.table)
            log.warning("retention sweep incomplete for %s", entry.table)

    result.incomplete = tuple(incomplete)
    result.snapshots_marked = _mark_erased_snapshots(connection, orphaned, moment)
    return result


def record_run(connection: Any, result: SweepResult, error: str | None = None) -> None:
    """Write down what this sweep removed.

    Counts per table, never identifiers: a permanent list of what was erased would
    defeat the erasure. Written even when nothing was removed, because "the job ran and
    found nothing" and "the job did not run" are different facts and only one of them
    needs investigating.
    """
    connection.execute(
        text(
            """
            INSERT INTO retention_runs (finished_at, removed, error)
            VALUES (now(), CAST(:removed AS jsonb), :error)
            """
        ),
        {
            "removed": _as_json(
                {
                    **result.removed,
                    "_snapshots_marked": result.snapshots_marked,
                    **({"_incomplete": len(result.incomplete)} if result.incomplete else {}),
                }
            ),
            "error": error,
        },
    )


def _as_json(payload: dict[str, int]) -> str:
    import json

    return json.dumps(payload, sort_keys=True)
