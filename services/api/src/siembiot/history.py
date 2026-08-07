"""How a domain's posture has moved over time.

Scheduling produces repeated runs; without this they overwrite one another's
impression and nobody can tell whether anything improved. It also closes the loop on
remediation: somebody who follows the DMARC guidance should be able to see that it
worked, and until now there was no screen that could say so.

The load-bearing idea here is **comparability**. Two scores are only comparable when
both runs saw about the same amount, because the score is an average over what was
evaluated. A run that reached less of the surface can score higher while the domain
got worse, and a chart that draws both as points on one line asserts a comparison the
evidence does not support.

So a delta is always accompanied by the coverage delta and by a flag saying whether
reading it as progress is justified. The numbers are still reported when it is not:
hiding them would replace a misleading answer with no answer, and the reader can judge
once they know what moved.
"""

from __future__ import annotations

from typing import cast
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import Connection, text
from sqlalchemy.engine import RowMapping

from siembiot.auth import current_principal
from siembiot.authorization import Action
from siembiot.check_metadata import CheckMetadata, load_check_metadata
from siembiot.contracts import (
    ASSESSMENT_MODES,
    FINDING_SEVERITIES,
    AssessmentChangeResponse,
    DomainHistoryResponse,
    FindingChangeResponse,
    HistoryPointResponse,
)
from siembiot.db import Database
from siembiot.errors import AppError
from siembiot.identity import Principal
from siembiot.organizations import authorize

#: How far coverage may move between two runs before their scores stop describing the
#: same question. Ten points is a judgement, not a derivation: below it the average is
#: over broadly the same checks, above it the two runs looked at materially different
#: surfaces and the difference in score is mostly the difference in what was seen.
COVERAGE_COMPARABLE_DELTA = 10.0

#: A timeline long enough to show a trend without becoming a data export. Older runs
#: remain in the database; this endpoint answers "how are we doing lately".
DEFAULT_HISTORY_LIMIT = 30


def _database(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def _points(connection: Connection, domain_id: UUID, limit: int) -> list[RowMapping]:
    """Completed runs that produced a score, newest first.

    Runs that never scored are absent rather than plotted as zero: a failed collection
    is not a posture of nought, and a chart that dips to the floor whenever the network
    misbehaved would teach people to distrust the chart.
    """
    return list(
        connection.execute(
            text(
                """
                SELECT a.id AS assessment_id, a.completed_at, a.mode, a.methodology_version,
                       s.score, s.band, s.coverage_percentage, s.coverage_sufficient
                FROM assessments a
                JOIN score_snapshots s
                    ON s.assessment_id = a.id AND s.is_projection = false
                WHERE a.domain_id = :domain_id
                  AND a.completed_at IS NOT NULL
                  AND s.score IS NOT NULL
                ORDER BY a.completed_at DESC
                LIMIT :limit
                """
            ),
            {"domain_id": domain_id, "limit": limit},
        ).mappings()
    )


def _transitions(
    connection: Connection, assessment_id: UUID
) -> tuple[list[RowMapping], list[RowMapping]]:
    """What opened and what resolved at one assessment.

    Read from `finding_history` rather than by comparing two lists of findings. The
    history is what the worker recorded at the moment it decided, so it stays right
    even when a finding has changed state several times since.
    """
    rows = list(
        connection.execute(
            text(
                """
                SELECT h.from_state, h.to_state, f.check_id, f.severity
                FROM finding_history h
                JOIN findings f ON f.id = h.finding_id
                WHERE h.assessment_id = :assessment_id
                ORDER BY f.severity, f.check_id
                """
            ),
            {"assessment_id": assessment_id},
        ).mappings()
    )
    opened = [row for row in rows if row["to_state"] in {"open", "regressed"}]
    resolved = [row for row in rows if row["to_state"] == "resolved"]
    return opened, resolved


def _change_entry(row: RowMapping, metadata: dict[str, CheckMetadata]) -> FindingChangeResponse:
    check_id = str(row["check_id"])
    entry = metadata.get(check_id)
    return FindingChangeResponse(
        check_id=check_id,
        severity=cast(FINDING_SEVERITIES, row["severity"]),
        title_ro=entry.title_ro if entry else check_id,
        title_en=entry.title_en if entry else check_id,
    )


def _comparability(previous: RowMapping, current: RowMapping) -> tuple[bool, str | None]:
    """Whether two runs answered the same question closely enough to be compared."""
    if not previous["coverage_sufficient"] or not current["coverage_sufficient"]:
        # Below the floor the methodology already refuses to present a band. Comparing
        # against a run it would not report on its own is worse than not comparing.
        return False, "insufficient_coverage"
    delta = abs(float(current["coverage_percentage"]) - float(previous["coverage_percentage"]))
    if delta > COVERAGE_COMPARABLE_DELTA:
        return False, "coverage_moved"
    return True, None


def build_history_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/organizations", tags=["history"])

    @router.get(
        "/{organization_id}/domains/{domain_id}/history",
        response_model=DomainHistoryResponse,
    )
    def index(
        organization_id: UUID,
        domain_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
        limit: int = Query(default=DEFAULT_HISTORY_LIMIT, ge=2, le=200),
    ) -> DomainHistoryResponse:
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.ASSESSMENT_READ)

            domain = connection.execute(
                text(
                    "SELECT id FROM domains WHERE id = :domain_id "
                    "AND organization_id = :organization_id"
                ),
                {"domain_id": domain_id, "organization_id": organization_id},
            ).scalar_one_or_none()
            if domain is None:
                raise AppError(404, "not_found", "The requested resource was not found.")

            newest_first = _points(connection, domain_id, limit)
            change_rows: tuple[list[RowMapping], list[RowMapping]] | None = None
            if len(newest_first) >= 2:
                change_rows = _transitions(connection, newest_first[0]["assessment_id"])
                unchanged = connection.execute(
                    text(
                        """
                        SELECT count(*) FROM findings
                        WHERE authorized_domain_id = :domain_id
                          AND state IN ('open', 'regressed')
                          AND first_seen_at < :since
                        """
                    ),
                    {"domain_id": domain_id, "since": newest_first[0]["completed_at"]},
                ).scalar_one()
            else:
                unchanged = 0

        metadata = load_check_metadata(
            str(newest_first[0]["methodology_version"]) if newest_first else "1.0.0"
        )

        points = [
            HistoryPointResponse(
                assessment_id=row["assessment_id"],
                completed_at=row["completed_at"],
                mode=cast(ASSESSMENT_MODES, row["mode"]),
                methodology_version=str(row["methodology_version"]),
                score=float(row["score"]),
                band=str(row["band"]),
                coverage_percentage=float(row["coverage_percentage"]),
                coverage_sufficient=bool(row["coverage_sufficient"]),
            )
            # Oldest first: a chart reads left to right, and reversing in every client
            # is work the server can do once.
            for row in reversed(newest_first)
        ]

        change = None
        if len(newest_first) >= 2 and change_rows is not None:
            current, previous = newest_first[0], newest_first[1]
            comparable, reason = _comparability(previous, current)
            opened, resolved = change_rows
            change = AssessmentChangeResponse(
                previous_assessment_id=previous["assessment_id"],
                current_assessment_id=current["assessment_id"],
                score_delta=round(float(current["score"]) - float(previous["score"]), 2),
                coverage_delta=round(
                    float(current["coverage_percentage"]) - float(previous["coverage_percentage"]),
                    2,
                ),
                comparable=comparable,
                incomparable_reason=reason,
                resolved=[_change_entry(row, metadata) for row in resolved],
                opened=[_change_entry(row, metadata) for row in opened],
                unchanged_count=int(unchanged),
            )

        return DomainHistoryResponse(domain_id=domain_id, points=points, change=change)

    return router
