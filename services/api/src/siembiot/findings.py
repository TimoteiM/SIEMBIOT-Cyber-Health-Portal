"""Findings for a domain.

A score answers "how are we doing". This answers "what is actually wrong", which is
the only one anybody can act on. The two are served together deliberately: a list of
weaknesses without the coverage it was drawn from invites the reader to assume the list
is complete, and it may not be.

Reads are authorized with `ASSESSMENT_READ`. A separate `FINDING_READ` would be granted
to exactly the roles that already hold it -- every role that can see a score can see
what produced it -- so it would add a name without adding a boundary.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import Connection, text
from sqlalchemy.engine import RowMapping

from siembiot.auth import current_principal
from siembiot.authorization import Action
from siembiot.check_metadata import CheckMetadata, load_check_metadata
from siembiot.contracts import (
    DomainFindingsResponse,
    FindingConfidenceResponse,
    FindingResponse,
    FindingSummaryResponse,
)
from siembiot.db import Database
from siembiot.errors import AppError
from siembiot.identity import Principal
from siembiot.organizations import authorize

#: Most urgent first. Severity is not alphabetical and not a number in the database, so
#: the ordering lives here rather than in the query.
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "informational")
_SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}


def _database(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def _latest_assessment(connection: Connection, domain_id: UUID) -> dict[str, Any] | None:
    """The most recent assessment that produced a score for this domain.

    A run that failed before scoring is not the answer to "how is this domain doing",
    so the join to the snapshot is inner: no snapshot, not the latest result.
    """
    row = (
        connection.execute(
            text(
                """
                SELECT a.id, a.methodology_version, s.score, s.band, s.coverage_percentage
                FROM assessments a
                JOIN score_snapshots s
                    ON s.assessment_id = a.id AND s.is_projection = false
                WHERE a.domain_id = :domain_id
                ORDER BY a.created_at DESC
                LIMIT 1
                """
            ),
            {"domain_id": domain_id},
        )
        .mappings()
        .one_or_none()
    )
    return dict(row) if row is not None else None


def _finding_response(row: RowMapping, metadata: Mapping[str, CheckMetadata]) -> FindingResponse:
    check_id = str(row["check_id"])
    # A check the catalog no longer describes still has to render. Dropping it would
    # quietly shorten the list, and a shorter list of weaknesses is the one mistake
    # this screen must never make. Falling back to the identifier is honest about what
    # is missing without hiding that something is there.
    entry = metadata.get(check_id)
    return FindingResponse(
        id=row["id"],
        check_id=check_id,
        check_version=str(row["check_version"]),
        methodology_version=str(row["methodology_version"]),
        pillar=str(row["pillar"]),
        pillar_letter=entry.pillar_letter if entry else "?",
        severity=row["severity"],
        state=row["state"],
        subject_kind=str(row["subject_kind"]),
        subject_identifier=str(row["subject_identifier"]),
        reason_code=row["reason_code"],
        title_ro=entry.title_ro if entry else check_id,
        title_en=entry.title_en if entry else check_id,
        rationale_ro=entry.rationale_ro if entry else "",
        rationale_en=entry.rationale_en if entry else "",
        remediation_template=entry.remediation_template if entry else None,
        references=list(entry.references) if entry else [],
        confidence=FindingConfidenceResponse(
            attribution=float(row["attribution_confidence"]),
            source=float(row["source_confidence"]),
            freshness=float(row["freshness_confidence"]),
        ),
        first_seen_at=row["first_seen_at"],
        last_seen_at=row["last_seen_at"],
        resolved_at=row["resolved_at"],
        evidence_count=len(row["evidence_observation_ids"] or []),
    )


def build_findings_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/organizations", tags=["findings"])

    @router.get(
        "/{organization_id}/domains/{domain_id}/findings",
        response_model=DomainFindingsResponse,
    )
    def index(
        organization_id: UUID,
        domain_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
        include_resolved: bool = Query(
            default=False,
            description=(
                "Resolved findings are excluded by default: the question is normally "
                "what is wrong now, and a list mixing fixed with unfixed reads as "
                "longer than the problem actually is."
            ),
        ),
    ) -> DomainFindingsResponse:
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

            rows = [
                row
                for row in connection.execute(
                    text(
                        """
                        SELECT id, check_id, check_version, methodology_version, pillar,
                               severity, state, subject_kind, subject_identifier,
                               reason_code, attribution_confidence, source_confidence,
                               freshness_confidence, first_seen_at, last_seen_at,
                               resolved_at, evidence_observation_ids
                        FROM findings
                        WHERE authorized_domain_id = :domain_id
                          AND (:include_resolved OR state <> 'resolved')
                        """
                    ),
                    {"domain_id": domain_id, "include_resolved": include_resolved},
                ).mappings()
            ]

            latest = _latest_assessment(connection, domain_id)

        # The catalog is read outside the transaction: it is a file on disk, and
        # holding a database connection open while parsing JSON serves nobody.
        version = str(latest["methodology_version"]) if latest else "1.0.0"
        metadata = load_check_metadata(version)

        findings = [_finding_response(row, metadata) for row in rows]
        # Most urgent first, then by check identifier so the order is stable between
        # requests -- a list that reshuffles is one a reader cannot scan twice.
        findings.sort(key=lambda item: (_SEVERITY_RANK.get(item.severity, 99), item.check_id))

        by_severity = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        return DomainFindingsResponse(
            domain_id=domain_id,
            assessment_id=latest["id"] if latest else None,
            methodology_version=str(latest["methodology_version"]) if latest else None,
            score=float(latest["score"]) if latest and latest["score"] is not None else None,
            band=str(latest["band"]) if latest and latest["band"] else None,
            coverage_percentage=(
                float(latest["coverage_percentage"])
                if latest and latest["coverage_percentage"] is not None
                else None
            ),
            summary=FindingSummaryResponse(
                total=len(findings),
                open=sum(1 for item in findings if item.state in {"open", "regressed"}),
                by_severity=by_severity,
            ),
            findings=findings,
        )

    return router
