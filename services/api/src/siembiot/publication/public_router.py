"""The unauthenticated read side of the observatory.

Every other route in this service resolves a principal, sets a tenant context and relies
on row-level security. These routes have none of that, and must not need it: they are
served by a connection that cannot reach tenant data at all. If that connection were the
application's, the schema boundary would still exist in the database and mean nothing in
practice, so the app refuses to serve these routes from anything that has USAGE on the
schema holding tenant tables.

Absent configuration, they are not mounted. A deployment that has not thought about
publication publishes nothing, rather than publishing through whatever connection was
already open.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from fastapi import APIRouter, Query, Request
from sqlalchemy import text

from siembiot.check_metadata import CheckMetadata, load_check_metadata
from siembiot.contracts import (
    PUBLISHED_BANDS,
    PUBLISHED_RESULTS,
    ObservatoryAggregateResponse,
    ObservatoryAggregatesResponse,
    ObservatoryListResponse,
    ObservatoryProfileResponse,
    ObservatorySummary,
    PublishedCheckResponse,
)
from siembiot.db import Database
from siembiot.errors import AppError

#: These responses are not cached, and that is a decision rather than an oversight.
#:
#: The first draft of this module set `max-age=60`, which would have made sixty seconds
#: the real answer to "how quickly does a withdrawal take effect" -- the row is deleted
#: synchronously, but a response already handed to a cache is out of our hands until it
#: expires. The service-wide `no-store` (see `request_context`) gives a suppression
#: latency of zero instead, and it applies to these routes for exactly the same reason it
#: applies to private ones.
#:
#: The cost is that every read reaches the database. That is affordable for a read model
#: this small, and making it cacheable later should be a decision somebody takes
#: deliberately, with the latency it reintroduces written down.
MAX_PAGE_SIZE = 100


def _title(metadata: Mapping[str, CheckMetadata], check_id: str) -> tuple[str, str]:
    """The catalogue's own wording, falling back to the identifier.

    A check published under a methodology whose catalogue no longer describes it should
    still render: the identifier is worse than a sentence and much better than a blank.
    """
    entry = metadata.get(check_id)
    if entry is None:
        return check_id, check_id
    return entry.title_ro, entry.title_en


def _database(request: Request) -> Database:
    return cast(Database, request.app.state.public_database)


def build_public_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/public", tags=["observatory"])

    @router.get("/observatory", response_model=ObservatoryListResponse)
    def index(
        request: Request,
        limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
        offset: int = Query(default=0, ge=0),
    ) -> ObservatoryListResponse:
        with _database(request).connection() as connection:
            rows = (
                connection.execute(
                    text(
                        """
                        SELECT registrable_domain, band, coverage_percentage,
                               methodology_version, observed_at, published_at
                        FROM observatory.profiles
                        ORDER BY registrable_domain
                        LIMIT :limit OFFSET :offset
                        """
                    ),
                    {"limit": limit, "offset": offset},
                )
                .mappings()
                .all()
            )
            total = connection.execute(
                text("SELECT count(*) FROM observatory.profiles")
            ).scalar_one()

        return ObservatoryListResponse(
            total=int(total),
            profiles=[
                ObservatorySummary(
                    registrable_domain=str(row["registrable_domain"]),
                    band=cast("PUBLISHED_BANDS | None", row["band"]),
                    coverage_percentage=float(row["coverage_percentage"]),
                    methodology_version=str(row["methodology_version"]),
                    observed_at=row["observed_at"],
                    published_at=row["published_at"],
                )
                for row in rows
            ],
        )

    @router.get("/aggregates", response_model=ObservatoryAggregatesResponse)
    def aggregates(request: Request) -> ObservatoryAggregatesResponse:
        """Cohort statistics that survived the size threshold.

        Declared before the profile route so `/aggregates` is not read as a domain name.
        """
        with _database(request).connection() as connection:
            rows = (
                connection.execute(
                    text(
                        """
                        SELECT DISTINCT ON (check_id, methodology_version)
                               check_id, cohort_size, pass_count,
                               methodology_version, released_at
                        FROM observatory.aggregates
                        ORDER BY check_id, methodology_version, released_at DESC
                        """
                    )
                )
                .mappings()
                .all()
            )

        return ObservatoryAggregatesResponse(
            aggregates=[
                ObservatoryAggregateResponse(
                    check_id=str(row["check_id"]),
                    cohort_size=int(row["cohort_size"]),
                    pass_count=int(row["pass_count"]),
                    methodology_version=str(row["methodology_version"]),
                    released_at=row["released_at"],
                )
                for row in rows
            ]
        )

    @router.get("/observatory/{registrable_domain}", response_model=ObservatoryProfileResponse)
    def profile(registrable_domain: str, request: Request) -> ObservatoryProfileResponse:
        with _database(request).connection() as connection:
            row = (
                connection.execute(
                    text(
                        """
                        SELECT id, registrable_domain, band, coverage_percentage,
                               methodology_version, policy_digest, observed_at, published_at
                        FROM observatory.profiles
                        WHERE registrable_domain = :registrable_domain
                        """
                    ),
                    {"registrable_domain": registrable_domain.lower()},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                # Deliberately the same answer for "never published", "withdrawn" and
                # "no such domain". Distinguishing them would let anybody enumerate
                # which institutions once agreed to publish and later changed their mind,
                # which is a fact about them that they withdrew.
                raise AppError(404, "not_found", "The requested resource was not found.")

            checks = (
                connection.execute(
                    text(
                        "SELECT check_id, result FROM observatory.profile_checks "
                        "WHERE profile_id = :profile_id ORDER BY check_id"
                    ),
                    {"profile_id": row["id"]},
                )
                .mappings()
                .all()
            )

        metadata = load_check_metadata(str(row["methodology_version"]))
        return ObservatoryProfileResponse(
            registrable_domain=str(row["registrable_domain"]),
            band=cast("PUBLISHED_BANDS | None", row["band"]),
            coverage_percentage=float(row["coverage_percentage"]),
            methodology_version=str(row["methodology_version"]),
            policy_digest=str(row["policy_digest"]),
            observed_at=row["observed_at"],
            published_at=row["published_at"],
            checks=[
                PublishedCheckResponse(
                    check_id=str(check["check_id"]),
                    # The column is constrained to exactly these three by a CHECK; the
                    # cast records that the database is the authority, not this line.
                    result=cast(PUBLISHED_RESULTS, check["result"]),
                    title_ro=_title(metadata, str(check["check_id"]))[0],
                    title_en=_title(metadata, str(check["check_id"]))[1],
                )
                for check in checks
            ],
        )

    return router
