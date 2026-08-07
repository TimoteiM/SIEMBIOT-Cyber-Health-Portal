"""Writing the projection: the only code in the product that publishes anything.

Kept deliberately small and in one place. Everything it needs in order to refuse has
already been decided elsewhere -- the catalogue says which checks are publishable, the
review table says whether anybody approved publishing at all, the consent row says
whether this organization agreed -- and this module's job is to ask all of them and then
write the handful of columns that survive.

It runs as the owner. The API cannot reach these inserts (it is granted DELETE on
profiles and nothing more), so the dangerous direction has exactly one caller.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Connection, text

from siembiot.publication.projection import Profile, ProjectionRefusedError, project_profile
from siembiot.publication.review import require_approved_review


def _assessment_inputs(connection: Connection, domain_id: UUID) -> dict[str, object] | None:
    """The most recent completed assessment for a domain, and what it decided.

    Returns None where there is nothing to publish yet, which is an ordinary state and
    not an error: a domain can be consented to long before it has ever been assessed.
    """
    snapshot = (
        connection.execute(
            text(
                """
                SELECT s.band, s.coverage_percentage, s.coverage_sufficient,
                       s.methodology_version, s.policy_digest, a.completed_at,
                       a.id AS assessment_id
                FROM score_snapshots s
                JOIN assessments a ON a.id = s.assessment_id
                WHERE a.domain_id = :domain_id
                  AND a.state IN ('completed', 'partially_completed')
                  -- Projections are what-if scores: what the domain would have scored
                  -- had something been fixed. Publishing one would put a result on a
                  -- public page that was never measured about anybody.
                  AND s.is_projection = false
                ORDER BY a.completed_at DESC
                LIMIT 1
                """
            ),
            {"domain_id": domain_id},
        )
        .mappings()
        .one_or_none()
    )
    if snapshot is None:
        return None

    evaluations = connection.execute(
        text("SELECT check_id, result FROM check_evaluations WHERE assessment_id = :assessment_id"),
        {"assessment_id": snapshot["assessment_id"]},
    ).mappings()

    return {
        "band": snapshot["band"],
        "coverage_percentage": float(snapshot["coverage_percentage"]),
        "coverage_sufficient": bool(snapshot["coverage_sufficient"]),
        "methodology_version": str(snapshot["methodology_version"]),
        "policy_digest": str(snapshot["policy_digest"]),
        "observed_at": snapshot["completed_at"],
        "evaluations": {str(row["check_id"]): str(row["result"]) for row in evaluations},
    }


def publish_domain(connection: Connection, domain_id: UUID) -> Profile | None:
    """Project one domain into the observatory, or refuse.

    Returns None when there is simply nothing to publish yet. Refusals -- no consent,
    unverified control, a takedown, no approved review -- raise, because each of those
    is a decision somebody made and silently doing nothing would hide it.
    """
    domain = (
        connection.execute(
            text(
                """
                SELECT d.registrable_domain, d.ownership_state,
                       EXISTS (
                           SELECT 1 FROM publication_consents c
                           WHERE c.domain_id = d.id AND c.revoked_at IS NULL
                       ) AS has_active_consent,
                       EXISTS (
                           SELECT 1 FROM publication_takedowns t
                           WHERE t.registrable_domain = d.registrable_domain
                       ) AS is_taken_down
                FROM domains d
                WHERE d.id = :domain_id
                """
            ),
            {"domain_id": domain_id},
        )
        .mappings()
        .one_or_none()
    )
    if domain is None:
        raise ProjectionRefusedError(f"{domain_id}: no such domain")

    inputs = _assessment_inputs(connection, domain_id)
    if inputs is None:
        return None

    # Before anything is projected. Approving publication under one methodology and
    # catalogue does not approve it under the ones that replace them, so this is checked
    # against the digest the assessment actually ran with rather than the current one.
    require_approved_review(
        connection,
        methodology_version=str(inputs["methodology_version"]),
        policy_digest=str(inputs["policy_digest"]),
    )

    profile = project_profile(
        registrable_domain=str(domain["registrable_domain"]),
        ownership_state=str(domain["ownership_state"]),
        has_active_consent=bool(domain["has_active_consent"]),
        is_taken_down=bool(domain["is_taken_down"]),
        band=inputs["band"],  # type: ignore[arg-type]
        coverage_sufficient=bool(inputs["coverage_sufficient"]),
        coverage_percentage=float(inputs["coverage_percentage"]),  # type: ignore[arg-type]
        methodology_version=str(inputs["methodology_version"]),
        policy_digest=str(inputs["policy_digest"]),
        observed_at=inputs["observed_at"],  # type: ignore[arg-type]
        evaluations=inputs["evaluations"],  # type: ignore[arg-type]
    )
    _write(connection, profile)
    return profile


def _write(connection: Connection, profile: Profile) -> None:
    """Replace the published profile, checks and all.

    The per-check rows are deleted and rewritten rather than merged, so a check that
    stops being reported -- because it was reclassified as private, or because the
    latest run could not evaluate it -- disappears from the public page instead of
    lingering as the last thing that was true about it.
    """
    profile_id = connection.execute(
        text(
            """
            INSERT INTO observatory.profiles (
                registrable_domain, band, coverage_percentage,
                methodology_version, policy_digest, observed_at
            ) VALUES (
                :registrable_domain, :band, :coverage_percentage,
                :methodology_version, :policy_digest, :observed_at
            )
            ON CONFLICT (registrable_domain) DO UPDATE SET
                band = excluded.band,
                coverage_percentage = excluded.coverage_percentage,
                methodology_version = excluded.methodology_version,
                policy_digest = excluded.policy_digest,
                observed_at = excluded.observed_at,
                published_at = now()
            RETURNING id
            """
        ),
        {
            "registrable_domain": profile.registrable_domain,
            "band": profile.band,
            "coverage_percentage": profile.coverage_percentage,
            "methodology_version": profile.methodology_version,
            "policy_digest": profile.policy_digest,
            "observed_at": profile.observed_at,
        },
    ).scalar_one()

    connection.execute(
        text("DELETE FROM observatory.profile_checks WHERE profile_id = :profile_id"),
        {"profile_id": profile_id},
    )
    for check in profile.checks:
        connection.execute(
            text(
                "INSERT INTO observatory.profile_checks (profile_id, check_id, result) "
                "VALUES (:profile_id, :check_id, :result)"
            ),
            {"profile_id": profile_id, "check_id": check.check_id, "result": check.result},
        )


def withdraw_domain(connection: Connection, registrable_domain: str) -> bool:
    """Take a profile down. Returns whether there was one."""
    removed = connection.execute(
        text("DELETE FROM observatory.profiles WHERE registrable_domain = :registrable_domain"),
        {"registrable_domain": registrable_domain},
    ).rowcount
    return bool(removed)


def last_published_at(connection: Connection, registrable_domain: str) -> datetime | None:
    return connection.execute(
        text(
            "SELECT published_at FROM observatory.profiles "
            "WHERE registrable_domain = :registrable_domain"
        ),
        {"registrable_domain": registrable_domain},
    ).scalar_one_or_none()
