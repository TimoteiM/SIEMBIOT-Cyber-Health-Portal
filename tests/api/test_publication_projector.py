"""The projector, against a real database: what actually reaches a public page.

The pure projection is tested elsewhere. This is the wiring -- which assessment it reads,
what it refuses, and what the observatory ends up containing -- because the interesting
mistakes here are in the query rather than in the logic. A projector that reads the wrong
snapshot publishes a real number about a real institution that was never measured.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "api" / "src"))

from siembiot.publication import (  # noqa: E402
    ProjectionRefusedError,
    ReviewMissingError,
    publish_domain,
)

METHODOLOGY = "1.0.0"


def owner_engine(url: str) -> Engine:
    return create_engine(url.replace("postgresql://", "postgresql+psycopg://"))


def seed(
    owner_url: str,
    *,
    ownership_state: str = "verified",
    consent: bool = True,
    digest: str | None = None,
    coverage_sufficient: bool = True,
    band: str = "managed",
    is_projection: bool = False,
    results: dict[str, str] | None = None,
) -> tuple[UUID, str, str]:
    """A domain with one completed assessment, ready to publish unless spoiled."""
    organization_id, user_id, domain_id = uuid4(), uuid4(), uuid4()
    assessment_id, snapshot_id = uuid4(), uuid4()
    host = f"proj-{organization_id.hex[:10]}.example.ro"
    policy_digest = digest or f"{uuid4().hex}{uuid4().hex}"
    now = datetime.now(UTC)
    results = results or {"B.dmarc_enforced": "pass", "F.server_banner_disclosure": "fail"}

    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Ana Popescu')",
            (str(user_id), str(user_id), f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Tenant', %s, %s)",
            (str(organization_id), f"pj-{organization_id.hex[:12]}", str(user_id)),
        )
        owner.execute(
            "INSERT INTO methodology_versions (version, policy_digest, notice) "
            "VALUES (%s, %s, 'test') ON CONFLICT (version) DO NOTHING",
            (METHODOLOGY, "f" * 64),
        )
        owner.execute(
            "INSERT INTO domains (id, organization_id, canonical_name, unicode_display, "
            "registrable_domain, ownership_state, created_by_user_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (
                str(domain_id),
                str(organization_id),
                host,
                host,
                host,
                ownership_state,
                str(user_id),
            ),
        )
        if consent:
            owner.execute(
                "INSERT INTO publication_consents (organization_id, domain_id, "
                "granted_by_user_id) VALUES (%s, %s, %s)",
                (str(organization_id), str(domain_id), str(user_id)),
            )
        owner.execute(
            "INSERT INTO assessments (id, organization_id, domain_id, methodology_version, "
            "state, completed_at) VALUES (%s, %s, %s, %s, 'completed', %s)",
            (str(assessment_id), str(organization_id), str(domain_id), METHODOLOGY, now),
        )
        owner.execute(
            "INSERT INTO score_snapshots (id, organization_id, assessment_id, "
            "methodology_version, is_projection, policy_digest, evidence_digest, "
            "score, band, coverage_percentage, coverage_sufficient, document, computed_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, 72.5, %s, 88.0, %s, '{}', %s)",
            (
                str(snapshot_id),
                str(organization_id),
                str(assessment_id),
                METHODOLOGY,
                is_projection,
                policy_digest,
                "e" * 64,
                band,
                coverage_sufficient,
                now,
            ),
        )
        for check_id, result in results.items():
            owner.execute(
                "INSERT INTO check_evaluations (id, organization_id, assessment_id, check_id, "
                "check_version, methodology_version, pillar, subject_kind, subject_identifier, "
                "result, score_bearing, weight, severity, attribution_confidence, "
                "source_confidence, freshness_confidence, evaluated_at) "
                "VALUES (%s, %s, %s, %s, '1.0.0', %s, 'email', 'domain', %s, %s, %s, 10, "
                "'high', 1.00, 1.00, 1.00, %s)",
                (
                    str(uuid4()),
                    str(organization_id),
                    str(assessment_id),
                    check_id,
                    METHODOLOGY,
                    host,
                    result,
                    result in {"pass", "fail", "warning"},
                    now,
                ),
            )
    return domain_id, host, policy_digest


def add_later_run(
    owner_url: str,
    domain_id: UUID,
    policy_digest: str,
    *,
    results: dict[str, str],
    band: str = "managed",
) -> None:
    """A second completed assessment for the same domain, an hour later."""
    assessment_id, snapshot_id = uuid4(), uuid4()
    when = datetime.now(UTC) + timedelta(hours=1)
    with psycopg.connect(owner_url, autocommit=True) as owner:
        row = owner.execute(
            "SELECT organization_id, registrable_domain FROM domains WHERE id = %s",
            (str(domain_id),),
        ).fetchone()
        assert row is not None
        organization_id, host = row
        owner.execute(
            "INSERT INTO assessments (id, organization_id, domain_id, methodology_version, "
            "state, completed_at) VALUES (%s, %s, %s, %s, 'completed', %s)",
            (str(assessment_id), str(organization_id), str(domain_id), METHODOLOGY, when),
        )
        owner.execute(
            "INSERT INTO score_snapshots (id, organization_id, assessment_id, "
            "methodology_version, is_projection, policy_digest, evidence_digest, score, "
            "band, coverage_percentage, coverage_sufficient, document, computed_at) "
            "VALUES (%s, %s, %s, %s, false, %s, %s, 72.5, %s, 88.0, true, '{}', %s)",
            (
                str(snapshot_id),
                str(organization_id),
                str(assessment_id),
                METHODOLOGY,
                policy_digest,
                "e" * 64,
                band,
                when,
            ),
        )
        for check_id, result in results.items():
            owner.execute(
                "INSERT INTO check_evaluations (id, organization_id, assessment_id, check_id, "
                "check_version, methodology_version, pillar, subject_kind, subject_identifier, "
                "result, score_bearing, weight, severity, attribution_confidence, "
                "source_confidence, freshness_confidence, evaluated_at) "
                "VALUES (%s, %s, %s, %s, '1.0.0', %s, 'email', 'domain', %s, %s, %s, 10, "
                "'high', 1.00, 1.00, 1.00, %s)",
                (
                    str(uuid4()),
                    str(organization_id),
                    str(assessment_id),
                    check_id,
                    METHODOLOGY,
                    host,
                    result,
                    result in {"pass", "fail", "warning"},
                    when,
                ),
            )


def approve(owner_url: str, policy_digest: str) -> None:
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO publication_reviews (methodology_version, policy_digest, "
            "reviewer_name, reviewer_role, decision) "
            "VALUES (%s, %s, 'Maria Ionescu', 'Data Protection Officer', 'approved')",
            (METHODOLOGY, policy_digest),
        )


def test_nothing_is_published_until_somebody_approved_it(
    postgres_database: dict[str, str],
) -> None:
    """The acceptance criterion for this milestone, enforced rather than documented."""
    domain_id, host, _ = seed(postgres_database["owner_url"])
    engine = owner_engine(postgres_database["owner_url"])
    with engine.begin() as connection:
        with pytest.raises(ReviewMissingError):
            publish_domain(connection, domain_id)
    engine.dispose()

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        count = owner.execute(
            "SELECT count(*) FROM observatory.profiles WHERE registrable_domain = %s", (host,)
        ).fetchone()
    assert count is not None and count[0] == 0


def test_an_approved_domain_is_published_with_only_publishable_checks(
    postgres_database: dict[str, str],
) -> None:
    domain_id, host, digest = seed(postgres_database["owner_url"])
    approve(postgres_database["owner_url"], digest)

    engine = owner_engine(postgres_database["owner_url"])
    with engine.begin() as connection:
        profile = publish_domain(connection, domain_id)
    engine.dispose()

    assert profile is not None and profile.band == "managed"

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        checks = owner.execute(
            "SELECT c.check_id, c.result FROM observatory.profile_checks c "
            "JOIN observatory.profiles p ON p.id = c.profile_id "
            "WHERE p.registrable_domain = %s",
            (host,),
        ).fetchall()

    # The private_only check was seeded and must not have travelled.
    assert checks == [("B.dmarc_enforced", "pass")]


def test_a_what_if_projection_is_never_published(
    postgres_database: dict[str, str],
) -> None:
    """A projected score is what a domain *would* have scored.

    Publishing one would put a number on a public page that was never measured about
    anybody, and it would look exactly like one that was.
    """
    domain_id, host, digest = seed(postgres_database["owner_url"], is_projection=True)
    approve(postgres_database["owner_url"], digest)

    engine = owner_engine(postgres_database["owner_url"])
    with engine.begin() as connection:
        # No non-projection snapshot exists, so there is nothing to publish -- which is
        # an ordinary state rather than an error.
        assert publish_domain(connection, domain_id) is None
    engine.dispose()

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        count = owner.execute(
            "SELECT count(*) FROM observatory.profiles WHERE registrable_domain = %s", (host,)
        ).fetchone()
    assert count is not None and count[0] == 0


def test_insufficient_coverage_publishes_no_band(postgres_database: dict[str, str]) -> None:
    domain_id, host, digest = seed(
        postgres_database["owner_url"],
        coverage_sufficient=False,
        band="insufficient_coverage",
    )
    approve(postgres_database["owner_url"], digest)

    engine = owner_engine(postgres_database["owner_url"])
    with engine.begin() as connection:
        publish_domain(connection, domain_id)
    engine.dispose()

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        row = owner.execute(
            "SELECT band, coverage_percentage FROM observatory.profiles "
            "WHERE registrable_domain = %s",
            (host,),
        ).fetchone()
    assert row is not None and row[0] is None


@pytest.mark.parametrize(
    ("spoiled", "reason"),
    [
        ({"consent": False}, "no active consent"),
        ({"ownership_state": "pending"}, "not verified"),
    ],
)
def test_the_projector_refuses_loudly(
    postgres_database: dict[str, str], spoiled: dict[str, object], reason: str
) -> None:
    """Refusals raise rather than returning None.

    Each is a decision somebody made -- they did not consent, they never proved control
    -- and quietly doing nothing would make those decisions invisible to whoever is
    wondering why a page is missing.
    """
    domain_id, _, digest = seed(postgres_database["owner_url"], **spoiled)  # type: ignore[arg-type]
    approve(postgres_database["owner_url"], digest)

    engine = owner_engine(postgres_database["owner_url"])
    with engine.begin() as connection:
        with pytest.raises(ProjectionRefusedError, match=reason):
            publish_domain(connection, domain_id)
    engine.dispose()


def test_a_takedown_stops_publication_even_with_consent(
    postgres_database: dict[str, str],
) -> None:
    domain_id, host, digest = seed(postgres_database["owner_url"])
    approve(postgres_database["owner_url"], digest)
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        owner.execute(
            "INSERT INTO publication_takedowns (registrable_domain, reason, recorded_by) "
            "VALUES (%s, 'disputed claim of control', 'moderation')",
            (host,),
        )

    engine = owner_engine(postgres_database["owner_url"])
    with engine.begin() as connection:
        with pytest.raises(ProjectionRefusedError, match="takedown"):
            publish_domain(connection, domain_id)
    engine.dispose()


def test_republishing_drops_checks_that_are_no_longer_reported(
    postgres_database: dict[str, str],
) -> None:
    """Otherwise a page keeps showing the last thing that was true about a check.

    That is worse than showing nothing: it is stale in a way a reader cannot detect,
    because it sits beside results that are current.
    """
    domain_id, host, digest = seed(
        postgres_database["owner_url"],
        results={"B.dmarc_enforced": "pass", "A.dnssec_enabled": "fail"},
    )
    approve(postgres_database["owner_url"], digest)

    engine = owner_engine(postgres_database["owner_url"])
    with engine.begin() as connection:
        publish_domain(connection, domain_id)
    engine.dispose()

    # A later run that could not evaluate DNSSEC at all. Written as a second assessment
    # rather than by editing the first: `check_evaluations` is append-only, and that is
    # also how it happens in reality.
    add_later_run(
        postgres_database["owner_url"],
        domain_id,
        digest,
        results={"B.dmarc_enforced": "pass", "A.dnssec_enabled": "unknown"},
    )

    engine = owner_engine(postgres_database["owner_url"])
    with engine.begin() as connection:
        publish_domain(connection, domain_id)
    engine.dispose()

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        checks = owner.execute(
            "SELECT c.check_id FROM observatory.profile_checks c "
            "JOIN observatory.profiles p ON p.id = c.profile_id "
            "WHERE p.registrable_domain = %s",
            (host,),
        ).fetchall()
    assert checks == [("B.dmarc_enforced",)]


def test_approval_does_not_carry_to_a_different_catalogue(
    postgres_database: dict[str, str],
) -> None:
    """A catalogue edited after sign-off is not what the reviewer read."""
    first, _, digest = seed(postgres_database["owner_url"])
    approve(postgres_database["owner_url"], digest)
    second, _, _ = seed(postgres_database["owner_url"])  # a different digest

    engine = owner_engine(postgres_database["owner_url"])
    with engine.begin() as connection:
        assert publish_domain(connection, first) is not None
    with engine.begin() as connection:
        with pytest.raises(ReviewMissingError):
            publish_domain(connection, second)
    engine.dispose()


def test_a_domain_with_no_assessment_is_not_an_error(
    postgres_database: dict[str, str],
) -> None:
    """Consenting long before the first run is ordinary."""
    organization_id, user_id, domain_id = uuid4(), uuid4(), uuid4()
    host = f"none-{organization_id.hex[:10]}.example.ro"
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Ana')",
            (str(user_id), str(user_id), f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Tenant', %s, %s)",
            (str(organization_id), f"nn-{organization_id.hex[:12]}", str(user_id)),
        )
        owner.execute(
            "INSERT INTO domains (id, organization_id, canonical_name, unicode_display, "
            "registrable_domain, ownership_state, created_by_user_id) "
            "VALUES (%s, %s, %s, %s, %s, 'verified', %s)",
            (str(domain_id), str(organization_id), host, host, host, str(user_id)),
        )
        owner.execute(
            "INSERT INTO publication_consents (organization_id, domain_id, granted_by_user_id) "
            "VALUES (%s, %s, %s)",
            (str(organization_id), str(domain_id), str(user_id)),
        )

    engine = owner_engine(postgres_database["owner_url"])
    with engine.begin() as connection:
        assert publish_domain(connection, domain_id) is None
    engine.dispose()


def test_the_most_recent_completed_assessment_wins(
    postgres_database: dict[str, str],
) -> None:
    """Publishing an older run would show a result the institution has already fixed."""
    domain_id, host, digest = seed(postgres_database["owner_url"], band="exposed")
    approve(postgres_database["owner_url"], digest)

    later_assessment, later_snapshot = uuid4(), uuid4()
    later = datetime.now(UTC) + timedelta(hours=1)
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        organization_id = owner.execute(
            "SELECT organization_id FROM domains WHERE id = %s", (str(domain_id),)
        ).fetchone()
        assert organization_id is not None
        owner.execute(
            "INSERT INTO assessments (id, organization_id, domain_id, methodology_version, "
            "state, completed_at) VALUES (%s, %s, %s, %s, 'completed', %s)",
            (
                str(later_assessment),
                str(organization_id[0]),
                str(domain_id),
                METHODOLOGY,
                later,
            ),
        )
        owner.execute(
            "INSERT INTO score_snapshots (id, organization_id, assessment_id, "
            "methodology_version, is_projection, policy_digest, evidence_digest, score, "
            "band, coverage_percentage, coverage_sufficient, document, computed_at) "
            "VALUES (%s, %s, %s, %s, false, %s, %s, 91.0, 'resilient', 95.0, true, '{}', %s)",
            (
                str(later_snapshot),
                str(organization_id[0]),
                str(later_assessment),
                METHODOLOGY,
                digest,
                "e" * 64,
                later,
            ),
        )

    engine = owner_engine(postgres_database["owner_url"])
    with engine.begin() as connection:
        profile = publish_domain(connection, domain_id)
    engine.dispose()

    assert profile is not None and profile.band == "resilient"
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        row = owner.execute(
            "SELECT band FROM observatory.profiles WHERE registrable_domain = %s", (host,)
        ).fetchone()
    assert row is not None and row[0] == "resilient"
