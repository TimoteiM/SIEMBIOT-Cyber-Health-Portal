"""What may leave the tenant boundary.

A mistake here is not one tenant seeing another's data. It is a named public institution's
security weaknesses on the internet, and no amount of apologising unpublishes them. So
most of this file is about the failure closing rather than the feature working, and the
boundary itself is asserted against a real connection as the real role -- the last time
this project trusted a grant it had read rather than one it had tested, the API was
running as a superuser and every row-level security policy had silently stopped applying.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "api" / "src"))

from siembiot.check_metadata import load_check_metadata  # noqa: E402
from siembiot.publication import (  # noqa: E402
    MINIMUM_COHORT_SIZE,
    ProjectionRefusedError,
    ReviewMissingError,
    aggregate_checks,
    project_profile,
    publishable_check_ids,
    require_approved_review,
)

DIGEST = "a" * 64
OBSERVED = datetime(2026, 8, 7, 10, 0, tzinfo=UTC)

#: Tables that hold tenant data. Not a sample: every one of them must be unreachable.
TENANT_TABLES = (
    "organizations",
    "users",
    "domains",
    "findings",
    "check_evaluations",
    "normalized_observations",
    "score_snapshots",
    "assessments",
    "audit_events",
    "maturity_responses",
    "publication_consents",
)


def projectable(**overrides: object) -> dict[str, object]:
    """A domain that is allowed to be published, so each test can spoil one thing."""
    return {
        "registrable_domain": "primaria.example.ro",
        "ownership_state": "verified",
        "has_active_consent": True,
        "is_taken_down": False,
        "band": "managed",
        "coverage_sufficient": True,
        "coverage_percentage": 88.0,
        "methodology_version": "1.0.0",
        "policy_digest": DIGEST,
        "observed_at": OBSERVED,
        "evaluations": {"B.dmarc_enforced": "pass"},
        **overrides,
    }


# -- the boundary, as the database enforces it -------------------------------


def test_the_public_role_cannot_read_any_tenant_table(
    postgres_database: dict[str, str],
) -> None:
    """The claim this whole design rests on, made against a real connection.

    Not "has no SELECT grant" -- it cannot resolve the schema at all, so the failure is
    at name resolution rather than at permission checking. A table added by a later
    migration is therefore unreachable by default, which is the property that has to
    survive people who are not thinking about publication.
    """
    with psycopg.connect(postgres_database["public_url"], autocommit=True) as public:
        for table in TENANT_TABLES:
            with pytest.raises(psycopg.Error) as caught:
                public.execute(f"SELECT * FROM public.{table} LIMIT 1")  # noqa: S608
            assert isinstance(
                caught.value,
                psycopg.errors.InsufficientPrivilege | psycopg.errors.UndefinedTable,
            ), f"{table} was readable by the public role"


def test_the_public_role_cannot_reach_tenant_data_through_a_function(
    postgres_database: dict[str, str],
) -> None:
    """The seams that deliberately cross tenants are the obvious way around a grant.

    `app_due_assessments` is SECURITY DEFINER and returns hostnames; if the public role
    could call it, the schema boundary would be decorative.
    """
    with psycopg.connect(postgres_database["public_url"], autocommit=True) as public:
        for call in ("app_due_assessments(10)", "app_operational_metrics()", "app_due_schedules()"):
            with pytest.raises(psycopg.Error):
                public.execute(f"SELECT * FROM public.{call}")  # noqa: S608


def test_the_public_role_can_read_the_observatory(
    postgres_database: dict[str, str],
) -> None:
    """And the boundary is not simply a role that can do nothing at all."""
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        owner.execute(
            "INSERT INTO observatory.profiles (registrable_domain, band, "
            "coverage_percentage, methodology_version, policy_digest, observed_at) "
            "VALUES (%s, 'managed', 88.0, '1.0.0', %s, now()) "
            "ON CONFLICT (registrable_domain) DO NOTHING",
            (f"readable-{uuid4().hex[:10]}.example.ro", DIGEST),
        )

    with psycopg.connect(postgres_database["public_url"], autocommit=True) as public:
        count = public.execute("SELECT count(*) FROM observatory.profiles").fetchone()
        assert count is not None and count[0] >= 1


def test_the_public_role_cannot_write_to_the_observatory(
    postgres_database: dict[str, str],
) -> None:
    """A public route that could write is one defacement away from a published claim
    nobody made."""
    with psycopg.connect(postgres_database["public_url"], autocommit=True) as public:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            public.execute(
                "INSERT INTO observatory.profiles (registrable_domain, "
                "coverage_percentage, methodology_version, policy_digest, observed_at) "
                "VALUES ('injected.example.ro', 100, '1.0.0', %s, now())",
                (DIGEST,),
            )


def test_the_observatory_carries_no_private_identifier(
    postgres_database: dict[str, str],
) -> None:
    """A copy of the observatory must not be joinable back to anything.

    Checked against the live schema rather than the migration text, so a column added
    later is caught wherever it was added from.
    """
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        columns = owner.execute(
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema = 'observatory'"
        ).fetchall()

    forbidden = ("organization_id", "domain_id", "user_id", "assessment_id", "finding_id")
    offending = [
        f"{table}.{column}"
        for table, column in columns
        if column in forbidden or column.endswith("_by_user_id")
    ]
    assert not offending, f"private identifiers in the public read model: {offending}"


# -- the interlock -----------------------------------------------------------


def test_nothing_is_published_without_a_recorded_review(
    postgres_database: dict[str, str],
) -> None:
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        from sqlalchemy import create_engine  # noqa: PLC0415

        engine = create_engine(
            postgres_database["owner_url"].replace("postgresql://", "postgresql+psycopg://")
        )
        with engine.connect() as connection:
            with pytest.raises(ReviewMissingError, match="no review recorded"):
                require_approved_review(
                    connection, methodology_version="1.0.0", policy_digest="b" * 64
                )
        engine.dispose()
        assert owner is not None


def test_an_approving_review_names_its_author(postgres_database: dict[str, str]) -> None:
    from sqlalchemy import create_engine  # noqa: PLC0415

    digest = f"{uuid4().hex}{uuid4().hex}"
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        owner.execute(
            "INSERT INTO publication_reviews (methodology_version, policy_digest, "
            "reviewer_name, reviewer_role, decision) "
            "VALUES ('1.0.0', %s, 'Maria Ionescu', 'Data Protection Officer', 'approved')",
            (digest,),
        )

    engine = create_engine(
        postgres_database["owner_url"].replace("postgresql://", "postgresql+psycopg://")
    )
    with engine.connect() as connection:
        assert (
            require_approved_review(connection, methodology_version="1.0.0", policy_digest=digest)
            == "Maria Ionescu"
        )
    engine.dispose()


def test_a_later_refusal_stops_publication(postgres_database: dict[str, str]) -> None:
    """So withdrawing approval does not require deleting the record that it was given."""
    from sqlalchemy import create_engine  # noqa: PLC0415

    digest = f"{uuid4().hex}{uuid4().hex}"
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        owner.execute(
            "INSERT INTO publication_reviews (methodology_version, policy_digest, "
            "reviewer_name, reviewer_role, decision, decided_at) VALUES "
            "('1.0.0', %s, 'Maria Ionescu', 'DPO', 'approved', now() - interval '2 days'), "
            "('1.0.0', %s, 'Maria Ionescu', 'DPO', 'refused', now())",
            (digest, digest),
        )

    engine = create_engine(
        postgres_database["owner_url"].replace("postgresql://", "postgresql+psycopg://")
    )
    with engine.connect() as connection:
        with pytest.raises(ReviewMissingError, match="refused"):
            require_approved_review(connection, methodology_version="1.0.0", policy_digest=digest)
    engine.dispose()


def test_an_edited_catalogue_needs_approving_again(
    postgres_database: dict[str, str],
) -> None:
    """The digest is what the reviewer actually read.

    A catalogue changed after sign-off, even keeping its version string, is not the
    thing that was approved.
    """
    from sqlalchemy import create_engine  # noqa: PLC0415

    approved = f"{uuid4().hex}{uuid4().hex}"
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        owner.execute(
            "INSERT INTO publication_reviews (methodology_version, policy_digest, "
            "reviewer_name, reviewer_role, decision) "
            "VALUES ('1.0.0', %s, 'Maria Ionescu', 'DPO', 'approved')",
            (approved,),
        )

    engine = create_engine(
        postgres_database["owner_url"].replace("postgresql://", "postgresql+psycopg://")
    )
    with engine.connect() as connection:
        with pytest.raises(ReviewMissingError):
            require_approved_review(
                connection, methodology_version="1.0.0", policy_digest=f"{uuid4().hex * 2}"
            )
    engine.dispose()


def test_a_review_cannot_be_recorded_anonymously(
    postgres_database: dict[str, str],
) -> None:
    """The decision needs an author, which is the reason it is a row and not a flag."""
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        with pytest.raises(psycopg.errors.CheckViolation):
            owner.execute(
                "INSERT INTO publication_reviews (methodology_version, policy_digest, "
                "reviewer_name, reviewer_role, decision) "
                "VALUES ('1.0.0', %s, '   ', 'DPO', 'approved')",
                (f"{uuid4().hex}{uuid4().hex}",),
            )


# -- what the projection refuses ---------------------------------------------


def test_a_private_check_never_reaches_a_public_profile() -> None:
    """The classification comes from the versioned catalogue, not from this package."""
    profile = project_profile(
        **projectable(  # type: ignore[arg-type]
            evaluations={
                "B.dmarc_enforced": "pass",
                "F.server_banner_disclosure": "fail",
                "E.domain_reputation_clean": "fail",
                "D.wildcard_dns_exposure": "fail",
            }
        )
    )
    published = {check.check_id for check in profile.checks}
    assert published == {"B.dmarc_enforced"}


def test_every_publishable_check_is_one_the_catalogue_classifies_as_public() -> None:
    metadata = load_check_metadata()
    for check_id in publishable_check_ids():
        assert metadata[check_id].public_safety_class == "public_profile"


def test_a_check_reclassified_as_private_disappears_from_public_profiles() -> None:
    """The property that makes the catalogue the single source of this decision.

    If this package kept its own list, reclassifying a check in the policy would change
    the private product and leave the public page as it was.
    """
    permitted = publishable_check_ids()
    private = {
        check_id
        for check_id, entry in load_check_metadata().items()
        if entry.public_safety_class != "public_profile"
    }
    assert private, "the catalogue no longer marks anything private; this test is vacuous"
    assert permitted.isdisjoint(private)


def test_our_own_collection_failures_are_not_published_as_findings() -> None:
    """A resolver that timed out is a fact about us, not about the institution."""
    profile = project_profile(
        **projectable(  # type: ignore[arg-type]
            evaluations={
                "B.dmarc_enforced": "unknown",
                "B.spf_present": "error",
                "C.hsts_present": "not_applicable",
                "A.dnssec_enabled": "fail",
            }
        )
    )
    assert {check.check_id for check in profile.checks} == {"A.dnssec_enabled"}


@pytest.mark.parametrize(
    ("spoiled", "reason"),
    [
        ({"has_active_consent": False}, "no active consent"),
        ({"ownership_state": "pending"}, "not verified"),
        ({"ownership_state": "reverification_required"}, "not verified"),
        ({"is_taken_down": True}, "takedown"),
    ],
)
def test_publication_is_refused_and_says_why(spoiled: dict[str, object], reason: str) -> None:
    with pytest.raises(ProjectionRefusedError, match=reason):
        project_profile(**projectable(**spoiled))  # type: ignore[arg-type]


def test_a_takedown_outranks_the_tenant_s_own_consent() -> None:
    """Otherwise the moderation control is advisory."""
    with pytest.raises(ProjectionRefusedError, match="takedown"):
        project_profile(
            **projectable(is_taken_down=True, has_active_consent=True)  # type: ignore[arg-type]
        )


def test_a_band_is_withheld_when_coverage_was_too_low() -> None:
    """More important in public than in private: a caveat does not survive a screenshot."""
    profile = project_profile(
        **projectable(coverage_sufficient=False, band="critical")  # type: ignore[arg-type]
    )
    assert profile.band is None
    assert profile.coverage_percentage == 88.0


def test_a_profile_carries_only_the_fields_that_were_declared() -> None:
    """The allowlist, checked as a shape rather than trusted as a convention.

    A future change that copied a private row into the projection would show up here as
    a field nobody named.
    """
    profile = project_profile(**projectable())  # type: ignore[arg-type]
    assert set(vars(profile)) == {
        "registrable_domain",
        "band",
        "coverage_percentage",
        "methodology_version",
        "policy_digest",
        "observed_at",
        "checks",
    }
    assert set(vars(profile.checks[0])) == {"check_id", "result"}


# -- cohorts -----------------------------------------------------------------


def test_a_cohort_below_the_threshold_is_not_released_at_all() -> None:
    """Not rounded, not ranged, not "fewer than five" -- absent.

    A suppression that appears only where the count is small is itself a signal.
    """
    thin = [{"B.dmarc_enforced": "pass"}] * (MINIMUM_COHORT_SIZE - 1)
    assert aggregate_checks(thin) == ()


def test_a_cohort_at_the_threshold_is_released() -> None:
    exact = [{"B.dmarc_enforced": "pass"}] * MINIMUM_COHORT_SIZE
    released = aggregate_checks(exact)
    assert len(released) == 1
    assert released[0].cohort_size == MINIMUM_COHORT_SIZE
    assert released[0].pass_percentage == 100.0


def test_each_check_gets_the_cohort_that_has_an_answer_for_it() -> None:
    """A check nobody could evaluate must not shrink its own denominator silently."""
    profiles = [
        {"B.dmarc_enforced": "pass", "A.dnssec_enabled": "fail"},
        {"B.dmarc_enforced": "fail", "A.dnssec_enabled": "unknown"},
        *[{"B.dmarc_enforced": "pass"} for _ in range(4)],
    ]
    released = {item.check_id: item for item in aggregate_checks(profiles)}
    assert "A.dnssec_enabled" not in released, "a two-member cohort was released"
    assert released["B.dmarc_enforced"].cohort_size == 6
    assert released["B.dmarc_enforced"].pass_count == 5


def test_the_database_refuses_a_thin_cohort_even_if_the_code_asks(
    postgres_database: dict[str, str],
) -> None:
    """The threshold is a constraint as well as a rule, so a bug here fails loudly."""
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        with pytest.raises(psycopg.errors.CheckViolation):
            owner.execute(
                "INSERT INTO observatory.aggregates (check_id, cohort_size, pass_count, "
                "methodology_version) VALUES ('B.dmarc_enforced', %s, 1, '1.0.0')",
                (MINIMUM_COHORT_SIZE - 1,),
            )


def test_the_code_threshold_and_the_database_threshold_agree() -> None:
    """Two copies of a number that must not drift apart."""
    migration = (
        Path(__file__).resolve().parents[2]
        / "services"
        / "api"
        / "migrations"
        / "versions"
        / "0015_publication_boundary.py"
    ).read_text(encoding="utf-8")
    assert f"MINIMUM_COHORT_SIZE = {MINIMUM_COHORT_SIZE}" in migration
