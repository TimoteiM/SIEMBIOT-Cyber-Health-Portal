"""Posture over time, and whether two runs can honestly be compared.

The interesting failure is not an error, it is a chart that lies: a score rises
because the second run saw less of the surface, and a reader concludes their domain
improved. Most of what follows attacks that.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import psycopg
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "api" / "src"))

from siembiot.config import Settings  # noqa: E402
from siembiot.identity import Principal  # noqa: E402
from siembiot.main import create_app  # noqa: E402

BASE_URL = "https://portal.example.test"
METHODOLOGY = "1.0.0"
DIGEST = "e" * 64


class NullIdentityResolver:
    def resolve(self, request: object) -> None:  # pragma: no cover - never consulted
        return None


@dataclass(frozen=True)
class Tenant:
    organization_id: UUID
    user_id: UUID
    domain_id: UUID


def seed(owner_url: str, *, role: str = "organization_owner") -> Tenant:
    organization_id, user_id, domain_id = uuid4(), uuid4(), uuid4()
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'History user')",
            (str(user_id), str(user_id), f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Tenant', %s, %s)",
            (str(organization_id), f"hi-{organization_id.hex[:12]}", str(user_id)),
        )
        owner.execute(
            "INSERT INTO memberships (organization_id, user_id, role, status) "
            "VALUES (%s, %s, %s, 'active')",
            (str(organization_id), str(user_id), role),
        )
        owner.execute(
            "INSERT INTO methodology_versions (version, policy_digest, notice) "
            "VALUES (%s, %s, 'test') ON CONFLICT (version) DO NOTHING",
            (METHODOLOGY, DIGEST),
        )
        owner.execute(
            "INSERT INTO domains (id, organization_id, canonical_name, unicode_display, "
            "registrable_domain, ownership_state, created_by_user_id) "
            "VALUES (%s, %s, 'hist.test', 'hist.test', 'hist.test', 'verified', %s)",
            (str(domain_id), str(organization_id), str(user_id)),
        )
    return Tenant(organization_id, user_id, domain_id)


def add_run(
    owner_url: str,
    tenant: Tenant,
    *,
    score: float,
    coverage: float,
    ago_days: int,
    band: str = "developing",
    scored: bool = True,
) -> UUID:
    """One completed assessment, optionally without a score."""
    assessment_id = uuid4()
    completed = datetime.now(UTC) - timedelta(days=ago_days)
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO assessments (id, organization_id, domain_id, methodology_version, "
            "state, mode, completed_at) VALUES (%s, %s, %s, %s, 'completed', "
            "'passive_observation', %s)",
            (
                str(assessment_id),
                str(tenant.organization_id),
                str(tenant.domain_id),
                METHODOLOGY,
                completed,
            ),
        )
        if scored:
            owner.execute(
                "INSERT INTO score_snapshots (id, organization_id, assessment_id, "
                "methodology_version, policy_digest, evidence_digest, score, band, "
                "coverage_percentage, coverage_sufficient, is_projection, document, "
                "computed_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, false, "
                "'{}', %s)",
                (
                    str(uuid4()),
                    str(tenant.organization_id),
                    str(assessment_id),
                    METHODOLOGY,
                    DIGEST,
                    DIGEST,
                    score,
                    band,
                    coverage,
                    coverage >= 60,
                    completed,
                ),
            )
    return assessment_id


def add_transition(
    owner_url: str,
    tenant: Tenant,
    assessment_id: UUID,
    *,
    check_id: str,
    to_state: str,
    from_state: str = "absent",
    severity: str = "medium",
) -> None:
    finding_id = uuid4()
    now = datetime.now(UTC)
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO findings (id, organization_id, fingerprint, check_id, check_version, "
            "methodology_version, pillar, subject_kind, subject_identifier, "
            "authorized_domain_id, severity, state, public_safety_class, "
            "attribution_confidence, source_confidence, freshness_confidence, "
            "first_seen_at, last_seen_at, resolved_at) "
            "VALUES (%s, %s, %s, %s, '1.0.0', %s, 'dns', 'domain', 'hist.test', %s, %s, %s, "
            "'public_profile', 1.00, 1.00, 1.00, %s, %s, %s)",
            (
                str(finding_id),
                str(tenant.organization_id),
                finding_id.hex + finding_id.hex,
                check_id,
                METHODOLOGY,
                str(tenant.domain_id),
                severity,
                "resolved" if to_state == "resolved" else "open",
                now - timedelta(days=60),
                now,
                now if to_state == "resolved" else None,
            ),
        )
        owner.execute(
            "INSERT INTO finding_history (id, organization_id, finding_id, assessment_id, "
            "from_state, to_state, occurred_at) VALUES (%s, %s, %s, %s, %s, %s, now())",
            (
                str(uuid4()),
                str(tenant.organization_id),
                str(finding_id),
                str(assessment_id),
                from_state,
                to_state,
            ),
        )


def client_for(postgres_database: dict[str, str], tenant: Tenant) -> TestClient:
    from siembiot.auth import current_principal, require_trusted_origin

    app = create_app(
        settings=Settings(
            environment="test",
            public_base_url=BASE_URL,
            app_database_url=postgres_database["app_url"].replace(
                "postgresql://", "postgresql+psycopg://"
            ),
        ),
        identity_resolver=NullIdentityResolver(),
    )
    principal = Principal(
        user_id=tenant.user_id, email="hist@example.test", display_name="History user"
    )
    app.dependency_overrides[current_principal] = lambda: principal
    app.dependency_overrides[require_trusted_origin] = lambda: principal
    return TestClient(app, base_url=BASE_URL)


def history(client: TestClient, tenant: Tenant) -> dict[str, Any]:
    body: dict[str, Any] = client.get(
        f"/api/v1/organizations/{tenant.organization_id}/domains/{tenant.domain_id}/history"
    ).json()
    return body


# -- the timeline ------------------------------------------------------------


def test_the_timeline_reads_oldest_first(postgres_database: dict[str, str]) -> None:
    """A chart reads left to right; reversing in every client is work done many times."""
    tenant = seed(postgres_database["owner_url"])
    add_run(postgres_database["owner_url"], tenant, score=40.0, coverage=90.0, ago_days=20)
    add_run(postgres_database["owner_url"], tenant, score=55.0, coverage=90.0, ago_days=1)

    with client_for(postgres_database, tenant) as client:
        points = history(client, tenant)["points"]

    assert [point["score"] for point in points] == [40.0, 55.0]


def test_a_run_that_never_scored_is_absent_rather_than_zero(
    postgres_database: dict[str, str],
) -> None:
    """A failed collection is not a posture of nought.

    Plotting it as zero would make the chart dip whenever the network misbehaved, and
    teach people to distrust the chart rather than the network.
    """
    tenant = seed(postgres_database["owner_url"])
    add_run(postgres_database["owner_url"], tenant, score=50.0, coverage=90.0, ago_days=5)
    add_run(
        postgres_database["owner_url"],
        tenant,
        score=0.0,
        coverage=0.0,
        ago_days=1,
        scored=False,
    )

    with client_for(postgres_database, tenant) as client:
        points = history(client, tenant)["points"]

    assert len(points) == 1
    assert points[0]["score"] == 50.0


def test_a_single_run_yields_no_comparison(postgres_database: dict[str, str]) -> None:
    """One point is not a trend, and inventing a baseline would be a claim."""
    tenant = seed(postgres_database["owner_url"])
    add_run(postgres_database["owner_url"], tenant, score=50.0, coverage=90.0, ago_days=1)

    with client_for(postgres_database, tenant) as client:
        body = history(client, tenant)

    assert len(body["points"]) == 1
    assert body["change"] is None


def test_a_domain_with_no_runs_is_empty_not_missing(
    postgres_database: dict[str, str],
) -> None:
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        body = history(client, tenant)
    assert body["points"] == []
    assert body["change"] is None


# -- comparability, which is the point ---------------------------------------


def test_two_runs_with_similar_coverage_are_comparable(
    postgres_database: dict[str, str],
) -> None:
    tenant = seed(postgres_database["owner_url"])
    add_run(postgres_database["owner_url"], tenant, score=40.0, coverage=90.0, ago_days=7)
    add_run(postgres_database["owner_url"], tenant, score=55.0, coverage=92.0, ago_days=1)

    with client_for(postgres_database, tenant) as client:
        change = history(client, tenant)["change"]

    assert change["comparable"] is True
    assert change["incomparable_reason"] is None
    assert change["score_delta"] == 15.0


def test_a_score_that_rose_because_coverage_fell_is_not_progress(
    postgres_database: dict[str, str],
) -> None:
    """The failure this whole feature is shaped around.

    The score is an average over what was evaluated. A run that reached less of the
    surface can score higher while the domain got worse, and drawing both as points on
    one line asserts a comparison the evidence does not support.
    """
    tenant = seed(postgres_database["owner_url"])
    add_run(postgres_database["owner_url"], tenant, score=40.0, coverage=95.0, ago_days=7)
    add_run(postgres_database["owner_url"], tenant, score=80.0, coverage=65.0, ago_days=1)

    with client_for(postgres_database, tenant) as client:
        change = history(client, tenant)["change"]

    assert change["comparable"] is False
    assert change["incomparable_reason"] == "coverage_moved"
    # Still reported: hiding the numbers replaces a misleading answer with no answer.
    assert change["score_delta"] == 40.0
    assert change["coverage_delta"] == -30.0


def test_a_run_below_the_coverage_floor_is_never_comparable(
    postgres_database: dict[str, str],
) -> None:
    """The methodology already refuses to present a band for it.

    Comparing against a run it would not report on its own is worse than not
    comparing at all.
    """
    tenant = seed(postgres_database["owner_url"])
    add_run(
        postgres_database["owner_url"],
        tenant,
        score=100.0,
        coverage=5.0,
        ago_days=7,
        band="insufficient_coverage",
    )
    add_run(
        postgres_database["owner_url"],
        tenant,
        score=45.0,
        coverage=12.0,
        ago_days=1,
        band="insufficient_coverage",
    )

    with client_for(postgres_database, tenant) as client:
        change = history(client, tenant)["change"]

    assert change["comparable"] is False
    assert change["incomparable_reason"] == "insufficient_coverage"


def test_coverage_is_always_reported_beside_the_score_delta(
    postgres_database: dict[str, str],
) -> None:
    """So a reader can judge for themselves, whatever the flag says."""
    tenant = seed(postgres_database["owner_url"])
    add_run(postgres_database["owner_url"], tenant, score=40.0, coverage=90.0, ago_days=7)
    add_run(postgres_database["owner_url"], tenant, score=42.0, coverage=88.0, ago_days=1)

    with client_for(postgres_database, tenant) as client:
        change = history(client, tenant)["change"]

    assert change["coverage_delta"] == -2.0
    assert change["comparable"] is True


# -- what changed ------------------------------------------------------------


def test_the_change_names_what_opened_and_what_resolved(
    postgres_database: dict[str, str],
) -> None:
    """The point of the screen: somebody who followed the guidance sees it worked."""
    tenant = seed(postgres_database["owner_url"])
    add_run(postgres_database["owner_url"], tenant, score=40.0, coverage=90.0, ago_days=7)
    current = add_run(postgres_database["owner_url"], tenant, score=55.0, coverage=90.0, ago_days=1)
    add_transition(
        postgres_database["owner_url"],
        tenant,
        current,
        check_id="B.spf_present",
        from_state="open",
        to_state="resolved",
    )
    add_transition(
        postgres_database["owner_url"],
        tenant,
        current,
        check_id="A.caa_present",
        to_state="open",
    )

    with client_for(postgres_database, tenant) as client:
        change = history(client, tenant)["change"]

    assert [item["check_id"] for item in change["resolved"]] == ["B.spf_present"]
    assert [item["check_id"] for item in change["opened"]] == ["A.caa_present"]


def test_changes_carry_the_words_needed_to_read_them(
    postgres_database: dict[str, str],
) -> None:
    """A check identifier in a change list is as unhelpful as it is in a finding."""
    tenant = seed(postgres_database["owner_url"])
    add_run(postgres_database["owner_url"], tenant, score=40.0, coverage=90.0, ago_days=7)
    current = add_run(postgres_database["owner_url"], tenant, score=55.0, coverage=90.0, ago_days=1)
    add_transition(
        postgres_database["owner_url"],
        tenant,
        current,
        check_id="A.dnssec_enabled",
        from_state="open",
        to_state="resolved",
    )

    with client_for(postgres_database, tenant) as client:
        resolved = history(client, tenant)["change"]["resolved"][0]

    assert resolved["title_ro"] and resolved["title_ro"] != "A.dnssec_enabled"
    assert resolved["title_en"]


def test_a_regression_counts_as_opened(postgres_database: dict[str, str]) -> None:
    """Something that came back is news, and it is the same news as something new."""
    tenant = seed(postgres_database["owner_url"])
    add_run(postgres_database["owner_url"], tenant, score=55.0, coverage=90.0, ago_days=7)
    current = add_run(postgres_database["owner_url"], tenant, score=40.0, coverage=90.0, ago_days=1)
    add_transition(
        postgres_database["owner_url"],
        tenant,
        current,
        check_id="C.hsts_present",
        from_state="resolved",
        to_state="regressed",
    )

    with client_for(postgres_database, tenant) as client:
        change = history(client, tenant)["change"]

    assert [item["check_id"] for item in change["opened"]] == ["C.hsts_present"]


# -- boundaries --------------------------------------------------------------


def test_history_does_not_cross_a_tenant_boundary(
    postgres_database: dict[str, str],
) -> None:
    mine = seed(postgres_database["owner_url"])
    theirs = seed(postgres_database["owner_url"])
    add_run(postgres_database["owner_url"], theirs, score=40.0, coverage=90.0, ago_days=1)

    with client_for(postgres_database, mine) as client:
        assert history(client, mine)["points"] == []
        cross = client.get(
            f"/api/v1/organizations/{mine.organization_id}/domains/{theirs.domain_id}/history"
        )
    assert cross.status_code == 404


def test_a_role_without_assessment_read_is_refused(
    postgres_database: dict[str, str],
) -> None:
    tenant = seed(postgres_database["owner_url"], role="maturity_contributor")
    with client_for(postgres_database, tenant) as client:
        response = client.get(
            f"/api/v1/organizations/{tenant.organization_id}/domains/{tenant.domain_id}/history"
        )
    assert response.status_code == 403
