"""Findings for a domain.

A score tells somebody how they are doing; this tells them what is wrong. The failure
modes worth testing are the ones where the list misleads rather than errors: a shorter
list than the truth, an order that buries the urgent, or a set of weaknesses leaking
across a tenant boundary.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "api" / "src"))

from siembiot.config import Settings  # noqa: E402
from siembiot.identity import Principal  # noqa: E402
from siembiot.main import create_app  # noqa: E402

BASE_URL = "https://portal.example.test"
METHODOLOGY = "1.0.0"
DIGEST = "c" * 64


class NullIdentityResolver:
    def resolve(self, request: object) -> None:  # pragma: no cover - never consulted
        return None


@dataclass(frozen=True)
class Tenant:
    organization_id: UUID
    user_id: UUID
    domain_id: UUID
    assessment_id: UUID


def seed(owner_url: str, *, role: str = "organization_owner", with_score: bool = True) -> Tenant:
    organization_id, user_id = uuid4(), uuid4()
    domain_id, assessment_id = uuid4(), uuid4()
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Findings user')",
            (str(user_id), str(user_id), f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Tenant', %s, %s)",
            (str(organization_id), f"fi-{organization_id.hex[:12]}", str(user_id)),
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
            "VALUES (%s, %s, 'findings.test', 'findings.test', 'findings.test', 'verified', %s)",
            (str(domain_id), str(organization_id), str(user_id)),
        )
        owner.execute(
            "INSERT INTO assessments (id, organization_id, domain_id, methodology_version, "
            "state, completed_at) VALUES (%s, %s, %s, %s, 'completed', %s)",
            (
                str(assessment_id),
                str(organization_id),
                str(domain_id),
                METHODOLOGY,
                datetime.now(UTC),
            ),
        )
        if not with_score:
            return Tenant(organization_id, user_id, domain_id, assessment_id)
        owner.execute(
            "INSERT INTO score_snapshots (id, organization_id, assessment_id, "
            "methodology_version, policy_digest, evidence_digest, score, band, "
            "coverage_percentage, coverage_sufficient, is_projection, document, computed_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, 43.3, 'exposed', 91.5, true, false, '{}', %s)",
            (
                str(uuid4()),
                str(organization_id),
                str(assessment_id),
                METHODOLOGY,
                DIGEST,
                DIGEST,
                datetime.now(UTC),
            ),
        )
    return Tenant(organization_id, user_id, domain_id, assessment_id)


def add_finding(
    owner_url: str,
    tenant: Tenant,
    *,
    check_id: str,
    severity: str,
    state: str = "open",
    pillar: str = "dns",
    reason_code: str | None = "example_reason",
) -> UUID:
    finding_id = uuid4()
    now = datetime.now(UTC)
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO findings (id, organization_id, fingerprint, check_id, check_version, "
            "methodology_version, pillar, subject_kind, subject_identifier, "
            "authorized_domain_id, severity, state, reason_code, public_safety_class, "
            "attribution_confidence, source_confidence, freshness_confidence, "
            "first_seen_at, last_seen_at, resolved_at, evidence_observation_ids) "
            "VALUES (%s, %s, %s, %s, '1.0.0', %s, %s, 'domain', 'findings.test', %s, %s, %s, "
            "%s, 'public_profile', 1.00, 1.00, 1.00, %s, %s, %s, %s)",
            (
                str(finding_id),
                str(tenant.organization_id),
                finding_id.hex + finding_id.hex,
                check_id,
                METHODOLOGY,
                pillar,
                str(tenant.domain_id),
                severity,
                state,
                reason_code,
                now - timedelta(days=30),
                now,
                now if state == "resolved" else None,
                [uuid4()],
            ),
        )
    return finding_id


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
        user_id=tenant.user_id,
        email="findings@example.test",
        display_name="Findings user",
    )
    app.dependency_overrides[current_principal] = lambda: principal
    app.dependency_overrides[require_trusted_origin] = lambda: principal
    return TestClient(app, base_url=BASE_URL)


def findings_url(tenant: Tenant, **params: str) -> str:
    query = "".join(f"&{key}={value}" for key, value in params.items())
    return (
        f"/api/v1/organizations/{tenant.organization_id}"
        f"/domains/{tenant.domain_id}/findings?x=1{query}"
    )


# -- what the list says ------------------------------------------------------


def test_a_finding_arrives_with_the_words_needed_to_understand_it(
    postgres_database: dict[str, str],
) -> None:
    """A check identifier is not an explanation.

    The row records the decision; the catalog carries the prose. If they were not
    joined here the reader would get `A.dnssec_enabled` and be none the wiser.
    """
    tenant = seed(postgres_database["owner_url"])
    add_finding(
        postgres_database["owner_url"], tenant, check_id="A.dnssec_enabled", severity="medium"
    )
    with client_for(postgres_database, tenant) as client:
        body = client.get(findings_url(tenant)).json()

    finding = body["findings"][0]
    assert finding["title_ro"] and finding["title_en"]
    assert finding["rationale_ro"] and finding["rationale_en"]
    assert finding["pillar_letter"] == "A"
    assert "rfc4033" in finding["references"]
    assert finding["reason_code"] == "example_reason"


def test_the_most_urgent_findings_come_first(postgres_database: dict[str, str]) -> None:
    """Severity is not alphabetical, and a reader scans from the top."""
    tenant = seed(postgres_database["owner_url"])
    for check_id, severity in (
        ("A.caa_present", "low"),
        ("B.dmarc_enforced", "critical"),
        ("A.dnssec_enabled", "medium"),
        ("B.spf_present", "high"),
    ):
        add_finding(postgres_database["owner_url"], tenant, check_id=check_id, severity=severity)

    with client_for(postgres_database, tenant) as client:
        body = client.get(findings_url(tenant)).json()

    assert [item["severity"] for item in body["findings"]] == [
        "critical",
        "high",
        "medium",
        "low",
    ]


def test_the_order_is_stable_between_identical_requests(
    postgres_database: dict[str, str],
) -> None:
    """A list that reshuffles is one nobody can scan twice."""
    tenant = seed(postgres_database["owner_url"])
    for check_id in ("A.caa_present", "A.dnssec_enabled", "B.spf_present"):
        add_finding(postgres_database["owner_url"], tenant, check_id=check_id, severity="medium")

    with client_for(postgres_database, tenant) as client:
        first = [item["check_id"] for item in client.get(findings_url(tenant)).json()["findings"]]
        second = [item["check_id"] for item in client.get(findings_url(tenant)).json()["findings"]]
    assert first == second == sorted(first)


def test_the_score_travels_with_the_findings(postgres_database: dict[str, str]) -> None:
    """Coverage next to the list, so nobody reads it as complete when it is not."""
    tenant = seed(postgres_database["owner_url"])
    add_finding(postgres_database["owner_url"], tenant, check_id="A.caa_present", severity="low")
    with client_for(postgres_database, tenant) as client:
        body = client.get(findings_url(tenant)).json()

    assert body["score"] == 43.3
    assert body["band"] == "exposed"
    assert body["coverage_percentage"] == 91.5
    assert body["assessment_id"] == str(tenant.assessment_id)


def test_a_domain_with_no_assessment_reports_absence_not_zero(
    postgres_database: dict[str, str],
) -> None:
    """Never assessed and scored zero are opposite facts."""
    # Seeded without a snapshot rather than by deleting one: score_snapshots is
    # append-only by trigger, which is the correct behaviour and not something a test
    # should be reaching around.
    tenant = seed(postgres_database["owner_url"], with_score=False)
    with client_for(postgres_database, tenant) as client:
        body = client.get(findings_url(tenant)).json()

    assert body["score"] is None
    assert body["band"] is None
    assert body["assessment_id"] is None
    assert body["summary"]["total"] == 0


def test_the_three_confidences_stay_separate(postgres_database: dict[str, str]) -> None:
    """Blending them would hide that evidence can be excellent about the wrong asset."""
    tenant = seed(postgres_database["owner_url"])
    add_finding(postgres_database["owner_url"], tenant, check_id="A.caa_present", severity="low")
    with client_for(postgres_database, tenant) as client:
        confidence = client.get(findings_url(tenant)).json()["findings"][0]["confidence"]
    assert set(confidence) >= {"attribution", "source", "freshness"}


# -- what the list leaves out ------------------------------------------------


def test_resolved_findings_are_excluded_unless_asked_for(
    postgres_database: dict[str, str],
) -> None:
    tenant = seed(postgres_database["owner_url"])
    add_finding(postgres_database["owner_url"], tenant, check_id="A.caa_present", severity="low")
    add_finding(
        postgres_database["owner_url"],
        tenant,
        check_id="A.dnssec_enabled",
        severity="low",
        state="resolved",
    )
    with client_for(postgres_database, tenant) as client:
        default = client.get(findings_url(tenant)).json()
        everything = client.get(findings_url(tenant, include_resolved="true")).json()

    assert default["summary"]["total"] == 1
    assert everything["summary"]["total"] == 2


def test_a_suppressed_finding_is_still_shown(postgres_database: dict[str, str]) -> None:
    """Suppressed means somebody decided about it, not that it went away.

    Hiding it by default would let a decision quietly become an omission, which is the
    difference between an accepted risk and a forgotten one.
    """
    tenant = seed(postgres_database["owner_url"])
    add_finding(
        postgres_database["owner_url"],
        tenant,
        check_id="A.caa_present",
        severity="low",
        state="suppressed",
    )
    with client_for(postgres_database, tenant) as client:
        body = client.get(findings_url(tenant)).json()

    assert body["summary"]["total"] == 1
    # It is not counted among what is still open, because somebody has ruled on it.
    assert body["summary"]["open"] == 0


def test_the_summary_counts_every_severity_including_the_empty_ones(
    postgres_database: dict[str, str],
) -> None:
    """A zero is information. Omitting the key makes a client guess."""
    tenant = seed(postgres_database["owner_url"])
    add_finding(postgres_database["owner_url"], tenant, check_id="A.caa_present", severity="low")
    with client_for(postgres_database, tenant) as client:
        summary = client.get(findings_url(tenant)).json()["summary"]

    assert summary["by_severity"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 1,
        "informational": 0,
    }


# -- boundaries --------------------------------------------------------------


def test_findings_do_not_cross_a_tenant_boundary(postgres_database: dict[str, str]) -> None:
    """The worst possible leak on this endpoint: somebody else's weaknesses."""
    mine = seed(postgres_database["owner_url"])
    theirs = seed(postgres_database["owner_url"])
    add_finding(postgres_database["owner_url"], theirs, check_id="A.caa_present", severity="high")

    with client_for(postgres_database, mine) as client:
        own = client.get(findings_url(mine)).json()
        cross = client.get(
            f"/api/v1/organizations/{mine.organization_id}/domains/{theirs.domain_id}/findings"
        )

    assert own["summary"]["total"] == 0
    assert cross.status_code == 404


def test_a_role_without_assessment_read_is_refused(postgres_database: dict[str, str]) -> None:
    tenant = seed(postgres_database["owner_url"], role="maturity_contributor")
    add_finding(postgres_database["owner_url"], tenant, check_id="A.caa_present", severity="low")
    with client_for(postgres_database, tenant) as client:
        assert client.get(findings_url(tenant)).status_code == 403


def test_a_read_only_auditor_may_see_findings(postgres_database: dict[str, str]) -> None:
    """Auditing is exactly the job of reading what is wrong without changing it."""
    tenant = seed(postgres_database["owner_url"], role="viewer_auditor")
    add_finding(postgres_database["owner_url"], tenant, check_id="A.caa_present", severity="low")
    with client_for(postgres_database, tenant) as client:
        assert client.get(findings_url(tenant)).status_code == 200


def test_an_unknown_domain_is_not_found(postgres_database: dict[str, str]) -> None:
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        response = client.get(
            f"/api/v1/organizations/{tenant.organization_id}/domains/{uuid4()}/findings"
        )
    assert response.status_code == 404


# -- the catalog seam --------------------------------------------------------


def test_a_check_the_catalog_no_longer_describes_still_appears(
    postgres_database: dict[str, str],
) -> None:
    """Dropping it would silently shorten the list of what is wrong.

    Falling back to the identifier tells the reader something is there and that its
    description is missing -- which is recoverable. A vanished weakness is not.
    """
    tenant = seed(postgres_database["owner_url"])
    add_finding(postgres_database["owner_url"], tenant, check_id="Z.retired_check", severity="high")
    with client_for(postgres_database, tenant) as client:
        body = client.get(findings_url(tenant)).json()

    assert body["summary"]["total"] == 1
    finding = body["findings"][0]
    assert finding["title_ro"] == "Z.retired_check"
    assert finding["pillar_letter"] == "?"


def test_remediation_is_named_but_never_invented(postgres_database: dict[str, str]) -> None:
    """The templates are not written yet.

    Passing the identifier through is honest. Generating plausible security advice to
    fill the space would be worse than the gap, because a reader cannot tell invented
    guidance from reviewed guidance and would act on it.
    """
    tenant = seed(postgres_database["owner_url"])
    add_finding(
        postgres_database["owner_url"], tenant, check_id="A.dnssec_enabled", severity="medium"
    )
    with client_for(postgres_database, tenant) as client:
        finding = client.get(findings_url(tenant)).json()["findings"][0]

    assert finding["remediation_template"] == "dnssec_enable"


@pytest.mark.parametrize("check_id", ["A.dnssec_enabled", "B.spf_present", "C.hsts_present"])
def test_every_catalog_check_can_be_rendered(
    postgres_database: dict[str, str], check_id: str
) -> None:
    """Rendering must not depend on which pillar a finding came from."""
    tenant = seed(postgres_database["owner_url"])
    add_finding(postgres_database["owner_url"], tenant, check_id=check_id, severity="medium")
    with client_for(postgres_database, tenant) as client:
        finding = client.get(findings_url(tenant)).json()["findings"][0]
    assert finding["title_ro"] != check_id
    assert finding["pillar_letter"] in {"A", "B", "C", "D", "E", "F"}
