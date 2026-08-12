"""Downloading an assessment as a document.

The report is the one artefact that leaves this platform, so the interesting failures
are not "the endpoint errors" but "somebody who should not have this document gets it".
A link lives in browser history, in a referrer header, in a chat thread, on a screen
during a call. Each of those is a way the URL travels without the person travelling with
it, and every property tested below exists because of one of them.
"""

from __future__ import annotations

import hashlib
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

#: A snapshot shaped the way the scorer stores one.
SNAPSHOT = (
    '{"overall": {"score": 43.3, "band": "exposed"},'
    ' "coverage": {"percentage": 91.5, "sufficient": true,'
    ' "undetermined_checks": ["C.tls_protocol_posture"]},'
    ' "pillars": [{"pillar": "dns", "score": 55.0, "weight": 0.2}]}'
)


class NullIdentityResolver:
    def resolve(self, request: object) -> None:  # pragma: no cover - never consulted
        return None


@dataclass(frozen=True)
class Tenant:
    organization_id: UUID
    user_id: UUID
    domain_id: UUID
    assessment_id: UUID


def seed(owner_url: str, *, with_score: bool = True, domain: str = "raport.test") -> Tenant:
    organization_id, user_id = uuid4(), uuid4()
    domain_id, assessment_id = uuid4(), uuid4()
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Report user')",
            (str(user_id), str(user_id), f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, %s, %s, %s)",
            (
                str(organization_id),
                "Primăria Exemplu",
                f"rp-{organization_id.hex[:12]}",
                str(user_id),
            ),
        )
        owner.execute(
            "INSERT INTO memberships (organization_id, user_id, role, status) "
            "VALUES (%s, %s, 'organization_owner', 'active')",
            (str(organization_id), str(user_id)),
        )
        owner.execute(
            "INSERT INTO methodology_versions (version, policy_digest, notice) "
            "VALUES (%s, %s, 'test') ON CONFLICT (version) DO NOTHING",
            (METHODOLOGY, DIGEST),
        )
        owner.execute(
            "INSERT INTO domains (id, organization_id, canonical_name, unicode_display, "
            "registrable_domain, ownership_state, created_by_user_id) "
            "VALUES (%s, %s, %s, %s, %s, 'verified', %s)",
            (str(domain_id), str(organization_id), domain, domain, domain, str(user_id)),
        )
        owner.execute(
            "INSERT INTO assessments (id, organization_id, domain_id, methodology_version, "
            "state, completed_at, mode) VALUES (%s, %s, %s, %s, 'completed', %s, "
            "'passive_observation')",
            (
                str(assessment_id),
                str(organization_id),
                str(domain_id),
                METHODOLOGY,
                datetime.now(UTC),
            ),
        )
        if with_score:
            owner.execute(
                "INSERT INTO score_snapshots (id, organization_id, assessment_id, "
                "methodology_version, policy_digest, evidence_digest, score, band, "
                "coverage_percentage, coverage_sufficient, is_projection, document, "
                "computed_at) VALUES (%s, %s, %s, %s, %s, %s, 43.3, 'exposed', 91.5, true, "
                "false, %s, %s)",
                (
                    str(uuid4()),
                    str(organization_id),
                    str(assessment_id),
                    METHODOLOGY,
                    DIGEST,
                    DIGEST,
                    SNAPSHOT,
                    datetime.now(UTC),
                ),
            )
    return Tenant(organization_id, user_id, domain_id, assessment_id)


def client_for(postgres_database: dict[str, str], user_id: UUID) -> TestClient:
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
    principal = Principal(user_id=user_id, email="report@example.test", display_name="Report user")
    app.dependency_overrides[current_principal] = lambda: principal
    app.dependency_overrides[require_trusted_origin] = lambda: principal
    return TestClient(app, base_url=BASE_URL)


def expire(owner_url: str) -> None:
    """Age every grant past its expiry.

    Both timestamps move: the table refuses a grant that expires before it was issued,
    so writing only `expires_at` is rejected rather than producing an expired row.
    """
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "UPDATE report_grants SET created_at = %s, expires_at = %s",
            (datetime.now(UTC) - timedelta(hours=1), datetime.now(UTC) - timedelta(minutes=1)),
        )


def mint(client: TestClient, tenant: Tenant, locale: str = "ro") -> dict[str, object]:
    response = client.post(
        f"/api/v1/organizations/{tenant.organization_id}"
        f"/domains/{tenant.domain_id}/reports?locale={locale}"
    )
    assert response.status_code == 201, response.text
    return dict(response.json())


# -- the happy path -------------------------------------------------------------------


def test_a_report_can_be_minted_and_downloaded_once(postgres_database: dict[str, str]) -> None:
    tenant = seed(postgres_database["owner_url"])
    client = client_for(postgres_database, tenant.user_id)

    grant = mint(client, tenant)
    response = client.get(str(grant["download_path"]))

    assert response.status_code == 200
    assert "CONFIDENȚIAL" in response.text
    assert "Primăria Exemplu" in response.text
    assert "raport.test" in response.text


def test_the_second_download_is_refused(postgres_database: dict[str, str]) -> None:
    """Single use. A link that leaks after it has been used is already spent, which is
    the common case: the person downloads the report, and the URL survives in history."""
    tenant = seed(postgres_database["owner_url"])
    client = client_for(postgres_database, tenant.user_id)

    grant = mint(client, tenant)
    assert client.get(str(grant["download_path"])).status_code == 200
    assert client.get(str(grant["download_path"])).status_code == 404


# -- the ways a link travels without its holder ---------------------------------------


def test_another_signed_in_user_cannot_redeem_the_link(
    postgres_database: dict[str, str],
) -> None:
    """The property that makes a leaked URL inert.

    Without it this is a capability URL, and a capability URL for a confidential document
    is one forwarded message away from being public.
    """
    tenant = seed(postgres_database["owner_url"])
    other = seed(postgres_database["owner_url"], domain="alta.test")

    grant = mint(client_for(postgres_database, tenant.user_id), tenant)
    stolen = client_for(postgres_database, other.user_id).get(str(grant["download_path"]))

    assert stolen.status_code == 404


def test_an_expired_grant_is_refused(postgres_database: dict[str, str]) -> None:
    tenant = seed(postgres_database["owner_url"])
    client = client_for(postgres_database, tenant.user_id)
    grant = mint(client, tenant)

    expire(postgres_database["owner_url"])

    assert client.get(str(grant["download_path"])).status_code == 404


def test_a_guessed_token_is_refused(postgres_database: dict[str, str]) -> None:
    tenant = seed(postgres_database["owner_url"])
    client = client_for(postgres_database, tenant.user_id)

    assert client.get("/api/v1/reports/" + "a" * 43).status_code == 404


@pytest.mark.parametrize(
    "reason",
    ["missing", "spent", "expired", "wrong_user"],
)
def test_every_refusal_looks_the_same(postgres_database: dict[str, str], reason: str) -> None:
    """One reply for four different reasons.

    The differences are exactly what somebody holding a leaked link would like to learn --
    "this token existed but is spent" tells them the link was real. None of them helps
    the legitimate holder, who simply asks for another link.
    """
    tenant = seed(postgres_database["owner_url"])
    client = client_for(postgres_database, tenant.user_id)
    grant = mint(client, tenant)
    path = str(grant["download_path"])

    if reason == "missing":
        path = "/api/v1/reports/" + "z" * 43
    elif reason == "spent":
        client.get(path)
    elif reason == "expired":
        expire(postgres_database["owner_url"])
    else:
        other = seed(postgres_database["owner_url"], domain="alta2.test")
        client = client_for(postgres_database, other.user_id)

    response = client.get(path)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


# -- what is stored -------------------------------------------------------------------


def test_the_token_is_never_stored(postgres_database: dict[str, str]) -> None:
    """A read of this table -- a backup, a log, an injection elsewhere -- must not yield
    a working download link."""
    tenant = seed(postgres_database["owner_url"])
    client = client_for(postgres_database, tenant.user_id)
    grant = mint(client, tenant)
    token = str(grant["download_path"]).rsplit("/", 1)[-1]

    expected = hashlib.sha256(token.encode()).hexdigest()
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        stored = [row[0] for row in owner.execute("SELECT token_hash FROM report_grants")]

    # The token appears nowhere, and its hash appears exactly once.
    assert not [value for value in stored if token in value]
    assert stored.count(expected) == 1


def test_the_report_itself_is_not_stored(postgres_database: dict[str, str]) -> None:
    """Rendered on demand from the snapshot. A stored copy would be a second, ageing
    version of a confidential document sitting in a table waiting to be read."""
    tenant = seed(postgres_database["owner_url"])
    client = client_for(postgres_database, tenant.user_id)
    client.get(str(mint(client, tenant)["download_path"]))

    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        columns = owner.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'report_grants'"
        ).fetchall()

    assert not [name for (name,) in columns if name in {"body", "content", "html", "document"}]


# -- caching and delivery -------------------------------------------------------------


def test_the_response_forbids_caching(postgres_database: dict[str, str]) -> None:
    """A confidential document written to a browser's disk cache outlives the session
    that fetched it, and a shared proxy is not the only cache that matters."""
    tenant = seed(postgres_database["owner_url"])
    client = client_for(postgres_database, tenant.user_id)

    response = client.get(str(mint(client, tenant)["download_path"]))

    assert "no-store" in response.headers["cache-control"]
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "attachment" in response.headers["content-disposition"]


# -- refusing to produce a document that would mislead --------------------------------


def test_a_domain_with_no_assessment_cannot_be_reported_on(
    postgres_database: dict[str, str],
) -> None:
    """Distinct from an empty report. "Nothing has been checked" must never be delivered
    as a document that reads like "nothing is wrong"."""
    tenant = seed(postgres_database["owner_url"], with_score=False)
    client = client_for(postgres_database, tenant.user_id)

    response = client.post(
        f"/api/v1/organizations/{tenant.organization_id}/domains/{tenant.domain_id}/reports"
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "no_scored_assessment"


def test_an_unsupported_language_is_refused(postgres_database: dict[str, str]) -> None:
    tenant = seed(postgres_database["owner_url"])
    client = client_for(postgres_database, tenant.user_id)

    response = client.post(
        f"/api/v1/organizations/{tenant.organization_id}"
        f"/domains/{tenant.domain_id}/reports?locale=fr"
    )

    assert response.status_code == 422


def test_the_language_is_fixed_when_the_grant_is_minted(
    postgres_database: dict[str, str],
) -> None:
    """The reader's browser must not be able to change the language of a document
    somebody else is accountable for having sent."""
    tenant = seed(postgres_database["owner_url"])
    client = client_for(postgres_database, tenant.user_id)

    grant = mint(client, tenant, locale="en")
    response = client.get(str(grant["download_path"]) + "?locale=ro")

    assert "CONFIDENTIAL" in response.text
    assert "CONFIDENȚIAL" not in response.text


def test_a_domain_in_another_organization_is_not_reportable(
    postgres_database: dict[str, str],
) -> None:
    tenant = seed(postgres_database["owner_url"])
    other = seed(postgres_database["owner_url"], domain="straina.test")
    client = client_for(postgres_database, tenant.user_id)

    response = client.post(
        f"/api/v1/organizations/{tenant.organization_id}/domains/{other.domain_id}/reports"
    )

    assert response.status_code == 404


# -- PDF ---------------------------------------------------------------------------------


def test_the_format_is_fixed_when_the_grant_is_minted(
    postgres_database: dict[str, str],
) -> None:
    """Like the language. A reader's URL must not change the form of a document somebody
    else is accountable for having sent."""
    tenant = seed(postgres_database["owner_url"])
    client = client_for(postgres_database, tenant.user_id)

    grant = mint(client, tenant)
    assert grant["document_format"] == "html"

    response = client.get(str(grant["download_path"]) + "?document_format=pdf")

    assert response.headers["content-type"].startswith("text/html")


def test_an_unknown_format_is_refused(postgres_database: dict[str, str]) -> None:
    tenant = seed(postgres_database["owner_url"])
    client = client_for(postgres_database, tenant.user_id)

    response = client.post(
        f"/api/v1/organizations/{tenant.organization_id}"
        f"/domains/{tenant.domain_id}/reports?document_format=docx"
    )

    assert response.status_code == 422


def test_pdf_availability_is_decided_at_mint_not_at_download(
    postgres_database: dict[str, str],
) -> None:
    """A deployment without the renderer says so when the report is asked for, rather
    than when the link is clicked -- by which time it has been sent to somebody.

    Asserted whichever way this environment is configured: with a renderer the grant is
    issued, without one the refusal names the reason. Both are correct; silently
    returning HTML under a PDF link is not.
    """
    from siembiot_worker.reports.pdf import RENDERER_UNAVAILABLE, renderer_available

    tenant = seed(postgres_database["owner_url"])
    client = client_for(postgres_database, tenant.user_id)

    response = client.post(
        f"/api/v1/organizations/{tenant.organization_id}"
        f"/domains/{tenant.domain_id}/reports?document_format=pdf"
    )

    if renderer_available():
        assert response.status_code == 201
        assert response.json()["document_format"] == "pdf"
        downloaded = client.get(response.json()["download_path"])
        assert downloaded.headers["content-type"] == "application/pdf"
        assert downloaded.content[:5] == b"%PDF-"
        assert downloaded.headers["content-disposition"].endswith('.pdf"')
    else:
        assert response.status_code == 503
        assert response.json()["error"]["code"] == RENDERER_UNAVAILABLE
