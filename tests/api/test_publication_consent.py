"""Agreeing to be published, and the one promise that has to be kept synchronously.

Withdrawing consent is the action this file exists for. Anything queued, flagged or
scheduled leaves a window in which the honest answer to "is our data still on your
website" is yes, and that window is the entire problem. So the profile is deleted in the
same transaction that records the withdrawal, and these tests check the row is gone
rather than that something was marked.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
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
DIGEST = "a" * 64


class NullIdentityResolver:
    def resolve(self, request: object) -> None:  # pragma: no cover - never consulted
        return None


@dataclass(frozen=True)
class Tenant:
    organization_id: UUID
    user_id: UUID
    domain_id: UUID
    host: str


def seed(owner_url: str, *, ownership_state: str = "verified") -> Tenant:
    organization_id, user_id, domain_id = uuid4(), uuid4(), uuid4()
    host = f"pub-{organization_id.hex[:10]}.example.ro"
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Ana Popescu')",
            (str(user_id), str(user_id), f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Tenant', %s, %s)",
            (str(organization_id), f"pb-{organization_id.hex[:12]}", str(user_id)),
        )
        owner.execute(
            "INSERT INTO memberships (organization_id, user_id, role, status) "
            "VALUES (%s, %s, 'organization_owner', 'active')",
            (str(organization_id), str(user_id)),
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
    return Tenant(organization_id, user_id, domain_id, host)


def publish(owner_url: str, host: str) -> None:
    """Put a profile on the public page, the way the projector would."""
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO observatory.profiles (registrable_domain, band, "
            "coverage_percentage, methodology_version, policy_digest, observed_at) "
            "VALUES (%s, 'managed', 88.0, '1.0.0', %s, now())",
            (host, DIGEST),
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
        user_id=tenant.user_id, email="ana@example.test", display_name="Ana Popescu"
    )
    app.dependency_overrides[current_principal] = lambda: principal
    app.dependency_overrides[require_trusted_origin] = lambda: principal
    return TestClient(app, base_url=BASE_URL)


def url(tenant: Tenant) -> str:
    return f"/api/v1/organizations/{tenant.organization_id}/domains/{tenant.domain_id}/publication"


def test_withdrawing_consent_removes_the_published_profile(
    postgres_database: dict[str, str],
) -> None:
    tenant = seed(postgres_database["owner_url"])
    publish(postgres_database["owner_url"], tenant.host)

    with client_for(postgres_database, tenant) as client:
        client.put(url(tenant))
        body = client.request("DELETE", url(tenant), json={"reason": "council decision"}).json()

    assert body["consented"] is False
    assert body["published_at"] is None

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        remaining = owner.execute(
            "SELECT count(*) FROM observatory.profiles WHERE registrable_domain = %s",
            (tenant.host,),
        ).fetchone()
    # Deleted, not hidden. A flag survives in caches and in queries written later by
    # somebody who did not know to check it.
    assert remaining is not None and remaining[0] == 0


def test_consent_alone_publishes_nothing(postgres_database: dict[str, str]) -> None:
    """Nobody puts their own institution on a public page by clicking once."""
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        body = client.put(url(tenant)).json()

    assert body["consented"] is True
    assert body["published_at"] is None


def test_consenting_requires_verified_control(postgres_database: dict[str, str]) -> None:
    """Publishing a posture under an institution's name, for a domain nobody proved they
    hold, is publishing about a third party."""
    tenant = seed(postgres_database["owner_url"], ownership_state="pending")
    with client_for(postgres_database, tenant) as client:
        response = client.put(url(tenant))

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "ownership_not_verified"


def test_withdrawal_is_recorded_rather_than_erased(
    postgres_database: dict[str, str],
) -> None:
    """Whether they ever agreed, and when they withdrew, stays answerable afterwards."""
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        client.put(url(tenant))
        client.request("DELETE", url(tenant), json={"reason": "council decision"})

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        row = owner.execute(
            "SELECT granted_at IS NOT NULL, revoked_at IS NOT NULL, revocation_reason "
            "FROM publication_consents WHERE domain_id = %s",
            (str(tenant.domain_id),),
        ).fetchone()
    assert row == (True, True, "council decision")


def test_withdrawing_needs_no_explanation(postgres_database: dict[str, str]) -> None:
    """Requiring a reason would be friction on exactly the action that must not have any."""
    tenant = seed(postgres_database["owner_url"])
    publish(postgres_database["owner_url"], tenant.host)
    with client_for(postgres_database, tenant) as client:
        client.put(url(tenant))
        response = client.request("DELETE", url(tenant), json={})

    assert response.status_code == 200
    assert response.json()["published_at"] is None


def test_consent_and_publication_are_reported_separately(
    postgres_database: dict[str, str],
) -> None:
    """Consent is permission; published_at is fact.

    Inferring one from the other is how an interface ends up telling somebody they are
    published when they are not, or worse, the reverse.
    """
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        consented = client.put(url(tenant)).json()
        publish(postgres_database["owner_url"], tenant.host)
        published = client.get(url(tenant)).json()

    assert consented["consented"] is True and consented["published_at"] is None
    assert published["consented"] is True and published["published_at"] is not None


def test_the_api_can_unpublish_and_cannot_publish(
    postgres_database: dict[str, str],
) -> None:
    """The asymmetry in the grants, asserted as the API's own role.

    Removal is always safe -- the worst outcome is a missing page. Publication is the
    dangerous direction and belongs to the projector, behind the review interlock.
    """
    tenant = seed(postgres_database["owner_url"])
    publish(postgres_database["owner_url"], tenant.host)

    with psycopg.connect(postgres_database["app_url"], autocommit=True) as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(
                "INSERT INTO observatory.profiles (registrable_domain, "
                "coverage_percentage, methodology_version, policy_digest, observed_at) "
                "VALUES ('unauthorized.example.ro', 100, '1.0.0', %s, now())",
                (DIGEST,),
            )
        # And the direction that is allowed still works.
        app.execute(
            "DELETE FROM observatory.profiles WHERE registrable_domain = %s",
            (tenant.host,),
        )
