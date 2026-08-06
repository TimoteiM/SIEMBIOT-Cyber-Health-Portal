from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import psycopg
from fastapi.testclient import TestClient
from siembiot.auth import current_principal, require_trusted_origin
from siembiot.config import Settings
from siembiot.db import Database
from siembiot.domains.network_adapter import DatabaseNetworkPolicy
from siembiot.identity import NullIdentityResolver, Principal
from siembiot.main import create_app
from siembiot_worker.network_safety.models import BrokerCheckpoint, VerificationFetchRequest
from siembiot_worker.network_safety.url_policy import VerificationDestination


def seed_owner(owner_url: str) -> tuple[UUID, Principal]:
    organization_id = uuid4()
    user_id = uuid4()
    with psycopg.connect(owner_url) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Security test user')",
            (str(user_id), str(user_id), f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Kill switch tenant', %s, %s)",
            (str(organization_id), f"kill-{organization_id.hex[:12]}", str(user_id)),
        )
        owner.execute(
            "INSERT INTO memberships (organization_id, user_id, role) "
            "VALUES (%s, %s, 'organization_owner')",
            (str(organization_id), str(user_id)),
        )
    return organization_id, Principal(
        user_id=user_id,
        email=f"{user_id}@example.test",
        display_name="Security test user",
    )


def _client(
    postgres_database: dict[str, str], organization_id: UUID, principal: Principal
) -> tuple[TestClient, Settings]:
    del organization_id
    settings = Settings(
        environment="test",
        public_base_url="https://portal.example.test",
        app_database_url=postgres_database["app_url"].replace(
            "postgresql://", "postgresql+psycopg://"
        ),
    )
    app = create_app(settings=settings, identity_resolver=NullIdentityResolver())
    app.dependency_overrides[current_principal] = lambda: principal
    app.dependency_overrides[require_trusted_origin] = lambda: principal
    return TestClient(app, base_url="https://portal.example.test"), settings


def _domain_and_challenge(
    client: TestClient, organization_id: UUID
) -> tuple[dict[str, object], dict[str, object]]:
    domain = client.post(
        f"/api/v1/organizations/{organization_id}/domains",
        json={"domain": "example.com"},
    ).json()
    challenge = client.post(
        f"/api/v1/organizations/{organization_id}/domains/{domain['id']}/challenges",
        json={"method": "https_file"},
    ).json()
    return domain, challenge


def test_tenant_kill_switch_cancels_queued_operations(
    postgres_database: dict[str, str],
) -> None:
    organization_id, principal = seed_owner(postgres_database["owner_url"])
    client, _ = _client(postgres_database, organization_id, principal)
    with client:
        domain, _ = _domain_and_challenge(client, organization_id)
        operation_id = uuid4()
        with psycopg.connect(postgres_database["owner_url"]) as owner:
            owner.execute(
                "INSERT INTO network_operations "
                "(id, organization_id, domain_id, operation_class) VALUES (%s, %s, %s, %s)",
                (
                    str(operation_id),
                    str(organization_id),
                    domain["id"],
                    "https_verification",
                ),
            )
        activated = client.post(
            f"/api/v1/organizations/{organization_id}/emergency-controls",
            json={
                "scope": "operation_class",
                "operation_class": "https_verification",
                "reason": "Suspend queued verification operations now",
            },
        )
        assert activated.status_code == 201
        with psycopg.connect(postgres_database["owner_url"]) as owner:
            status = owner.execute(
                "SELECT status, reason_code, cancel_requested_at IS NOT NULL, "
                "completed_at IS NOT NULL FROM network_operations WHERE id = %s",
                (str(operation_id),),
            ).fetchone()
        assert status == ("cancelled", "emergency_control_active", True, True)


def test_policy_rereads_database_and_rejects_new_control_without_stale_cache(
    postgres_database: dict[str, str],
) -> None:
    organization_id, principal = seed_owner(postgres_database["owner_url"])
    client, settings = _client(postgres_database, organization_id, principal)
    with client:
        domain, challenge = _domain_and_challenge(client, organization_id)
    database = Database(settings.app_database_url)
    request = VerificationFetchRequest(
        organization_id=organization_id,
        domain_id=UUID(str(domain["id"])),
        challenge_id=UUID(str(challenge["id"])),
        canonical_host="example.com",
        authorized_redirect_hosts=("example.com",),
    )
    destination = VerificationDestination.https("example.com")
    with database.tenant_connection(principal.user_id, organization_id) as connection:
        policy = DatabaseNetworkPolicy(connection)
        assert policy.authorize(request, BrokerCheckpoint.BEFORE_RESOLUTION, destination).allowed
        with psycopg.connect(postgres_database["owner_url"]) as owner:
            owner.execute(
                "INSERT INTO emergency_controls "
                "(scope, organization_id, reason, created_by_user_id) "
                "VALUES ('organization', %s, %s, %s)",
                (
                    str(organization_id),
                    "Concurrent emergency control for cache test",
                    str(principal.user_id),
                ),
            )
        denied = policy.authorize(request, BrokerCheckpoint.BEFORE_CONNECT, destination)
        assert not denied.allowed
        assert denied.reason_code == "emergency_control_active"
    database.close()


def test_authorization_revocation_cancels_manifest_queued_work(
    postgres_database: dict[str, str],
) -> None:
    organization_id, principal = seed_owner(postgres_database["owner_url"])
    client, _ = _client(postgres_database, organization_id, principal)
    with client:
        domain = client.post(
            f"/api/v1/organizations/{organization_id}/domains",
            json={"domain": "example.com"},
        ).json()
        with psycopg.connect(postgres_database["owner_url"]) as owner:
            owner.execute(
                "UPDATE domains SET ownership_state = 'verified', verified_at = now(), "
                "reverification_due_at = now() + interval '30 days' WHERE id = %s",
                (domain["id"],),
            )
        valid_from = datetime.now(UTC)
        authorization = client.post(
            f"/api/v1/organizations/{organization_id}/authorizations",
            json={
                "domain_ids": [domain["id"]],
                "operation_classes": ["https_verification"],
                "policy_version": "scope-v1",
                "consent_version": "ro-v1",
                "consent_text": (
                    "Autorizez explicit domeniul exact pentru această verificare limitată."
                ),
                "valid_from": valid_from.isoformat(),
                "valid_until": (valid_from + timedelta(hours=1)).isoformat(),
            },
        ).json()
        manifest = client.post(
            f"/api/v1/organizations/{organization_id}/authorizations/{authorization['id']}/accept"
        ).json()
        operation_id = uuid4()
        with psycopg.connect(postgres_database["owner_url"]) as owner:
            owner.execute(
                "INSERT INTO network_operations "
                "(id, organization_id, domain_id, manifest_id, operation_class) "
                "VALUES (%s, %s, %s, %s, 'https_verification')",
                (
                    str(operation_id),
                    str(organization_id),
                    domain["id"],
                    manifest["id"],
                ),
            )
        revoked = client.post(
            f"/api/v1/organizations/{organization_id}/authorizations/{authorization['id']}/revoke",
            json={"reason": "Authorization withdrawn immediately by owner"},
        )
        assert revoked.status_code == 200
        with psycopg.connect(postgres_database["owner_url"]) as owner:
            status = owner.execute(
                "SELECT status, reason_code, cancel_requested_at IS NOT NULL "
                "FROM network_operations WHERE id = %s",
                (str(operation_id),),
            ).fetchone()
        assert status == ("cancelled", "authorization_revoked", True)
