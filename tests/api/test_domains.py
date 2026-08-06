from __future__ import annotations

import hashlib
from uuid import UUID, uuid4

import psycopg
from fastapi.testclient import TestClient
from siembiot.auth import current_principal, require_trusted_origin
from siembiot.config import Settings
from siembiot.identity import NullIdentityResolver, Principal
from siembiot.main import create_app


class MutableTXTResolver:
    def __init__(self) -> None:
        self.records: tuple[str, ...] = ()
        self.queries: list[str] = []

    def resolve_txt(self, name: str) -> tuple[str, ...]:
        self.queries.append(name)
        return self.records


def seed_owner(owner_url: str, *, role: str = "organization_owner") -> tuple[UUID, Principal]:
    organization_id = uuid4()
    user_id = uuid4()
    with psycopg.connect(owner_url) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Domain API user')",
            (str(user_id), str(user_id), f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Domain API tenant', %s, %s)",
            (str(organization_id), f"api-{organization_id.hex[:12]}", str(user_id)),
        )
        owner.execute(
            "INSERT INTO memberships (organization_id, user_id, role) VALUES (%s, %s, %s)",
            (str(organization_id), str(user_id), role),
        )
    principal = Principal(
        user_id=user_id,
        email=f"{user_id}@example.test",
        display_name="Domain API user",
    )
    return organization_id, principal


def client_for(
    postgres_database: dict[str, str], principal: Principal, resolver: MutableTXTResolver
) -> TestClient:
    settings = Settings(
        environment="test",
        public_base_url="https://portal.example.test",
        app_database_url=postgres_database["app_url"].replace(
            "postgresql://", "postgresql+psycopg://"
        ),
        domain_challenge_ttl_seconds=900,
        domain_challenge_create_limit_per_hour=3,
    )
    app = create_app(
        settings=settings, txt_resolver=resolver, identity_resolver=NullIdentityResolver()
    )
    app.dependency_overrides[current_principal] = lambda: principal
    app.dependency_overrides[require_trusted_origin] = lambda: principal
    return TestClient(app, base_url="https://portal.example.test")


def test_domain_dns_challenge_verifies_without_storing_or_auditing_plaintext(
    postgres_database: dict[str, str],
) -> None:
    organization_id, principal = seed_owner(postgres_database["owner_url"])
    resolver = MutableTXTResolver()
    with client_for(postgres_database, principal, resolver) as client:
        created = client.post(
            f"/api/v1/organizations/{organization_id}/domains",
            json={"domain": "ȘCOALĂ.ro"},
        )
        assert created.status_code == 201
        domain = created.json()
        assert domain["canonical_name"] == "xn--coal-3sa77n.ro"
        assert domain["ownership_state"] == "pending"

        challenge_response = client.post(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}/challenges",
            json={"method": "dns_txt"},
        )
        assert challenge_response.status_code == 201
        challenge = challenge_response.json()
        token = challenge.pop("verification_token")
        assert challenge["verification_location"] == "_tyche-verify.xn--coal-3sa77n.ro"

        with psycopg.connect(postgres_database["owner_url"]) as owner:
            stored = owner.execute(
                "SELECT token_digest FROM domain_challenges WHERE id = %s",
                (challenge["id"],),
            ).fetchone()
            assert stored == (hashlib.sha256(token.encode()).digest(),)
            audit_text = " ".join(
                str(row[0])
                for row in owner.execute(
                    "SELECT context::text FROM audit_events WHERE organization_id = %s",
                    (str(organization_id),),
                )
            )
            event_text = " ".join(
                str(row[0])
                for row in owner.execute(
                    "SELECT context::text FROM domain_verification_events "
                    "WHERE organization_id = %s",
                    (str(organization_id),),
                )
            )
        assert token not in audit_text
        assert token not in event_text

        resolver.records = (token,)
        verified = client.post(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}"
            f"/challenges/{challenge['id']}/verify"
        )
        assert verified.status_code == 200
        assert verified.json()["ownership_state"] == "verified"
        assert resolver.queries == ["_tyche-verify.xn--coal-3sa77n.ro"]

        replay = client.post(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}"
            f"/challenges/{challenge['id']}/verify"
        )
        assert replay.status_code == 409


def test_challenge_expiry_active_uniqueness_rate_limit_and_revocation(
    postgres_database: dict[str, str],
) -> None:
    organization_id, principal = seed_owner(postgres_database["owner_url"])
    resolver = MutableTXTResolver()
    with client_for(postgres_database, principal, resolver) as client:
        domain = client.post(
            f"/api/v1/organizations/{organization_id}/domains",
            json={"domain": "limits.example.com"},
        ).json()
        first = client.post(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}/challenges",
            json={"method": "dns_txt"},
        )
        assert first.status_code == 201
        duplicate = client.post(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}/challenges",
            json={"method": "dns_txt"},
        )
        assert duplicate.status_code == 409
        revoked = client.delete(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}"
            f"/challenges/{first.json()['id']}"
        )
        assert revoked.status_code == 204

        second = client.post(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}/challenges",
            json={"method": "dns_txt"},
        )
        assert second.status_code == 201
        client.delete(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}"
            f"/challenges/{second.json()['id']}"
        )
        third = client.post(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}/challenges",
            json={"method": "dns_txt"},
        )
        assert third.status_code == 201
        client.delete(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}"
            f"/challenges/{third.json()['id']}"
        )
        limited = client.post(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}/challenges",
            json={"method": "dns_txt"},
        )
        assert limited.status_code == 429

        with psycopg.connect(postgres_database["owner_url"]) as owner:
            owner.execute(
                "UPDATE domain_challenges SET state = 'pending', revoked_at = NULL, "
                "created_at = now() - interval '20 minutes', "
                "expires_at = now() - interval '1 second' WHERE id = %s",
                (third.json()["id"],),
            )
        expired = client.post(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}"
            f"/challenges/{third.json()['id']}/verify"
        )
        assert expired.status_code == 410


def test_domain_object_authorization_denies_cross_tenant_and_analyst_mutation(
    postgres_database: dict[str, str],
) -> None:
    owner_org, owner_principal = seed_owner(postgres_database["owner_url"])
    analyst_org, analyst_principal = seed_owner(postgres_database["owner_url"], role="analyst")
    resolver = MutableTXTResolver()
    with client_for(postgres_database, owner_principal, resolver) as owner_client:
        domain = owner_client.post(
            f"/api/v1/organizations/{owner_org}/domains", json={"domain": "private.example.com"}
        ).json()
    with client_for(postgres_database, analyst_principal, resolver) as analyst_client:
        own_mutation = analyst_client.post(
            f"/api/v1/organizations/{analyst_org}/domains", json={"domain": "denied.example.com"}
        )
        assert own_mutation.status_code == 403
        cross_tenant = analyst_client.get(
            f"/api/v1/organizations/{owner_org}/domains/{domain['id']}"
        )
        assert cross_tenant.status_code in {403, 404}


def test_verification_attempt_budget_fails_closed_and_audits_safe_outcomes(
    postgres_database: dict[str, str],
) -> None:
    organization_id, principal = seed_owner(postgres_database["owner_url"])
    resolver = MutableTXTResolver()
    with client_for(postgres_database, principal, resolver) as client:
        domain = client.post(
            f"/api/v1/organizations/{organization_id}/domains",
            json={"domain": "attempts.example.com"},
        ).json()
        challenge = client.post(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}/challenges",
            json={"method": "dns_txt"},
        ).json()
        token = challenge["verification_token"]
        for _ in range(5):
            response = client.post(
                f"/api/v1/organizations/{organization_id}/domains/{domain['id']}"
                f"/challenges/{challenge['id']}/verify"
            )
            assert response.status_code == 409

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        challenge_state = owner.execute(
            "SELECT state, attempts FROM domain_challenges WHERE id = %s", (challenge["id"],)
        ).fetchone()
        domain_state = owner.execute(
            "SELECT ownership_state FROM domains WHERE id = %s", (domain["id"],)
        ).fetchone()
        audit_rows = owner.execute(
            "SELECT action, outcome, context::text FROM audit_events "
            "WHERE organization_id = %s AND action = 'domain.verification_attempted'",
            (str(organization_id),),
        ).fetchall()
    assert challenge_state == ("failed", 5)
    assert domain_state == ("failed",)
    assert len(audit_rows) == 5
    assert all(row[1] == "failure" and token not in row[2] for row in audit_rows)
