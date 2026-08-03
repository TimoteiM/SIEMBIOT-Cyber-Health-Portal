from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import psycopg
from fastapi.testclient import TestClient
from siembiot.auth import Principal, current_principal, require_csrf
from siembiot.config import Settings
from siembiot.main import create_app


def seed_finding(
    owner_url: str, *, role: str = "organization_owner"
) -> tuple[UUID, UUID, Principal]:
    org, user, domain = uuid4(), uuid4(), uuid4()
    with psycopg.connect(owner_url) as owner:
        owner.execute(
            "INSERT INTO users(id,oidc_issuer,oidc_subject,email,display_name) VALUES(%s,'https://idp.example.test',%s,%s,'Evidence API user')",
            (user, user, f"{user}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations(id,name,slug,created_by_user_id) VALUES(%s,'Evidence API',%s,%s)",
            (org, f"evidence-api-{org.hex[:10]}", user),
        )
        owner.execute(
            "INSERT INTO memberships(organization_id,user_id,role) VALUES(%s,%s,%s)",
            (org, user, role),
        )
        owner.execute(
            "INSERT INTO domains(id,organization_id,canonical_name,unicode_display,registrable_domain,created_by_user_id) VALUES(%s,%s,'evidence.example.test','evidence.example.test','evidence.example.test',%s)",
            (domain, org, user),
        )
        authorization_row = owner.execute(
            "INSERT INTO assessment_authorizations(organization_id,authorized_by_user_id,policy_version,consent_version,consent_text_digest,valid_from,valid_until) VALUES(%s,%s,'v1','v1',%s,now(),now()+interval '1 day') RETURNING id",
            (org, user, bytes(32)),
        ).fetchone()
        assert authorization_row is not None
        authorization = authorization_row[0]
        manifest_row = owner.execute(
            "INSERT INTO scope_manifests(organization_id,authorization_id,manifest_version,canonical_payload,payload_hash,signature,key_id,algorithm) VALUES(%s,%s,'v1','{}',%s,%s,'fixture-key','EdDSA') RETURNING id",
            (org, authorization, org.bytes * 2, user.bytes * 4),
        ).fetchone()
        assert manifest_row is not None
        manifest = manifest_row[0]
        finding_row = owner.execute(
            "INSERT INTO findings(organization_id,asset_id,scope_manifest_id,evidence_mode,fingerprint,fingerprint_version,identity_digest,check_id,policy_hash,attribution_state,severity,first_seen_at,publishable,classification) VALUES(%s,%s,%s,'fixture',%s,'fingerprint-v1',%s,'dns.dnssec',%s,'direct','high',now(),false,'DEMO/FIXTURE') RETURNING id",
            (org, domain, manifest, bytes([1]) * 32, bytes([2]) * 32, bytes([3]) * 32),
        ).fetchone()
        assert finding_row is not None
        finding = finding_row[0]
    principal = Principal(
        session_id=uuid4(),
        user_id=user,
        email=f"{user}@example.test",
        display_name="Evidence API user",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        csrf_hash=bytes(32),
    )
    return org, finding, principal


def client_for(postgres_database: dict[str, str], principal: Principal) -> TestClient:
    app = create_app(
        settings=Settings(
            environment="test",
            public_base_url="https://portal.example.test",
            database_url=postgres_database["app_url"].replace(
                "postgresql://", "postgresql+psycopg://"
            ),
        )
    )
    app.dependency_overrides[current_principal] = lambda: principal
    app.dependency_overrides[require_csrf] = lambda: principal
    return TestClient(app, base_url="https://portal.example.test")


def test_fixture_finding_is_visibly_classified_and_decisions_append_events(
    postgres_database: dict[str, str],
) -> None:
    org, finding, principal = seed_finding(postgres_database["owner_url"])
    with client_for(postgres_database, principal) as client:
        listed = client.get(f"/api/v1/organizations/{org}/evidence/findings")
        assert listed.status_code == 200
        assert listed.json()[0]["classification"] == "DEMO/FIXTURE"
        assert listed.json()[0]["publishable"] is False
        decision = client.post(
            f"/api/v1/organizations/{org}/evidence/findings/{finding}/events",
            json={
                "event_type": "suppressed",
                "reason": "Approved temporary suppression for review",
                "scope_reference": "scope-a",
                "review_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
            },
        )
        assert decision.status_code == 201
        history = client.get(f"/api/v1/organizations/{org}/evidence/findings/{finding}/history")
        assert history.status_code == 200
        assert history.json()[0]["event_type"] == "suppressed"


def test_cross_tenant_and_low_role_decisions_are_denied(postgres_database: dict[str, str]) -> None:
    owner_org, finding, owner = seed_finding(postgres_database["owner_url"])
    analyst_org, _, analyst = seed_finding(postgres_database["owner_url"], role="analyst")
    with client_for(postgres_database, analyst) as client:
        assert client.get(f"/api/v1/organizations/{owner_org}/evidence/findings").status_code in {
            403,
            404,
        }
        response = client.post(
            f"/api/v1/organizations/{analyst_org}/evidence/findings/{finding}/events",
            json={
                "event_type": "reopened",
                "reason": "Attempted cross tenant mutation",
                "scope_reference": "scope-a",
            },
        )
        assert response.status_code in {403, 404}
