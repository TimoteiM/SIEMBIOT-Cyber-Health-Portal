from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import psycopg
from fastapi.testclient import TestClient
from siembiot.auth import current_principal, require_trusted_origin
from siembiot.config import Settings
from siembiot.domains.manifests import canonical_manifest_bytes, manifest_allows_target
from siembiot.domains.signing import Ed25519ManifestSigner, ManifestKeySet
from siembiot.identity import NullIdentityResolver, Principal
from siembiot.main import create_app


def seed_verified_domain(
    owner_url: str, *, role: str = "organization_owner", domain: str = "example.com"
) -> tuple[UUID, UUID, Principal]:
    organization_id, user_id, domain_id = uuid4(), uuid4(), uuid4()
    with psycopg.connect(owner_url) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Authorization user')",
            (str(user_id), str(user_id), f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Authorization tenant', %s, %s)",
            (str(organization_id), f"auth-{organization_id.hex[:12]}", str(user_id)),
        )
        owner.execute(
            "INSERT INTO memberships (organization_id, user_id, role) VALUES (%s, %s, %s)",
            (str(organization_id), str(user_id), role),
        )
        owner.execute(
            "INSERT INTO domains "
            "(id, organization_id, canonical_name, unicode_display, registrable_domain, "
            "ownership_state, verified_at, reverification_due_at, created_by_user_id) "
            "VALUES (%s, %s, %s, %s, %s, 'verified', now(), now() + interval '30 days', %s)",
            (str(domain_id), str(organization_id), domain, domain, domain, str(user_id)),
        )
    principal = Principal(
        user_id=user_id,
        email=f"{user_id}@example.test",
        display_name="Authorization user",
    )
    return organization_id, domain_id, principal


def client_for(
    postgres_database: dict[str, str],
    principal: Principal,
    signer: Ed25519ManifestSigner,
) -> TestClient:
    app = create_app(
        settings=Settings(
            environment="test",
            public_base_url="https://portal.example.test",
            app_database_url=postgres_database["app_url"].replace(
                "postgresql://", "postgresql+psycopg://"
            ),
        ),
        manifest_signer=signer,
        identity_resolver=NullIdentityResolver(),
    )
    app.dependency_overrides[current_principal] = lambda: principal
    app.dependency_overrides[require_trusted_origin] = lambda: principal
    return TestClient(app, base_url="https://portal.example.test")


def authorization_body(domain_id: UUID) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "domain_ids": [str(domain_id)],
        "operation_classes": ["https_verification", "active_assessment"],
        "policy_version": "policy-v1",
        "consent_version": "consent-ro-v1",
        "consent_text": "Autorizez explicit operațiunile declarate pentru domeniul selectat.",
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(days=30)).isoformat(),
    }


def test_explicit_authorization_creates_verifiable_immutable_manifest_and_revokes(
    postgres_database: dict[str, str],
) -> None:
    organization_id, domain_id, principal = seed_verified_domain(postgres_database["owner_url"])
    signer = Ed25519ManifestSigner.generate("dev-test-key", development_only=True)
    consent = authorization_body(domain_id)["consent_text"]
    with client_for(postgres_database, principal, signer) as client:
        draft = client.post(
            f"/api/v1/organizations/{organization_id}/authorizations",
            json=authorization_body(domain_id),
        )
        assert draft.status_code == 201
        assert draft.json()["state"] == "draft"

        accepted = client.post(
            f"/api/v1/organizations/{organization_id}/authorizations/{draft.json()['id']}/accept"
        )
        assert accepted.status_code == 201
        manifest = accepted.json()
        assert manifest["key_id"] == "dev-test-key"
        assert "signature" not in manifest
        assert "canonical_payload" not in manifest

        revoked = client.post(
            f"/api/v1/organizations/{organization_id}/authorizations/{draft.json()['id']}/revoke",
            json={"reason": "Authorization withdrawn by the accountable owner"},
        )
        assert revoked.status_code == 200
        assert revoked.json()["state"] == "revoked"

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        authorization = owner.execute(
            "SELECT consent_text, consent_text_digest, state FROM assessment_authorizations "
            "WHERE id = %s",
            (draft.json()["id"],),
        ).fetchone()
        stored = owner.execute(
            "SELECT canonical_payload, payload_hash, signature, key_id, algorithm "
            "FROM scope_manifests WHERE id = %s",
            (manifest["id"],),
        ).fetchone()
    assert authorization == (
        consent,
        hashlib.sha256(str(consent).encode()).digest(),
        "revoked",
    )
    assert stored is not None
    payload, payload_hash, signature, key_id, algorithm = stored
    encoded = canonical_manifest_bytes(payload)
    assert payload_hash == hashlib.sha256(encoded).digest()
    assert ManifestKeySet([signer.public_key()]).verify(key_id, algorithm, encoded, signature)
    assert manifest_allows_target(payload, "example.com", "active_assessment")
    assert not manifest_allows_target(payload, "child.example.com", "active_assessment")
    assert json.dumps(payload, ensure_ascii=False).find(str(consent)) >= 0


def test_unverified_cross_tenant_and_low_role_authorizations_fail_closed(
    postgres_database: dict[str, str],
) -> None:
    owner_org, owner_domain, owner_principal = seed_verified_domain(
        postgres_database["owner_url"], domain="owner.example.com"
    )
    analyst_org, analyst_domain, analyst_principal = seed_verified_domain(
        postgres_database["owner_url"], role="analyst", domain="analyst.example.com"
    )
    signer = Ed25519ManifestSigner.generate("dev-test-key", development_only=True)
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        owner.execute(
            "UPDATE domains SET ownership_state = 'reverification_required' WHERE id = %s",
            (str(owner_domain),),
        )
    with client_for(postgres_database, owner_principal, signer) as owner_client:
        unverified = owner_client.post(
            f"/api/v1/organizations/{owner_org}/authorizations",
            json=authorization_body(owner_domain),
        )
        assert unverified.status_code == 409
        cross_tenant = owner_client.post(
            f"/api/v1/organizations/{owner_org}/authorizations",
            json=authorization_body(analyst_domain),
        )
        assert cross_tenant.status_code == 404
    with client_for(postgres_database, analyst_principal, signer) as analyst_client:
        denied = analyst_client.post(
            f"/api/v1/organizations/{analyst_org}/authorizations",
            json=authorization_body(analyst_domain),
        )
        assert denied.status_code == 403
