"""Assessment and asset-candidate endpoints.

Two properties get the most attention here: progress must be counted from settled
steps rather than elapsed time, and deciding what belongs in scope must stay with the
roles that manage domains rather than everyone who can read findings.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from siembiot.config import Settings
from siembiot.identity import NullIdentityResolver, Principal
from siembiot.main import create_app

BASE_URL = "https://portal.example.test"
METHODOLOGY = "1.0.0"
DIGEST = "a" * 64


@dataclass(frozen=True)
class Tenant:
    organization_id: UUID
    user_id: UUID
    domain_id: UUID
    principal: Principal


def seed(
    owner_url: str, *, role: str = "organization_owner", ownership: str = "verified"
) -> Tenant:
    organization_id, user_id, domain_id = uuid4(), uuid4(), uuid4()
    with psycopg.connect(owner_url) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Assessment user')",
            (str(user_id), str(user_id), f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Tenant', %s, %s)",
            (str(organization_id), f"as-{organization_id.hex[:12]}", str(user_id)),
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
            "VALUES (%s, %s, 'example.test', 'example.test', 'example.test', %s, %s)",
            (str(domain_id), str(organization_id), ownership, str(user_id)),
        )
    return Tenant(
        organization_id=organization_id,
        user_id=user_id,
        domain_id=domain_id,
        principal=Principal(user_id, f"{user_id}@example.test", "Assessment user"),
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
    app.dependency_overrides[current_principal] = lambda: tenant.principal
    app.dependency_overrides[require_trusted_origin] = lambda: tenant.principal
    return TestClient(app, base_url=BASE_URL)


def create_assessment(client: TestClient, tenant: Tenant) -> dict[str, object]:
    response = client.post(
        f"/api/v1/organizations/{tenant.organization_id}/assessments",
        json={"domain_id": str(tenant.domain_id)},
    )
    assert response.status_code == 201, response.text
    return dict(response.json())


# -- creating and observing --------------------------------------------------


def test_a_new_assessment_is_queued_rather_than_run_inline(
    postgres_database: dict[str, str],
) -> None:
    """Collection takes minutes; a request that waited for it would tell nobody anything."""
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        assessment = create_assessment(client, tenant)
    assert assessment["state"] == "queued"
    assert assessment["completed_at"] is None
    assert assessment["score"] is None


def test_progress_starts_at_zero_and_counts_settled_steps(
    postgres_database: dict[str, str],
) -> None:
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        assessment = create_assessment(client, tenant)
        progress = assessment["progress"]
        assert isinstance(progress, dict)
        assert progress["settled_steps"] == 0
        assert progress["percentage"] == 0.0
        assert progress["total_steps"] > 0

        # A worker settles two steps.
        with psycopg.connect(postgres_database["owner_url"]) as owner:
            for name, state in (("plan", "succeeded"), ("collect.dns", "failed")):
                owner.execute(
                    "INSERT INTO assessment_steps "
                    "(organization_id, assessment_id, name, state) VALUES (%s, %s, %s, %s)",
                    (str(tenant.organization_id), str(assessment["id"]), name, state),
                )

        refreshed = client.get(
            f"/api/v1/organizations/{tenant.organization_id}/assessments/{assessment['id']}"
        ).json()
        assert refreshed["progress"]["settled_steps"] == 2
        assert refreshed["progress"]["succeeded_steps"] == 1
        assert refreshed["progress"]["failed_steps"] == ["collect.dns"]
        assert refreshed["progress"]["percentage"] > 0


def test_a_second_request_reuses_the_run_already_in_flight(
    postgres_database: dict[str, str],
) -> None:
    """Two concurrent runs would compete for the same evidence rows."""
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        first = create_assessment(client, tenant)
        second = client.post(
            f"/api/v1/organizations/{tenant.organization_id}/assessments",
            json={"domain_id": str(tenant.domain_id)},
        )
        assert second.status_code == 201
        assert second.json()["id"] == first["id"]


def test_an_assessment_for_an_unknown_domain_is_refused(
    postgres_database: dict[str, str],
) -> None:
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        response = client.post(
            f"/api/v1/organizations/{tenant.organization_id}/assessments",
            json={"domain_id": str(uuid4())},
        )
    assert response.status_code == 404


def test_creating_an_assessment_is_audited(postgres_database: dict[str, str]) -> None:
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        create_assessment(client, tenant)
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        actions = owner.execute(
            "SELECT action FROM audit_events WHERE organization_id = %s",
            (str(tenant.organization_id),),
        ).fetchall()
    assert ("assessment.queued",) in actions


# -- cancellation ------------------------------------------------------------


def test_cancellation_is_recorded_as_a_request(postgres_database: dict[str, str]) -> None:
    """Work in flight observes the request and settles itself; the API does not stop it."""
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        assessment = create_assessment(client, tenant)
        response = client.post(
            f"/api/v1/organizations/{tenant.organization_id}/assessments/{assessment['id']}/cancel",
            json={"reason": "authorization revoked"},
        )
        assert response.status_code == 200
        assert response.json()["cancellation_requested"] is True


def test_a_settled_assessment_cannot_be_cancelled(postgres_database: dict[str, str]) -> None:
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        assessment = create_assessment(client, tenant)
        with psycopg.connect(postgres_database["owner_url"]) as owner:
            owner.execute(
                "UPDATE assessments SET state = 'completed', completed_at = now() WHERE id = %s",
                (str(assessment["id"]),),
            )
        response = client.post(
            f"/api/v1/organizations/{tenant.organization_id}/assessments/{assessment['id']}/cancel",
            json={"reason": "too late"},
        )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "assessment_already_settled"


# -- authorization -----------------------------------------------------------


def test_a_read_only_role_cannot_start_an_assessment(
    postgres_database: dict[str, str],
) -> None:
    tenant = seed(postgres_database["owner_url"], role="viewer_auditor")
    with client_for(postgres_database, tenant) as client:
        response = client.post(
            f"/api/v1/organizations/{tenant.organization_id}/assessments",
            json={"domain_id": str(tenant.domain_id)},
        )
    assert response.status_code == 403


def test_a_read_only_role_may_still_observe_an_assessment(
    postgres_database: dict[str, str],
) -> None:
    tenant = seed(postgres_database["owner_url"], role="viewer_auditor")
    with client_for(postgres_database, tenant) as client:
        response = client.get(f"/api/v1/organizations/{tenant.organization_id}/assessments")
    assert response.status_code == 200


def test_another_tenants_assessment_is_not_found(postgres_database: dict[str, str]) -> None:
    owner_tenant = seed(postgres_database["owner_url"])
    other_tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, owner_tenant) as client:
        assessment = create_assessment(client, owner_tenant)

    with client_for(postgres_database, other_tenant) as intruder:
        response = intruder.get(
            f"/api/v1/organizations/{other_tenant.organization_id}/assessments/{assessment['id']}"
        )
    assert response.status_code == 404


# -- asset candidates --------------------------------------------------------


def insert_candidate(owner_url: str, tenant: Tenant, name: str = "www.example.test") -> UUID:
    with psycopg.connect(owner_url) as owner:
        row = owner.execute(
            "INSERT INTO asset_candidates (organization_id, domain_id, name, source, "
            "attribution_confidence, attribution_basis) "
            "VALUES (%s, %s, %s, 'certificate_transparency', 0.9, "
            "'subdomain_of_authorized_domain') RETURNING id::text",
            (str(tenant.organization_id), str(tenant.domain_id), name),
        ).fetchone()
    assert row is not None
    return UUID(row[0])


def test_candidates_are_listed_unreviewed(postgres_database: dict[str, str]) -> None:
    tenant = seed(postgres_database["owner_url"])
    insert_candidate(postgres_database["owner_url"], tenant)
    with client_for(postgres_database, tenant) as client:
        response = client.get(
            f"/api/v1/organizations/{tenant.organization_id}"
            f"/domains/{tenant.domain_id}/asset-candidates"
        )
    assert response.status_code == 200
    candidates = response.json()
    assert len(candidates) == 1
    assert candidates[0]["state"] == "unreviewed"
    assert candidates[0]["attribution_basis"] == "subdomain_of_authorized_domain"


def test_accepting_a_candidate_records_an_attributable_decision(
    postgres_database: dict[str, str],
) -> None:
    tenant = seed(postgres_database["owner_url"])
    candidate_id = insert_candidate(postgres_database["owner_url"], tenant)
    with client_for(postgres_database, tenant) as client:
        response = client.post(
            f"/api/v1/organizations/{tenant.organization_id}"
            f"/asset-candidates/{candidate_id}/decision",
            json={"decision": "accepted", "reason": "Confirmed ours"},
        )
    assert response.status_code == 200
    assert response.json()["state"] == "accepted"

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        decisions = owner.execute(
            "SELECT decision, actor_user_id::text FROM asset_candidate_decisions "
            "WHERE candidate_id = %s",
            (str(candidate_id),),
        ).fetchall()
        actions = owner.execute(
            "SELECT action FROM audit_events WHERE organization_id = %s",
            (str(tenant.organization_id),),
        ).fetchall()
    assert decisions == [("accepted", str(tenant.user_id))]
    assert ("asset.accepted",) in actions


def test_repeating_a_decision_is_refused(postgres_database: dict[str, str]) -> None:
    tenant = seed(postgres_database["owner_url"])
    candidate_id = insert_candidate(postgres_database["owner_url"], tenant)
    with client_for(postgres_database, tenant) as client:
        payload = {"decision": "rejected"}
        assert (
            client.post(
                f"/api/v1/organizations/{tenant.organization_id}"
                f"/asset-candidates/{candidate_id}/decision",
                json=payload,
            ).status_code
            == 200
        )
        repeat = client.post(
            f"/api/v1/organizations/{tenant.organization_id}"
            f"/asset-candidates/{candidate_id}/decision",
            json=payload,
        )
    assert repeat.status_code == 409
    assert repeat.json()["error"]["code"] == "decision_unchanged"


def test_an_analyst_may_read_candidates_but_not_decide_scope(
    postgres_database: dict[str, str],
) -> None:
    """Accepting an asset decides what may be assessed, so it is not a reporting action."""
    tenant = seed(postgres_database["owner_url"], role="analyst")
    candidate_id = insert_candidate(postgres_database["owner_url"], tenant)
    with client_for(postgres_database, tenant) as client:
        assert (
            client.get(
                f"/api/v1/organizations/{tenant.organization_id}"
                f"/domains/{tenant.domain_id}/asset-candidates"
            ).status_code
            == 200
        )
        denied = client.post(
            f"/api/v1/organizations/{tenant.organization_id}"
            f"/asset-candidates/{candidate_id}/decision",
            json={"decision": "accepted"},
        )
    assert denied.status_code == 403


def test_a_candidate_belonging_to_another_tenant_is_not_found(
    postgres_database: dict[str, str],
) -> None:
    owner_tenant = seed(postgres_database["owner_url"])
    other_tenant = seed(postgres_database["owner_url"])
    candidate_id = insert_candidate(postgres_database["owner_url"], owner_tenant)
    with client_for(postgres_database, other_tenant) as intruder:
        response = intruder.post(
            f"/api/v1/organizations/{other_tenant.organization_id}"
            f"/asset-candidates/{candidate_id}/decision",
            json={"decision": "accepted"},
        )
    assert response.status_code == 404


@pytest.mark.parametrize("decision", ["unreviewed", "maybe", ""])
def test_an_invented_decision_is_rejected_by_the_contract(
    postgres_database: dict[str, str], decision: str
) -> None:
    tenant = seed(postgres_database["owner_url"])
    candidate_id = insert_candidate(postgres_database["owner_url"], tenant)
    with client_for(postgres_database, tenant) as client:
        response = client.post(
            f"/api/v1/organizations/{tenant.organization_id}"
            f"/asset-candidates/{candidate_id}/decision",
            json={"decision": decision},
        )
    assert response.status_code == 422


# -- assessment modes --------------------------------------------------------


def test_passive_observation_needs_no_proof_of_control(
    postgres_database: dict[str, str],
) -> None:
    """The point of the mode.

    Passive observation reads DNS, RDAP, Certificate Transparency, the TLS handshake
    and the page any visitor sees. Requiring proof of control for that would be a
    ceremony that protects nobody, while putting the methodology out of reach of
    anyone evaluating a domain they do not run -- a regulator, a journalist, or
    somebody deciding whether to trust a supplier.
    """
    tenant = seed(postgres_database["owner_url"], ownership="pending")
    with client_for(postgres_database, tenant) as client:
        response = client.post(
            f"/api/v1/organizations/{tenant.organization_id}/assessments",
            json={"domain_id": str(tenant.domain_id), "mode": "passive_observation"},
        )
    assert response.status_code == 201
    assert response.json()["mode"] == "passive_observation"


def test_an_authorized_assessment_still_requires_verified_control(
    postgres_database: dict[str, str],
) -> None:
    """The wider mode keeps every requirement it had."""
    tenant = seed(postgres_database["owner_url"], ownership="pending")
    with client_for(postgres_database, tenant) as client:
        response = client.post(
            f"/api/v1/organizations/{tenant.organization_id}/assessments",
            json={"domain_id": str(tenant.domain_id), "mode": "authorized_assessment"},
        )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "ownership_not_verified"


def test_omitting_the_mode_gets_the_narrower_one(postgres_database: dict[str, str]) -> None:
    """A caller who says nothing must not be given the more intrusive behaviour."""
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        response = client.post(
            f"/api/v1/organizations/{tenant.organization_id}/assessments",
            json={"domain_id": str(tenant.domain_id)},
        )
    assert response.status_code == 201
    assert response.json()["mode"] == "passive_observation"


def test_an_unrecognised_mode_is_refused(postgres_database: dict[str, str]) -> None:
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        response = client.post(
            f"/api/v1/organizations/{tenant.organization_id}/assessments",
            json={"domain_id": str(tenant.domain_id), "mode": "authorized"},
        )
    assert response.status_code == 422


def test_the_mode_is_recorded_in_the_audit_trail(postgres_database: dict[str, str]) -> None:
    """An auditor must be able to answer "under what authority" from the log alone."""
    tenant = seed(postgres_database["owner_url"], ownership="pending")
    with client_for(postgres_database, tenant) as client:
        client.post(
            f"/api/v1/organizations/{tenant.organization_id}/assessments",
            json={"domain_id": str(tenant.domain_id), "mode": "passive_observation"},
        )
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        context = owner.execute(
            "SELECT context FROM audit_events WHERE action = 'assessment.queued' "
            "AND organization_id = %s",
            (str(tenant.organization_id),),
        ).fetchone()
    assert context is not None
    assert context[0]["mode"] == "passive_observation"


def test_an_authorized_run_cannot_exist_without_an_authorization(
    postgres_database: dict[str, str],
) -> None:
    """Enforced by the database, not by whichever code path created the row.

    Without this the mode column would be a label rather than a guarantee: any future
    caller could write 'authorized_assessment' with nothing backing it.
    """
    tenant = seed(postgres_database["owner_url"])
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        with pytest.raises(psycopg.errors.CheckViolation):
            owner.execute(
                "INSERT INTO assessments (id, organization_id, domain_id, "
                "methodology_version, state, mode) "
                "VALUES (%s, %s, %s, %s, 'queued', 'authorized_assessment')",
                (str(uuid4()), str(tenant.organization_id), str(tenant.domain_id), METHODOLOGY),
            )
