"""Planned work, and whether the evidence agrees it happened.

The case worth most of this file: somebody marks a fix complete and the next assessment
still sees the weakness. That disagreement is the product's whole reason for existing --
an assertion and an observation coming apart -- so it has to be surfaced rather than
reconciled, and marking work done must never close a finding.
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
DIGEST = "f" * 64


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
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Ana Popescu')",
            (str(user_id), str(user_id), f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Tenant', %s, %s)",
            (str(organization_id), f"rm-{organization_id.hex[:12]}", str(user_id)),
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
            "VALUES (%s, %s, 'road.test', 'road.test', 'road.test', 'verified', %s)",
            (str(domain_id), str(organization_id), str(user_id)),
        )
    return Tenant(organization_id, user_id, domain_id)


def add_finding(
    owner_url: str,
    tenant: Tenant,
    *,
    check_id: str = "B.spf_present",
    severity: str = "high",
    state: str = "open",
) -> UUID:
    finding_id = uuid4()
    now = datetime.now(UTC)
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO findings (id, organization_id, fingerprint, check_id, check_version, "
            "methodology_version, pillar, subject_kind, subject_identifier, "
            "authorized_domain_id, severity, state, public_safety_class, "
            "attribution_confidence, source_confidence, freshness_confidence, "
            "first_seen_at, last_seen_at, resolved_at) "
            "VALUES (%s, %s, %s, %s, '1.0.0', %s, 'email', 'domain', 'road.test', %s, %s, %s, "
            "'public_profile', 1.00, 1.00, 1.00, %s, %s, %s)",
            (
                str(finding_id),
                str(tenant.organization_id),
                finding_id.hex + finding_id.hex,
                check_id,
                METHODOLOGY,
                str(tenant.domain_id),
                severity,
                state,
                now,
                now,
                now if state == "resolved" else None,
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
        user_id=tenant.user_id, email="ana@example.test", display_name="Ana Popescu"
    )
    app.dependency_overrides[current_principal] = lambda: principal
    app.dependency_overrides[require_trusted_origin] = lambda: principal
    return TestClient(app, base_url=BASE_URL)


def action_url(tenant: Tenant, finding_id: UUID) -> str:
    return f"/api/v1/organizations/{tenant.organization_id}/findings/{finding_id}/action"


def roadmap(client: TestClient, tenant: Tenant) -> dict[str, Any]:
    body: dict[str, Any] = client.get(
        f"/api/v1/organizations/{tenant.organization_id}/domains/{tenant.domain_id}/roadmap"
    ).json()
    return body


# -- assertion against observation -------------------------------------------


def test_marking_work_complete_does_not_close_the_finding(
    postgres_database: dict[str, str],
) -> None:
    """Nothing a user types changes what was measured. Only the next run does."""
    tenant = seed(postgres_database["owner_url"])
    finding_id = add_finding(postgres_database["owner_url"], tenant)

    with client_for(postgres_database, tenant) as client:
        client.put(action_url(tenant, finding_id), json={"status": "completed"})

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        state = owner.execute(
            "SELECT state FROM findings WHERE id = %s", (str(finding_id),)
        ).fetchone()
    assert state is not None and state[0] == "open"


def test_completed_work_with_the_weakness_still_observed_is_contradicted(
    postgres_database: dict[str, str],
) -> None:
    """The case this feature exists for.

    Either the fix did not work or it was applied somewhere the assessment does not
    reach. Both are worth somebody's attention, and neither is served by quietly
    trusting one side.
    """
    tenant = seed(postgres_database["owner_url"])
    finding_id = add_finding(postgres_database["owner_url"], tenant)

    with client_for(postgres_database, tenant) as client:
        action = client.put(action_url(tenant, finding_id), json={"status": "completed"}).json()
        summary = roadmap(client, tenant)

    assert action["verification"] == "asserted_not_observed"
    assert action["finding_state"] == "open"
    assert summary["contradicted_count"] == 1


def test_completed_work_the_evidence_agrees_with_is_confirmed(
    postgres_database: dict[str, str],
) -> None:
    tenant = seed(postgres_database["owner_url"])
    finding_id = add_finding(postgres_database["owner_url"], tenant, state="resolved")

    with client_for(postgres_database, tenant) as client:
        action = client.put(action_url(tenant, finding_id), json={"status": "completed"}).json()

    assert action["verification"] == "confirmed"


def test_a_weakness_that_went_away_on_its_own_is_named_as_such(
    postgres_database: dict[str, str],
) -> None:
    """Worth knowing: it may have been fixed outside the tool, or changed by accident."""
    tenant = seed(postgres_database["owner_url"])
    finding_id = add_finding(postgres_database["owner_url"], tenant, state="resolved")

    with client_for(postgres_database, tenant) as client:
        action = client.put(action_url(tenant, finding_id), json={"status": "planned"}).json()

    assert action["verification"] == "resolved_without_action"


def test_suppressing_a_finding_does_not_confirm_the_work(
    postgres_database: dict[str, str],
) -> None:
    """Deciding not to fix something is not evidence that it was fixed."""
    tenant = seed(postgres_database["owner_url"])
    finding_id = add_finding(postgres_database["owner_url"], tenant, state="accepted_risk")

    with client_for(postgres_database, tenant) as client:
        action = client.put(action_url(tenant, finding_id), json={"status": "completed"}).json()

    assert action["verification"] == "asserted_not_observed"


# -- the plan ----------------------------------------------------------------


def test_findings_nobody_has_planned_for_are_counted(
    postgres_database: dict[str, str],
) -> None:
    """The gap between what is known and what anybody intends to do -- the number a
    list of tasks never shows, because it is about what is absent from the list."""
    tenant = seed(postgres_database["owner_url"])
    planned = add_finding(postgres_database["owner_url"], tenant, check_id="B.spf_present")
    add_finding(postgres_database["owner_url"], tenant, check_id="A.caa_present")
    add_finding(postgres_database["owner_url"], tenant, check_id="C.hsts_present")

    with client_for(postgres_database, tenant) as client:
        client.put(action_url(tenant, planned), json={"status": "planned"})
        summary = roadmap(client, tenant)

    assert summary["unplanned_count"] == 2
    assert len(summary["actions"]) == 1


def test_an_action_past_its_date_is_overdue(postgres_database: dict[str, str]) -> None:
    tenant = seed(postgres_database["owner_url"])
    finding_id = add_finding(postgres_database["owner_url"], tenant)
    past = (datetime.now(UTC) - timedelta(days=3)).isoformat()

    with client_for(postgres_database, tenant) as client:
        action = client.put(
            action_url(tenant, finding_id), json={"status": "in_progress", "due_at": past}
        ).json()
        summary = roadmap(client, tenant)

    assert action["overdue"] is True
    assert summary["overdue_count"] == 1


def test_completed_work_is_never_overdue(postgres_database: dict[str, str]) -> None:
    """A date that has passed on finished work is history, not a problem."""
    tenant = seed(postgres_database["owner_url"])
    finding_id = add_finding(postgres_database["owner_url"], tenant)
    past = (datetime.now(UTC) - timedelta(days=3)).isoformat()

    with client_for(postgres_database, tenant) as client:
        action = client.put(
            action_url(tenant, finding_id), json={"status": "completed", "due_at": past}
        ).json()

    assert action["overdue"] is False


def test_work_can_be_left_unassigned(postgres_database: dict[str, str]) -> None:
    """Unassigned work is a real and common state; requiring a name would produce a
    fictional one."""
    tenant = seed(postgres_database["owner_url"])
    finding_id = add_finding(postgres_database["owner_url"], tenant)

    with client_for(postgres_database, tenant) as client:
        action = client.put(action_url(tenant, finding_id), json={"status": "planned"}).json()

    assert action["owner_user_id"] is None
    assert action["owner_display_name"] is None


def test_an_owner_must_be_a_member_of_the_organization(
    postgres_database: dict[str, str],
) -> None:
    """Otherwise the screen shows a name and nobody is accountable behind it."""
    tenant = seed(postgres_database["owner_url"])
    outsider = seed(postgres_database["owner_url"])
    finding_id = add_finding(postgres_database["owner_url"], tenant)

    with client_for(postgres_database, tenant) as client:
        response = client.put(
            action_url(tenant, finding_id),
            json={"status": "planned", "owner_user_id": str(outsider.user_id)},
        )
    assert response.status_code == 422


def test_editing_a_note_does_not_restate_when_work_finished(
    postgres_database: dict[str, str],
) -> None:
    """The completion time is a fact about the work, not about the last edit."""
    tenant = seed(postgres_database["owner_url"])
    finding_id = add_finding(postgres_database["owner_url"], tenant)

    with client_for(postgres_database, tenant) as client:
        first = client.put(action_url(tenant, finding_id), json={"status": "completed"}).json()
        second = client.put(
            action_url(tenant, finding_id),
            json={"status": "completed", "note": "Deployed via the DNS provider."},
        ).json()

    assert second["completed_at"] == first["completed_at"]
    assert second["note"] == "Deployed via the DNS provider."


def test_reopening_clears_the_completion_time(postgres_database: dict[str, str]) -> None:
    tenant = seed(postgres_database["owner_url"])
    finding_id = add_finding(postgres_database["owner_url"], tenant)

    with client_for(postgres_database, tenant) as client:
        client.put(action_url(tenant, finding_id), json={"status": "completed"})
        reopened = client.put(action_url(tenant, finding_id), json={"status": "in_progress"}).json()

    assert reopened["completed_at"] is None
    assert reopened["verification"] == "in_flight"


# -- history and boundaries --------------------------------------------------


def test_status_changes_are_recorded(postgres_database: dict[str, str]) -> None:
    """So an action that was overdue for a month and then quietly re-dated still shows
    that it was."""
    tenant = seed(postgres_database["owner_url"])
    finding_id = add_finding(postgres_database["owner_url"], tenant)

    with client_for(postgres_database, tenant) as client:
        client.put(action_url(tenant, finding_id), json={"status": "planned"})
        client.put(action_url(tenant, finding_id), json={"status": "in_progress"})
        client.put(action_url(tenant, finding_id), json={"status": "completed"})

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        rows = owner.execute(
            "SELECT from_status, to_status FROM remediation_action_history h "
            "JOIN remediation_actions a ON a.id = h.action_id "
            "WHERE a.finding_id = %s ORDER BY h.occurred_at",
            (str(finding_id),),
        ).fetchall()

    assert [row[1] for row in rows] == ["planned", "in_progress", "completed"]
    assert rows[0][0] is None


def test_a_read_only_role_cannot_plan_work(postgres_database: dict[str, str]) -> None:
    """Planning is not reading. The roles that can start an assessment own what
    happens to a domain."""
    tenant = seed(postgres_database["owner_url"], role="viewer_auditor")
    finding_id = add_finding(postgres_database["owner_url"], tenant)

    with client_for(postgres_database, tenant) as client:
        assert (
            client.get(
                f"/api/v1/organizations/{tenant.organization_id}/domains/{tenant.domain_id}/roadmap"
            ).status_code
            == 200
        )
        assert (
            client.put(action_url(tenant, finding_id), json={"status": "planned"}).status_code
            == 403
        )


def test_planning_against_another_tenants_finding_is_not_found(
    postgres_database: dict[str, str],
) -> None:
    mine = seed(postgres_database["owner_url"])
    theirs = seed(postgres_database["owner_url"])
    their_finding = add_finding(postgres_database["owner_url"], theirs)

    with client_for(postgres_database, mine) as client:
        response = client.put(action_url(mine, their_finding), json={"status": "planned"})
    assert response.status_code == 404
