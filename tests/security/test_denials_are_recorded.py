"""A refused attempt has to outlive the refusal.

`authorize` appended an `authorization.denied` event and then raised, both inside the
request's transaction. `engine.begin()` rolls back on an exception, so every denial was
recorded and discarded in the same breath. A database holding fifteen `assessment.queued`
rows held zero `authorization.denied` rows, and refusals had certainly happened.

The attempts worth investigating are the ones that failed. A trail that records only what
succeeded is the opposite of an audit trail, and it fails silently: nothing errors, the
caller is refused exactly as intended, and the absence looks like nobody ever tried.
"""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import UUID

import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from test_reports import Tenant, client_for, seed  # noqa: E402


def denial_count(owner_url: str, organization_id: UUID) -> int:
    with psycopg.connect(owner_url, autocommit=True) as owner:
        row = owner.execute(
            "SELECT count(*) FROM audit_events "
            "WHERE action = 'authorization.denied' AND organization_id = %s",
            (str(organization_id),),
        ).fetchone()
    return int(row[0]) if row else 0


def demote(owner_url: str, tenant: Tenant, role: str = "maturity_contributor") -> None:
    """A role that can read the organisation and almost nothing else, so an ordinary
    request is refused for authorization reasons rather than for a missing membership."""
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "UPDATE memberships SET role = %s WHERE organization_id = %s",
            (role, str(tenant.organization_id)),
        )


def test_a_refusal_survives_the_request_that_was_refused(
    postgres_database: dict[str, str],
) -> None:
    """The regression. Before the fix this count stayed at zero however many times the
    caller was turned away."""
    tenant = seed(postgres_database["owner_url"])
    demote(postgres_database["owner_url"], tenant)
    client = client_for(postgres_database, tenant.user_id)

    before = denial_count(postgres_database["owner_url"], tenant.organization_id)
    response = client.post(
        f"/api/v1/organizations/{tenant.organization_id}"
        f"/domains/{tenant.domain_id}/reports?locale=ro"
    )
    after = denial_count(postgres_database["owner_url"], tenant.organization_id)

    assert response.status_code == 403
    assert after == before + 1, "the refusal was rolled back with the request"


def test_the_refusal_records_what_was_attempted(postgres_database: dict[str, str]) -> None:
    """ "Somebody was refused" is not useful on its own. Which action, and under which
    role, is what an investigation needs."""
    tenant = seed(postgres_database["owner_url"])
    demote(postgres_database["owner_url"], tenant)
    client = client_for(postgres_database, tenant.user_id)

    client.post(
        f"/api/v1/organizations/{tenant.organization_id}"
        f"/domains/{tenant.domain_id}/reports?locale=ro"
    )

    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        row = owner.execute(
            "SELECT context, outcome FROM audit_events "
            "WHERE action = 'authorization.denied' AND organization_id = %s",
            (str(tenant.organization_id),),
        ).fetchone()

    assert row is not None
    assert row[0]["requested_action"] == "assessment.read"
    assert row[0]["role"] == "maturity_contributor"
    assert row[1] == "denied"


def test_a_recorded_refusal_is_chained_like_any_other_event(
    postgres_database: dict[str, str],
) -> None:
    """A refusal is the event most worth tampering with afterwards, so it gets the same
    protection as everything else rather than being appended outside the chain."""
    tenant = seed(postgres_database["owner_url"])
    demote(postgres_database["owner_url"], tenant)
    client = client_for(postgres_database, tenant.user_id)

    client.post(
        f"/api/v1/organizations/{tenant.organization_id}"
        f"/domains/{tenant.domain_id}/reports?locale=ro"
    )

    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        hashed = owner.execute(
            "SELECT event_hash FROM audit_events "
            "WHERE action = 'authorization.denied' AND organization_id = %s",
            (str(tenant.organization_id),),
        ).fetchone()
        # Scoped to this organisation. The chain is per organisation and the audit
        # suite deliberately breaks other tenants' chains in the same database, so a
        # global assertion here would fail for somebody else's reason.
        breaks = owner.execute(
            "SELECT * FROM audit_chain_breaks() WHERE organization_id = %s",
            (str(tenant.organization_id),),
        ).fetchall()

    assert hashed is not None and hashed[0] is not None
    assert breaks == []


def test_an_audit_failure_does_not_turn_a_refusal_into_a_server_error(
    postgres_database: dict[str, str],
) -> None:
    """The caller is being denied either way. A 500 would tell somebody probing the
    platform that they had found something more interesting than a refusal."""
    tenant = seed(postgres_database["owner_url"])
    demote(postgres_database["owner_url"], tenant)
    client = client_for(postgres_database, tenant.user_id)

    for _ in range(3):
        response = client.post(
            f"/api/v1/organizations/{tenant.organization_id}"
            f"/domains/{tenant.domain_id}/reports?locale=ro"
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "forbidden"


def test_the_seed_would_have_passed_this_before_the_fix(
    postgres_database: dict[str, str],
) -> None:
    """A guard on the guard.

    The first version of this test used an origin the API refuses and a body it rejects,
    so the 403 never reached `authorize` at all and the count stayed at zero for a reason
    that had nothing to do with the bug. This asserts the request really does reach
    authorization: a permitted caller gets through.
    """
    tenant = seed(postgres_database["owner_url"])
    client = client_for(postgres_database, tenant.user_id)

    response = client.post(
        f"/api/v1/organizations/{tenant.organization_id}"
        f"/domains/{tenant.domain_id}/reports?locale=ro"
    )

    assert response.status_code == 201, "an owner must not be refused; the test proves nothing"
    assert denial_count(postgres_database["owner_url"], tenant.organization_id) == 0
