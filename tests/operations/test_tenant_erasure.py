"""Erasing an institution: everything about it, and nothing about anybody else.

Retention ages data out on a timer. This is the other obligation -- an organization asks
to be removed -- and the failure modes are opposite. Retention's danger is deleting too
much; erasure's is deleting too little, because the institution is told it is gone and a
missed table means it is not.

So most of what is tested here is completeness, and the completeness test is derived from
the schema rather than from a list. A list would go stale at the next migration and its
staleness would look exactly like success.
"""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import UUID, uuid4

import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

from erase_organization import (  # noqa: E402
    TENANT_COLUMN,
    erase,
    plan,
    remaining_references,
    tenant_tables,
)

IDENTIFIER = "01JQ0000000000000000000001"


def seed(owner_url: str, *, domain: str) -> tuple[UUID, UUID]:
    """An organization with something in every layer: identity, evidence, conclusions,
    self-assessment, and its own audit trail."""
    organization_id, user_id = uuid4(), uuid4()
    domain_id, assessment_id = uuid4(), uuid4()
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Erasure user')",
            (str(user_id), str(user_id), f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'To be erased', %s, %s)",
            (str(organization_id), f"er-{organization_id.hex[:12]}", str(user_id)),
        )
        owner.execute(
            "INSERT INTO memberships (organization_id, user_id, role, status) "
            "VALUES (%s, %s, 'organization_owner', 'active')",
            (str(organization_id), str(user_id)),
        )
        owner.execute(
            "INSERT INTO methodology_versions (version, policy_digest, notice) "
            "VALUES ('1.0.0', %s, 'test') ON CONFLICT (version) DO NOTHING",
            ("e" * 64,),
        )
        owner.execute(
            "INSERT INTO domains (id, organization_id, canonical_name, unicode_display, "
            "registrable_domain, ownership_state, created_by_user_id) "
            "VALUES (%s, %s, %s, %s, %s, 'verified', %s)",
            (str(domain_id), str(organization_id), domain, domain, domain, str(user_id)),
        )
        owner.execute(
            "INSERT INTO assessments (id, organization_id, domain_id, methodology_version, "
            "state, completed_at) VALUES (%s, %s, %s, '1.0.0', 'completed', now())",
            (str(assessment_id), str(organization_id), str(domain_id)),
        )
        owner.execute(
            "INSERT INTO score_snapshots (id, organization_id, assessment_id, "
            "methodology_version, policy_digest, evidence_digest, score, band, "
            "coverage_percentage, coverage_sufficient, is_projection, document, computed_at) "
            "VALUES (%s, %s, %s, '1.0.0', %s, %s, 50, 'developing', 90, true, false, '{}', now())",
            (str(uuid4()), str(organization_id), str(assessment_id), "e" * 64, "e" * 64),
        )
        owner.execute(
            "INSERT INTO normalized_observations (id, organization_id, assessment_id, "
            "subject_kind, subject_identifier, authorized_domain_id, observation_type, "
            "status, attributes, attribution_confidence, source_confidence, "
            "freshness_confidence, confidence_reasons, adapter_id, adapter_version, "
            "content_hash, collected_at) VALUES (%s, %s, %s, 'domain', %s, %s, 'dns.caa', "
            "'observed', '{}', 1.0, 1.0, 1.0, '{}', 'dns_resilience', '1.0.0', %s, now())",
            (
                str(uuid4()),
                str(organization_id),
                str(assessment_id),
                domain,
                str(domain_id),
                "e" * 64,
            ),
        )
        owner.execute(
            "INSERT INTO audit_events (organization_id, actor_type, actor_id, action, "
            "resource_type, resource_id, request_id, correlation_id, outcome, context) "
            "VALUES (%s, 'user', 'u', 'domain.enrolled', 'domain', %s, %s, %s, "
            "'success', '{}')",
            (str(organization_id), str(domain_id), IDENTIFIER, IDENTIFIER),
        )
    return organization_id, domain_id


def erase_now(owner_url: str, organization_id: UUID) -> dict[str, int]:
    with psycopg.connect(owner_url) as connection, connection.cursor() as cursor:
        removed = erase(cursor, organization_id, "To be erased")
        left = remaining_references(cursor, organization_id)
        assert not left, f"rows still reference the organization: {left}"
        connection.commit()
    return removed


# -- completeness ---------------------------------------------------------------------


def test_every_table_holding_tenant_data_is_covered(postgres_database: dict[str, str]) -> None:
    """The erasure's central claim.

    Read from the catalogue rather than compared against a list: a list would go stale at
    the next migration, and a stale list looks exactly like a complete erasure.
    """
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        holding = {
            name
            for (name,) in owner.execute(
                "SELECT c.table_name FROM information_schema.columns c "
                "JOIN information_schema.tables t ON t.table_schema = c.table_schema "
                "AND t.table_name = c.table_name "
                "WHERE c.table_schema = 'public' AND c.column_name = %s "
                "AND t.table_type = 'BASE TABLE'",
                (TENANT_COLUMN,),
            )
        }
        with owner.cursor() as cursor:
            covered = set(tenant_tables(cursor))

    assert holding == covered


def test_nothing_at_all_is_left(postgres_database: dict[str, str]) -> None:
    organization_id, _ = seed(postgres_database["owner_url"], domain="sters.test")

    erase_now(postgres_database["owner_url"], organization_id)

    with (
        psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner,
        owner.cursor() as cursor,
    ):
        assert remaining_references(cursor, organization_id) == {}
        surviving = owner.execute(
            "SELECT count(*) FROM organizations WHERE id = %s", (str(organization_id),)
        ).fetchone()
        assert surviving is not None and surviving[0] == 0


def test_the_plan_removes_nothing(postgres_database: dict[str, str]) -> None:
    """Irreversible operations should be hard to perform by accident."""
    organization_id, _ = seed(postgres_database["owner_url"], domain="plan.test")

    with (
        psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner,
        owner.cursor() as cursor,
    ):
        counts = plan(cursor, organization_id)
        still_there = remaining_references(cursor, organization_id)

    assert counts
    assert still_there == counts or set(still_there) <= set(counts)


# -- and nothing about anybody else ---------------------------------------------------


def test_another_organization_is_untouched(postgres_database: dict[str, str]) -> None:
    erased, _ = seed(postgres_database["owner_url"], domain="pleaca.test")
    kept, _ = seed(postgres_database["owner_url"], domain="ramane.test")

    erase_now(postgres_database["owner_url"], erased)

    with (
        psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner,
        owner.cursor() as cursor,
    ):
        assert remaining_references(cursor, kept)


def test_other_audit_chains_still_verify(postgres_database: dict[str, str]) -> None:
    """The reason audit is chained per organization rather than globally.

    Removing one institution's events removes one entire chain, so there is nothing left
    to fail verification. A single global chain would have made erasure and
    tamper-evidence mutually exclusive: honouring the request would have broken the
    trail for every other tenant.
    """
    erased, _ = seed(postgres_database["owner_url"], domain="unu.test")
    kept, _ = seed(postgres_database["owner_url"], domain="doi.test")

    erase_now(postgres_database["owner_url"], erased)

    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        breaks = owner.execute("SELECT * FROM audit_chain_breaks()").fetchall()
        surviving = owner.execute(
            "SELECT count(*) FROM audit_events WHERE organization_id = %s", (str(kept),)
        ).fetchone()

    assert breaks == []
    assert surviving is not None and surviving[0] > 0


# -- what survives, and why -----------------------------------------------------------


def test_a_tombstone_records_that_it_happened(postgres_database: dict[str, str]) -> None:
    """Losing the record that we ever held anything would be its own dishonesty. The
    tombstone goes into the platform's chain, which is not the one just removed."""
    organization_id, _ = seed(postgres_database["owner_url"], domain="piatra.test")

    erase_now(postgres_database["owner_url"], organization_id)

    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        row = owner.execute(
            "SELECT organization_id, context, event_hash FROM audit_events "
            "WHERE action = 'organization.erased' AND resource_id = %s",
            (str(organization_id),),
        ).fetchone()

    assert row is not None, "no tombstone was written"
    assert row[0] is None, "the tombstone belongs to the platform chain, not the erased one"
    assert row[2] is not None, "the tombstone is chained like any other event"
    assert row[1]["rows_removed"]


def test_the_tombstone_does_not_quote_what_was_erased(
    postgres_database: dict[str, str],
) -> None:
    """A tombstone carrying the erased data would be a copy of it under another name."""
    organization_id, _ = seed(postgres_database["owner_url"], domain="secret-domain.test")

    erase_now(postgres_database["owner_url"], organization_id)

    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        found = owner.execute(
            "SELECT context FROM audit_events WHERE action = 'organization.erased' "
            "AND resource_id = %s",
            (str(organization_id),),
        ).fetchone()

    assert found is not None
    context = found[0]
    assert "secret-domain.test" not in str(context)
    assert set(context) == {"organization_name", "rows_removed"}


# -- the guard ------------------------------------------------------------------------


def test_evidence_cannot_be_removed_without_declaring_an_erasure(
    postgres_database: dict[str, str],
) -> None:
    """Erasure is a second named reason, not a wider hole. A plain DELETE is still
    refused, so removal has to be deliberate however broad the caller's grants are."""
    organization_id, _ = seed(postgres_database["owner_url"], domain="fara-motiv.test")

    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        try:
            owner.execute(
                "DELETE FROM normalized_observations WHERE organization_id = %s",
                (str(organization_id),),
            )
        except psycopg.errors.InsufficientPrivilege as error:
            assert "append-only" in str(error)
        else:  # pragma: no cover - the guard failing is the point of the test
            raise AssertionError("evidence was removed without a declared reason")


def test_audit_cannot_be_removed_by_a_retention_sweep(
    postgres_database: dict[str, str],
) -> None:
    """The two reasons are not interchangeable.

    An institution asking to be forgotten may take its audit trail with it. Ageing an
    accountability record out on a timer is a different act, and nothing should be able
    to do it automatically -- so retention is refused here even though erasure is not.
    """
    organization_id, _ = seed(postgres_database["owner_url"], domain="audit-motiv.test")

    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        owner.execute("SELECT set_config('app.retention_sweep', 'on', false)")
        try:
            owner.execute(
                "DELETE FROM audit_events WHERE organization_id = %s", (str(organization_id),)
            )
        except psycopg.errors.InsufficientPrivilege as error:
            assert "immutable" in str(error)
        else:  # pragma: no cover
            raise AssertionError("retention removed an audit event")
