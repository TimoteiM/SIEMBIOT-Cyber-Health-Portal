"""Make the audit trail actually tamper-evident.

`audit_events` has carried `previous_hash` and `event_hash` since the first migration,
with a CHECK constraint fixing them at 32 bytes. Nothing ever wrote them. Every row in
every deployment has both columns null, so the trail was append-only -- a trigger stops
the application rewriting it -- and not tamper-evident: anybody who could reach the
database directly could insert, alter or reorder history and nothing would notice.

That distinction matters more than it sounds. Append-only protects against the
application; a chain protects against whoever has the credentials, which is the case an
audit trail exists for.

**Computed in the database, not in the application.** A hash written by
`append_audit_event` would only cover rows inserted through it, and the whole point is
to detect the writes that did not go through the usual path. A `BEFORE INSERT` trigger
covers every writer, including psql.

**One chain per organization.** A single global chain would serialize every audit write
in the product behind one lock. Per-organization chains keep the guarantee where it is
useful -- an institution's own history cannot be edited without detection -- at the cost
of not ordering events across tenants, which nobody needs. Events with no organization
form their own chain.

**Position is part of what is signed.** Each row carries a `sequence_number` from a
single sequence, and it is inside the hashed content, so deleting a row from the middle
or reordering two rows breaks verification rather than going unnoticed.

**Existing rows are deliberately not backfilled.** Hashing them now would compute a
digest of whatever they say today: if anything had already been altered, the backfill
would certify the altered version and the chain would report a spotless history. That is
worse than no chain, because it looks like assurance. Rows written before this migration
therefore stay unhashed and are reported as what they are -- predating tamper-evidence.

They cannot be used to hide anything later, because the verifier requires the unchained
rows to be a contiguous prefix. A row inserted afterwards with no hash -- which needs the
trigger disabled -- lands after chained rows and breaks that, so the attempt shows up as
a break rather than as another old row.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0019_audit_chain"
down_revision: str | Sequence[str] | None = "0018_retention"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        ALTER TABLE audit_events ADD COLUMN sequence_number bigserial;
        CREATE UNIQUE INDEX audit_events_sequence_idx ON audit_events (sequence_number);

        -- A serial column brings a sequence, and INSERT on the table does not carry
        -- permission to advance it. Granted to exactly the roles that already hold
        -- INSERT here -- without this every audit write in the product fails, which is
        -- how the test suite found it.
        GRANT USAGE ON SEQUENCE audit_events_sequence_number_seq TO siembiot_app;

        -- What a row hashes over: everything about it except the two hash columns.
        --
        -- Derived from `to_jsonb` rather than by listing fields, so a column added later
        -- is covered automatically. A list would silently stop protecting whatever
        -- somebody forgot to add to it, which is the failure this whole migration is
        -- about. `jsonb`'s text form sorts its keys, so the serialization is canonical.
        CREATE FUNCTION audit_event_content(event audit_events) RETURNS bytea
        LANGUAGE sql IMMUTABLE AS $$
            SELECT convert_to(
                ((to_jsonb(event) - 'event_hash' - 'previous_hash')::text), 'UTF8'
            )
        $$;

        CREATE FUNCTION audit_event_digest(previous bytea, event audit_events)
        RETURNS bytea LANGUAGE sql IMMUTABLE AS $$
            SELECT sha256(coalesce(previous, '\x'::bytea) || audit_event_content(event))
        $$;

        -- The chain is built here rather than by the application: a hash written by one
        -- code path only covers rows that took it, and the writes worth detecting are
        -- exactly the ones that did not.
        CREATE FUNCTION audit_chain_link() RETURNS trigger
        LANGUAGE plpgsql AS $$
        DECLARE
            previous bytea;
        BEGIN
            -- Serializes writers within one organization, so two concurrent events
            -- cannot both read the same predecessor and produce a fork. Held to the end
            -- of the transaction, and taken per organization so an audit write for one
            -- institution never waits on another's.
            PERFORM pg_advisory_xact_lock(
                hashtextextended(
                    'audit:' || coalesce(NEW.organization_id::text, 'platform'), 0
                )
            );

            SELECT event_hash INTO previous
            FROM audit_events
            WHERE organization_id IS NOT DISTINCT FROM NEW.organization_id
            ORDER BY sequence_number DESC
            LIMIT 1;

            NEW.previous_hash := previous;
            NEW.event_hash := audit_event_digest(previous, NEW);
            RETURN NEW;
        END
        $$;

        CREATE TRIGGER audit_events_chain
            BEFORE INSERT ON audit_events
            FOR EACH ROW EXECUTE FUNCTION audit_chain_link();

        -- Recompute the chains and return the first break in each.
        --
        -- Per organization, not the first break overall: stopping at the first would let
        -- one tenant's damaged trail hide the state of everybody else's, and "is this
        -- institution's history intact" is the question this answers. Returns rows rather
        -- than raising, so a caller learns what is wrong and where. An empty result is an
        -- intact trail.
        CREATE FUNCTION audit_chain_breaks()
        RETURNS TABLE (
            organization_id uuid,
            sequence_number bigint,
            occurred_at timestamptz,
            problem text
        )
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
        DECLARE
            row_record audit_events%ROWTYPE;
            expected bytea;
            current_org uuid;
            first_row boolean := true;
            seen_chained boolean := false;
            broken boolean := false;
        BEGIN
            FOR row_record IN
                SELECT * FROM audit_events AS a
                ORDER BY a.organization_id NULLS FIRST, a.sequence_number
            LOOP
                IF first_row OR row_record.organization_id IS DISTINCT FROM current_org THEN
                    expected := NULL;
                    current_org := row_record.organization_id;
                    first_row := false;
                    seen_chained := false;
                    broken := false;
                END IF;

                -- One report per chain. Everything after a break is unverifiable by
                -- definition, so listing it would be noise rather than more evidence.
                CONTINUE WHEN broken;

                -- Rows written before this migration have no hash. They are legitimate
                -- only as a contiguous prefix: once a chained row has been seen, an
                -- unhashed one after it means the trigger was disabled to insert it.
                IF row_record.event_hash IS NULL THEN
                    IF seen_chained THEN
                        organization_id := row_record.organization_id;
                        sequence_number := row_record.sequence_number;
                        occurred_at := row_record.occurred_at;
                        problem := 'an unhashed event follows hashed ones: it was '
                                   'inserted with the chain trigger disabled';
                        RETURN NEXT;
                        broken := true;
                        CONTINUE;
                    END IF;
                    CONTINUE;
                END IF;

                -- The first chained row of a chain must point at nothing, and this is
                -- checked rather than assumed. The trigger reads the latest event_hash for
                -- the organization, which is null both for a brand new chain and for one
                -- that begins after unhashed rows -- so a non-null previous_hash here can
                -- only mean the chained row that came before it was deleted.
                --
                -- The first draft took the row's own previous_hash as the expected value,
                -- to accommodate chains starting mid-table. That accommodation let anyone
                -- remove events from the front of a chain undetected, which is exactly
                -- where somebody covering their tracks would start.
                seen_chained := true;

                IF row_record.previous_hash IS DISTINCT FROM expected THEN
                    organization_id := row_record.organization_id;
                    sequence_number := row_record.sequence_number;
                    occurred_at := row_record.occurred_at;
                    problem := 'previous_hash does not match the preceding event: a row '
                               'was removed, reordered, or inserted out of band';
                    RETURN NEXT;
                    broken := true;
                    CONTINUE;
                END IF;

                expected := audit_event_digest(expected, row_record);
                IF row_record.event_hash IS DISTINCT FROM expected THEN
                    organization_id := row_record.organization_id;
                    sequence_number := row_record.sequence_number;
                    occurred_at := row_record.occurred_at;
                    problem := 'event_hash does not match this row''s contents: the row '
                               'was altered after it was written';
                    RETURN NEXT;
                    broken := true;
                    CONTINUE;
                END IF;
            END LOOP;
        END
        $$;

        REVOKE ALL ON FUNCTION audit_chain_breaks() FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION audit_chain_breaks() TO siembiot_owner, siembiot_app;
        """
    )


def downgrade() -> None:
    op.execute(
        r"""
        DROP TRIGGER IF EXISTS audit_events_chain ON audit_events;
        DROP FUNCTION IF EXISTS audit_chain_breaks();
        DROP FUNCTION IF EXISTS audit_chain_link();
        DROP FUNCTION IF EXISTS audit_event_digest(bytea, audit_events);
        DROP FUNCTION IF EXISTS audit_event_content(audit_events);
        REVOKE ALL ON SEQUENCE audit_events_sequence_number_seq FROM siembiot_app;
        DROP INDEX IF EXISTS audit_events_sequence_idx;
        ALTER TABLE audit_events DROP COLUMN IF EXISTS sequence_number;
        """
    )
