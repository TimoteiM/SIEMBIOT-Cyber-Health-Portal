"""Let a whole organization be removed, and say which reason applied.

Retention gave the append-only triggers a single exception: a transaction that sets
`app.retention_sweep` may delete. Erasing an institution on request is the other lawful
reason to remove data, and it is not retention -- so it gets its own name rather than
borrowing one that would make the two indistinguishable at the moment of deletion.

Both are still narrow. Every other UPDATE and DELETE on evidence is refused exactly as
before, and neither setting grants anything by itself: the grants decide who may delete,
and these settings decide whether a deletion was deliberate.

Nothing here schedules anything. Erasure is run by a person, as the owner, against one
named organization -- see `scripts/erase_organization.py` for why it has no role and no
job of its own.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0020_tenant_erasure"
down_revision: str | Sequence[str] | None = "0019_audit_chain"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE OR REPLACE FUNCTION app_data_removal_reason() RETURNS text
        LANGUAGE sql STABLE AS $$
            SELECT CASE
                WHEN coalesce(current_setting('app.retention_sweep', true), '') = 'on'
                    THEN 'retention'
                WHEN coalesce(current_setting('app.tenant_erasure', true), '') = 'on'
                    THEN 'erasure'
                ELSE NULL
            END
        $$;

        CREATE OR REPLACE FUNCTION prevent_row_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE' AND app_data_removal_reason() IS NOT NULL THEN
                RETURN OLD;
            END IF;
            RAISE EXCEPTION '% rows are append-only', TG_TABLE_NAME USING ERRCODE = '42501';
        END
        $$;

        CREATE OR REPLACE FUNCTION prevent_snapshot_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF app_data_removal_reason() IS NOT NULL THEN
                IF TG_OP = 'DELETE' THEN
                    RETURN OLD;
                END IF;
                -- Still the single permitted UPDATE, and still only under retention:
                -- erasure removes the row rather than annotating it, so a snapshot being
                -- edited during an erasure would mean something had gone wrong.
                IF TG_OP = 'UPDATE'
                   AND app_data_removal_reason() = 'retention'
                   AND OLD.evidence_erased_at IS NULL
                   AND NEW.evidence_erased_at IS NOT NULL
                   AND (to_jsonb(NEW) - 'evidence_erased_at')
                       = (to_jsonb(OLD) - 'evidence_erased_at') THEN
                    RETURN NEW;
                END IF;
            END IF;
            RAISE EXCEPTION 'score_snapshots rows are append-only' USING ERRCODE = '42501';
        END
        $$;

        -- Audit is immutable, and erasure is the one thing that may remove it: an
        -- institution that asks to be forgotten cannot be told "except for the record of
        -- everything you did". Retention is deliberately *not* accepted here -- ageing
        -- out an accountability trail is a different act, and nothing should be able to
        -- do it on a timer.
        CREATE OR REPLACE FUNCTION prevent_audit_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE'
               AND coalesce(current_setting('app.tenant_erasure', true), '') = 'on' THEN
                RETURN OLD;
            END IF;
            RAISE EXCEPTION 'audit events are immutable' USING ERRCODE = '42501';
        END
        $$;
        """
    )


def downgrade() -> None:
    op.execute(
        r"""
        CREATE OR REPLACE FUNCTION prevent_audit_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'audit events are immutable' USING ERRCODE = '42501';
        END
        $$;

        CREATE OR REPLACE FUNCTION prevent_row_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE'
               AND coalesce(current_setting('app.retention_sweep', true), '') = 'on' THEN
                RETURN OLD;
            END IF;
            RAISE EXCEPTION '% rows are append-only', TG_TABLE_NAME USING ERRCODE = '42501';
        END
        $$;

        CREATE OR REPLACE FUNCTION prevent_snapshot_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF coalesce(current_setting('app.retention_sweep', true), '') = 'on' THEN
                IF TG_OP = 'DELETE' THEN
                    RETURN OLD;
                END IF;
                IF TG_OP = 'UPDATE'
                   AND OLD.evidence_erased_at IS NULL
                   AND NEW.evidence_erased_at IS NOT NULL
                   AND (to_jsonb(NEW) - 'evidence_erased_at')
                       = (to_jsonb(OLD) - 'evidence_erased_at') THEN
                    RETURN NEW;
                END IF;
            END IF;
            RAISE EXCEPTION 'score_snapshots rows are append-only' USING ERRCODE = '42501';
        END
        $$;

        DROP FUNCTION IF EXISTS app_data_removal_reason();
        """
    )
