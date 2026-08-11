"""Retention: a record of what was removed, and a mark on what can no longer be proved.

Evidence accumulated indefinitely because nothing removed it. Sweeping it is the easy
half; the half that matters is being honest about the consequence.

A score snapshot carries a policy digest and an evidence digest precisely so that it can
be recomputed and checked. Once the observations underneath it are gone, it cannot be --
and nothing in the row would have said so. A reader would still see the digest and
reasonably conclude the workings were available. `evidence_erased_at` is that missing
sentence: after it is set, the score stands as a record of what was found and stops
claiming to be reproducible.

`retention_runs` records each sweep. Not for tidiness: deletion of tenant data is an act
somebody may later have to account for, and "the job runs nightly" is not an answer to
"what did you delete on the fourteenth". Counts per table, not identifiers -- a list of
what was erased, retained forever, would defeat the erasure.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0018_retention"
down_revision: str | Sequence[str] | None = "0017_report_grants"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE score_snapshots
            ADD COLUMN evidence_erased_at timestamptz NULL;

        COMMENT ON COLUMN score_snapshots.evidence_erased_at IS
            'When the observations this score was computed from were removed under '
            'retention. While null, the score can be recomputed and checked against '
            'its digests; once set, it is a record of a finding rather than a '
            'reproducible calculation, and reports say so.';

        CREATE TABLE retention_runs (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            started_at timestamptz NOT NULL DEFAULT now(),
            finished_at timestamptz NULL,

            -- Counts per table. Deliberately not the identifiers of what was removed:
            -- keeping a permanent list of erased rows would defeat the erasure.
            removed jsonb NOT NULL DEFAULT '{}'::jsonb,

            -- Set when a sweep failed part way. A partial sweep is safe -- the next one
            -- removes whatever was left -- but it should be visible rather than
            -- indistinguishable from a clean run that had nothing to do.
            error text NULL
        );

        CREATE INDEX retention_runs_started_idx ON retention_runs (started_at DESC);

        -- No row-level security and no tenant column. A retention run is platform
        -- housekeeping across every tenant, and the counts are not one organization's
        -- data.
        GRANT SELECT ON retention_runs TO siembiot_app;
        """
    )

    # -- the role that may forget things ------------------------------------------
    #
    # Nothing could delete evidence, and that was correct until now: the app and worker
    # roles hold INSERT and SELECT only, and the tables carry append-only triggers so
    # that a completed assessment cannot be quietly rewritten.
    #
    # Retention needs one narrow hole in that, and the safe way to make a hole is to give
    # it its own role rather than widen an existing one. `siembiot_retention` can delete
    # expired rows from the tables the schedule names and do nothing else -- it cannot
    # insert, cannot alter a finding, cannot read the publication schema, and holds no
    # privilege on any table outside the sweep.
    #
    # It carries BYPASSRLS because retention is genuinely cross-tenant: it operates on
    # every organization at once, so there is no tenant to scope it to and a policy-based
    # version would need a permissive policy on every swept table, which is a larger hole
    # than this one. The bypass is bounded by the grants, which are the actual boundary.
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'siembiot_retention') THEN
                CREATE ROLE siembiot_retention
                    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS;
            END IF;
        END
        $$;

        GRANT USAGE ON SCHEMA public TO siembiot_retention;

        GRANT SELECT, DELETE ON normalized_observations TO siembiot_retention;
        GRANT SELECT, DELETE ON network_operations TO siembiot_retention;
        GRANT SELECT, DELETE ON scope_manifests TO siembiot_retention;
        GRANT SELECT, DELETE ON assessment_step_attempts TO siembiot_retention;
        GRANT SELECT, DELETE ON report_grants TO siembiot_retention;
        GRANT SELECT, DELETE ON domain_challenges TO siembiot_retention;
        GRANT SELECT, DELETE ON workflow_idempotency_keys TO siembiot_retention;

        -- Read, and write exactly one column. Column-level grants are unusual and
        -- deliberate: this role must be able to record that evidence is gone and must
        -- not be able to touch a score, a band or a digest.
        GRANT SELECT ON score_snapshots TO siembiot_retention;
        GRANT UPDATE (evidence_erased_at) ON score_snapshots TO siembiot_retention;

        -- It reads assessments to tell a run whose evidence was erased from one that has
        -- not produced any yet.
        GRANT SELECT ON assessments TO siembiot_retention;
        GRANT SELECT, INSERT ON retention_runs TO siembiot_retention;
        """
    )

    # -- the exception to append-only ---------------------------------------------
    #
    # `prevent_row_mutation` refused every UPDATE and DELETE, which is why evidence could
    # never be removed. Rather than dropping the triggers, the refusal now has exactly one
    # exception, and it has to be asked for explicitly: a transaction that sets
    # `app.retention_sweep` may delete.
    #
    # The flag is not the security boundary and is not pretending to be one -- any role
    # can set it. The boundary is the grant: only `siembiot_retention` holds DELETE on
    # these tables at all. What the flag prevents is the other failure, a stray DELETE
    # somewhere in application code silently succeeding because somebody once widened a
    # grant. Removal has to be deliberate as well as permitted.
    op.execute(
        r"""
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

        -- A score outlives its evidence, so its row has to be able to say so. This is
        -- the only UPDATE permitted anywhere on a snapshot, and it is checked by
        -- comparing the whole row rather than by listing columns: `to_jsonb` minus the
        -- one field must be identical, so a future column cannot be smuggled through a
        -- gap in a list nobody updated.
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

        DROP TRIGGER IF EXISTS snapshots_append_only ON score_snapshots;
        CREATE TRIGGER snapshots_append_only
            BEFORE UPDATE OR DELETE ON score_snapshots
            FOR EACH ROW EXECUTE FUNCTION prevent_snapshot_mutation();
        """
    )


def downgrade() -> None:
    op.execute(
        r"""
        DROP TRIGGER IF EXISTS snapshots_append_only ON score_snapshots;
        DROP FUNCTION IF EXISTS prevent_snapshot_mutation();

        CREATE OR REPLACE FUNCTION prevent_row_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION '% rows are append-only', TG_TABLE_NAME USING ERRCODE = '42501';
        END
        $$;

        CREATE TRIGGER snapshots_append_only
            BEFORE UPDATE OR DELETE ON score_snapshots
            FOR EACH ROW EXECUTE FUNCTION prevent_row_mutation();

        DROP TABLE IF EXISTS retention_runs;
        ALTER TABLE score_snapshots DROP COLUMN IF EXISTS evidence_erased_at;

        -- The role is not dropped: it may own privileges in other databases on the same
        -- cluster, and a downgrade that removes a login somebody else depends on is a
        -- larger surprise than one that leaves an unused role behind.
        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM siembiot_retention;
        """
    )
