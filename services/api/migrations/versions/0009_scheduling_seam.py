"""A worker identity, and a narrow cross-tenant view for the scheduler.

Until now every row-level security policy asked the same question: does the current
*person* have an active membership in this organization? That is exactly right for a
request made on someone's behalf, and it is unanswerable for the worker, which acts on
nobody's behalf. The result was that the worker could neither find work nor record it.

Two things are added here, and both are deliberately narrow.

**A worker role.** `siembiot_worker` is a separate login role with its own credentials.
The policies below let it write within one organization *without* a membership -- but
only the organization named in `app.organization_id`, so a worker connection is still
confined to exactly one tenant, exactly like a user's.

It matters that this is a role rather than a session flag. A flag would mean anyone who
could talk to the database as `siembiot_app` -- the API's own role -- could assert
"I am the worker" and write to any tenant. A role cannot be asserted; it requires
credentials the API does not have.

**One cross-tenant read.** The scheduler must ask "which runs are due?" before it knows
which tenant it is acting for. `app_due_assessments` answers that and nothing else: it
returns identifiers and a hostname. It cannot leak an observation, a finding, or a
score, because it does not select them. Everything after that call runs tenant-scoped.

Reviewing this seam means reading one function body and one predicate.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0009_scheduling_seam"
down_revision: str | Sequence[str] | None = "0008_orchestration_and_assets"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: States from which no further work can be dispatched. `draft` and
#: `awaiting_authorization` are in this list deliberately: a run nobody has authorized
#: must never be started by a scheduler.
SETTLED = (
    "'draft', 'awaiting_authorization', 'completed', 'cancelled', "
    "'partially_completed', 'failed', 'expired', 'blocked_by_policy'"
)

#: Tables the worker writes while carrying out a run.
WORKER_READ_WRITE = "assessments, assessment_steps, asset_candidates, findings"
WORKER_APPEND_ONLY = (
    "assessment_step_attempts, workflow_idempotency_keys, normalized_observations, "
    "check_evaluations, score_snapshots, finding_history, asset_candidate_decisions"
)
WORKER_READ_ONLY = "domains, organizations, methodology_versions"

#: Every table whose policies must also admit the worker. Kept as one list so a table
#: cannot be granted to the worker while its policies still refuse it.
TENANT_TABLES = (
    ("assessments", ("update",)),
    ("assessment_steps", ("update",)),
    ("asset_candidates", ("update",)),
    ("findings", ("update",)),
    ("assessment_step_attempts", ()),
    ("workflow_idempotency_keys", ()),
    ("normalized_observations", ()),
    ("check_evaluations", ()),
    ("score_snapshots", ()),
    ("finding_history", ()),
    ("asset_candidate_decisions", ()),
)


def upgrade() -> None:
    # Every value spliced below is a module constant defined above -- table lists and
    # a state list -- and none is reachable from a request. They are constants rather
    # than literals so the grants and the policies cannot drift apart: a table added to
    # one list is added to both. See the S608 note in pyproject.toml.
    op.execute(
        rf"""
        -- The role is created by infra/compose/postgres-init (locally) or by the
        -- platform (in deployment), because a password must never live in a migration.
        -- Creating it here without one keeps the migration runnable either way: an
        -- existing role is left exactly as it is, credentials included.
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'siembiot_worker') THEN
                CREATE ROLE siembiot_worker
                    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
            END IF;
        END
        $$;

        -- True only for a connection that both *is* the worker and has been given a
        -- tenant to act for. Neither half is sufficient: the role alone still sees no
        -- rows, and the setting alone means nothing without the role.
        --
        -- Not SECURITY DEFINER: it must observe the caller's identity, not the owner's.
        CREATE FUNCTION app_is_worker_for(target_organization_id uuid)
        RETURNS boolean
        LANGUAGE sql STABLE SET search_path = public, pg_temp AS $$
            SELECT current_user = 'siembiot_worker'
               AND target_organization_id IS NOT DISTINCT FROM
                   nullif(current_setting('app.organization_id', true), '')::uuid
        $$;

        COMMENT ON FUNCTION app_is_worker_for(uuid) IS
            'True for a worker connection scoped to this organization. Confers no '
            'cross-tenant access: the worker is bound to app.organization_id exactly '
            'as a user is.';

        CREATE FUNCTION app_due_assessments(max_rows integer DEFAULT 50)
        RETURNS TABLE (
            assessment_id uuid,
            organization_id uuid,
            domain_id uuid,
            host text
        )
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
            SELECT a.id, a.organization_id, a.domain_id, d.canonical_name
            FROM assessments a
            JOIN domains d ON d.id = a.domain_id
            WHERE a.state NOT IN ({SETTLED})
              -- A step waiting out its backoff window is not due. Without this the
              -- scheduler would re-enqueue it every sweep, and the worker would pick it
              -- up only to find nothing it is allowed to run yet.
              AND NOT EXISTS (
                  SELECT 1 FROM assessment_steps s
                  WHERE s.assessment_id = a.id
                    AND s.state = 'pending'
                    AND s.next_attempt_at IS NOT NULL
                    AND s.next_attempt_at > now()
              )
              -- Nor is a run somebody is already carrying out. A live lease makes a
              -- duplicate dispatch harmless, not free: without this, a run taking
              -- several minutes is re-enqueued on every sweep, and the queue fills
              -- with tasks whose only job is to discover they have nothing to do.
              -- An expired lease is deliberately not excluded -- reclaiming those is
              -- exactly how a worker that died mid-run gets picked back up.
              AND NOT EXISTS (
                  SELECT 1 FROM assessment_steps s
                  WHERE s.assessment_id = a.id
                    AND s.lease_expires_at IS NOT NULL
                    AND s.lease_expires_at > now()
              )
            ORDER BY a.created_at
            LIMIT least(greatest(max_rows, 1), 500)
        $$;

        COMMENT ON FUNCTION app_due_assessments(integer) IS
            'Scheduling metadata only. The single cross-tenant read in the system; it '
            'returns identifiers and a hostname and must never be widened to evidence.';

        -- PostgreSQL grants EXECUTE on a new function to PUBLIC by default, so the
        -- grants below are only meaningful after that default is taken away. Without
        -- this revoke, `app_due_assessments` -- a SECURITY DEFINER function that reads
        -- across every tenant -- would be callable by the API's role, and one SQL
        -- injection there would enumerate every organization's domains.
        REVOKE ALL ON FUNCTION app_due_assessments(integer) FROM PUBLIC;
        REVOKE ALL ON FUNCTION app_is_worker_for(uuid) FROM PUBLIC;

        -- The predicate is referenced by policies on tables both roles use, so both
        -- must be able to evaluate it. It discloses nothing: it returns false for
        -- anyone who is not the worker.
        GRANT EXECUTE ON FUNCTION app_is_worker_for(uuid) TO siembiot_app, siembiot_worker;
        GRANT EXECUTE ON FUNCTION app_due_assessments(integer) TO siembiot_worker;

        -- The scheduler reads across tenants; it never runs anything. Everything the
        -- worker does after that call is tenant-scoped, so these are the ordinary
        -- privileges plus the row-level policies below -- not an exemption from them.
        GRANT EXECUTE ON FUNCTION
            app_current_organization_id(), app_has_tenant_access(uuid)
            TO siembiot_worker;
        -- Migration 0001 revoked schema access from PUBLIC, so a new role starts with
        -- none at all -- which is the right default, and means this must be explicit.
        GRANT USAGE ON SCHEMA public TO siembiot_worker;
        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM siembiot_worker;
        GRANT SELECT ON {WORKER_READ_ONLY} TO siembiot_worker;
        GRANT SELECT, INSERT, UPDATE ON {WORKER_READ_WRITE} TO siembiot_worker;
        GRANT SELECT, INSERT ON {WORKER_APPEND_ONLY} TO siembiot_worker;
        """
    )

    for table, _ in TENANT_TABLES:
        op.execute(
            f"""
            CREATE POLICY {table}_worker_select ON {table}
                FOR SELECT USING (app_is_worker_for(organization_id));
            CREATE POLICY {table}_worker_insert ON {table}
                FOR INSERT WITH CHECK (app_is_worker_for(organization_id));
            """
        )

    for table, commands in TENANT_TABLES:
        if "update" in commands:
            op.execute(
                f"""
                CREATE POLICY {table}_worker_update ON {table}
                    FOR UPDATE USING (app_is_worker_for(organization_id))
                    WITH CHECK (app_is_worker_for(organization_id));
                """
            )


def downgrade() -> None:
    for table, commands in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_worker_select ON {table};")
        op.execute(f"DROP POLICY IF EXISTS {table}_worker_insert ON {table};")
        if "update" in commands:
            op.execute(f"DROP POLICY IF EXISTS {table}_worker_update ON {table};")
    op.execute(
        f"""
        REVOKE ALL ON {WORKER_READ_ONLY} FROM siembiot_worker;
        REVOKE ALL ON {WORKER_READ_WRITE} FROM siembiot_worker;
        REVOKE ALL ON {WORKER_APPEND_ONLY} FROM siembiot_worker;
        DROP FUNCTION IF EXISTS app_due_assessments(integer);
        DROP FUNCTION IF EXISTS app_is_worker_for(uuid);
        """
    )
