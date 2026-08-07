"""Aggregate counts for monitoring, without letting a request handler read across tenants.

The API runs as a role that row-level security applies to, which is the whole basis of
tenant isolation. That role therefore cannot answer "how many assessments are queued
across the platform" — and the first attempt at a metrics endpoint discovered this in
the worst possible way: not with an error, but with every count coming back **zero**,
because row-level security hides rows rather than refusing the query. A monitoring
system would have recorded a healthy, idle platform indefinitely.

Silent zeros are worse than a failed scrape. A failed scrape is visible; a confident
wrong number is not.

So the operator's view goes through one `SECURITY DEFINER` function, the same shape as
`app_due_assessments` and for the same reason: the exemption is a single reviewable
body rather than a widened grant. What it returns is aggregates and nothing else — a
metric name, a label drawn from a set the schema already constrains, and a number.
There is no row in the result that names an organization, a domain or a person, so
granting it to the API's role gives a request handler nothing it could leak.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0012_operational_metrics"
down_revision: str | Sequence[str] | None = "0011_assessment_schedules"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE FUNCTION app_operational_metrics()
        RETURNS TABLE (metric text, label_key text, label_value text, value double precision)
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
            SELECT 'assessments', 'state', state, count(*)::double precision
            FROM assessments GROUP BY state
          UNION ALL
            SELECT 'assessment_steps', 'state', state, count(*)::double precision
            FROM assessment_steps GROUP BY state
          UNION ALL
            SELECT 'domains', 'ownership_state', ownership_state, count(*)::double precision
            FROM domains GROUP BY ownership_state
          UNION ALL
            SELECT 'network_operations', 'reason_code', coalesce(reason_code, 'none'),
                   count(*)::double precision
            FROM network_operations GROUP BY coalesce(reason_code, 'none')
          UNION ALL
            -- The clearest signal that work has stopped flowing. A count of queued runs
            -- cannot tell "busy" from "stuck"; the age of the oldest one can.
            SELECT 'oldest_unsettled_assessment_seconds', NULL, NULL,
                   coalesce(extract(epoch FROM now() - min(created_at)), 0)::double precision
            FROM assessments
            WHERE state NOT IN (
                'completed', 'cancelled', 'partially_completed', 'failed',
                'expired', 'blocked_by_policy', 'draft', 'awaiting_authorization'
            )
          UNION ALL
            SELECT 'schedules_due', NULL, NULL, count(*)::double precision
            FROM assessment_schedules
            WHERE cadence <> 'off' AND next_run_at IS NOT NULL AND next_run_at <= now()
          UNION ALL
            -- Not readable by the application role directly, and it should not be:
            -- knowing the schema version is an operator's business, not a handler's.
            SELECT 'build_info', 'schema_version', version_num, 1::double precision
            FROM alembic_version
        $$;

        COMMENT ON FUNCTION app_operational_metrics() IS
            'Aggregate counts for monitoring. Crosses tenants deliberately and returns '
            'no identifier of any kind; must never be widened to return one.';

        -- PostgreSQL grants EXECUTE to PUBLIC by default, so the revoke is what makes
        -- the grant below mean anything.
        REVOKE ALL ON FUNCTION app_operational_metrics() FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION app_operational_metrics() TO siembiot_app;
        """
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS app_operational_metrics();")
