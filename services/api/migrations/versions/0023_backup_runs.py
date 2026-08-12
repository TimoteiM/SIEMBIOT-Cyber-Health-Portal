"""A record of every backup attempt, and the age of the newest good one.

The schedule and the destination refusals existed; what nothing could answer was "did last
night's backup actually happen". A job whose only trace is a log line on one host is a job
nobody can alert on, and backups fail silently by nature — nothing breaks when they stop,
right up until somebody needs one.

So the metric is an **age**, not a count. `siembiot_last_successful_backup_seconds` is the
same shape as the oldest-unsettled-assessment gauge and for the same reason: a count of
backups cannot distinguish a healthy platform from one whose backups stopped a fortnight
ago, and the age can.

Failures are rows too. A run that could not reach its destination is the row an operator
most needs, and recording only successes would make a broken backup indistinguishable from
a scheduler that never fired.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0023_backup_runs"
down_revision: str | Sequence[str] | None = "0022_report_format"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE backup_runs (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            started_at timestamptz NOT NULL DEFAULT now(),
            finished_at timestamptz NULL,

            -- Where it went. Recorded so a restore knows where to look, and so a
            -- deployment that silently changed destination is visible in the history
            -- rather than only in whatever configuration is current.
            destination text NULL,

            -- Of the dump, so a restore can be checked against what was written rather
            -- than against what the filesystem currently holds.
            content_sha256 text NULL CHECK (content_sha256 IS NULL OR length(content_sha256) = 64),
            size_bytes bigint NULL CHECK (size_bytes IS NULL OR size_bytes >= 0),

            -- Null on success. Named reasons, so "no backup last night" says which of
            -- the failures it was; three of them are a minute of configuration.
            error text NULL
        );

        CREATE INDEX backup_runs_started_idx ON backup_runs (started_at DESC);

        GRANT SELECT ON backup_runs TO siembiot_app;
        -- INSERT but not UPDATE or DELETE. One row per attempt, written when the attempt
        -- finishes: a worker that could revise its own history could turn a failed
        -- backup into a successful one, which is the only lie this table can tell.
        GRANT SELECT, INSERT ON backup_runs TO siembiot_worker;
        GRANT SELECT, DELETE ON backup_runs TO siembiot_retention;

        COMMENT ON TABLE backup_runs IS
            'Every backup attempt, successful or not. The age of the newest successful '
            'run is exported as a metric, because backups fail silently and a count '
            'cannot tell a healthy platform from one whose backups stopped.';
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION app_operational_metrics()
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
            SELECT 'provider_quota_used', 'adapter_id', adapter_id, used::double precision
            FROM provider_quota_snapshots
            WHERE quota_window = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD')
          UNION ALL
            SELECT 'provider_quota_denied', 'adapter_id', adapter_id, denied::double precision
            FROM provider_quota_snapshots
            WHERE quota_window = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD')
          UNION ALL
            -- Seconds since the newest successful backup.
            --
            -- A platform that has never taken one reports a very large number rather than
            -- zero or nothing: absent would look like a broken exporter, and zero would
            -- read as "backed up moments ago", which is the most dangerous of the three
            -- things this could say.
            SELECT 'last_successful_backup_seconds', NULL, NULL,
                   coalesce(
                       extract(epoch FROM now() - max(finished_at)),
                       extract(epoch FROM interval '3650 days')
                   )::double precision
            FROM backup_runs
            WHERE error IS NULL AND finished_at IS NOT NULL
          UNION ALL
            -- Attempts that failed in the last day.
            --
            -- A gauge over a window rather than a monotonic counter, because "tried and
            -- failed" and "never ran" are different problems with different fixes, and
            -- the age metric above cannot tell them apart. This one fires the day before
            -- the age threshold is reached, which is the difference between fixing a
            -- misconfiguration and discovering it during a restore.
            SELECT 'failed_backups_recent', NULL, NULL, count(*)::double precision
            FROM backup_runs
            WHERE error IS NOT NULL AND started_at > now() - interval '24 hours'
          UNION ALL
            SELECT 'build_info', 'schema_version', version_num, 1::double precision
            FROM alembic_version
        $$;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION app_operational_metrics()
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
            SELECT 'provider_quota_used', 'adapter_id', adapter_id, used::double precision
            FROM provider_quota_snapshots
            WHERE quota_window = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD')
          UNION ALL
            SELECT 'provider_quota_denied', 'adapter_id', adapter_id, denied::double precision
            FROM provider_quota_snapshots
            WHERE quota_window = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD')
          UNION ALL
            SELECT 'build_info', 'schema_version', version_num, 1::double precision
            FROM alembic_version
        $$;

        DROP TABLE IF EXISTS backup_runs;
        """
    )
