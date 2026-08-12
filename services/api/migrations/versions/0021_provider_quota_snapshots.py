"""Provider quota, recorded where a dashboard and an alert can see it.

The adapters have tracked quota since Milestone 3 and nothing could read it: the ledger
counted in one worker's memory, so four workers meant four private budgets and the metrics
endpoint — a different process entirely — saw none of them.

The live counter now lives in Redis, shared by every worker. This table is the other half:
a periodic copy of the day's counters, which is what makes quota historical and what puts
it in reach of `/metrics`, since that endpoint reads the database and not the broker.

Two rows per adapter per day at most, upserted, so a snapshot every few minutes does not
grow the table. Keeping every sample would turn an operational counter into a time series
nobody asked for, and Prometheus is already the thing that stores time series.

Not tenant data: a provider budget is the platform's, spent on behalf of everybody, and
there is no organization to scope it to.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0021_provider_quota_snapshots"
down_revision: str | Sequence[str] | None = "0020_tenant_erasure"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE provider_quota_snapshots (
            adapter_id text NOT NULL,
            -- A calendar day in UTC, matching the Redis key. Text rather than a date so
            -- the two representations cannot disagree about a timezone.
            --
            -- Named `quota_window` because `window` is a reserved word: PostgreSQL
            -- accepts it in a column definition and then rejects every INSERT that names
            -- it, so the table would have been created successfully and the snapshot
            -- task would have failed every five minutes.
            quota_window text NOT NULL,
            used bigint NOT NULL DEFAULT 0 CHECK (used >= 0),
            -- Calls refused because the budget was spent. Without this, `used = limit`
            -- cannot distinguish one call turned away from ten thousand.
            denied bigint NOT NULL DEFAULT 0 CHECK (denied >= 0),
            captured_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (adapter_id, quota_window)
        );

        CREATE INDEX provider_quota_window_idx ON provider_quota_snapshots (quota_window DESC);

        GRANT SELECT ON provider_quota_snapshots TO siembiot_app;
        GRANT SELECT, INSERT, UPDATE ON provider_quota_snapshots TO siembiot_worker;
        -- Swept on the operational period, so the one role allowed to delete needs
        -- reaching it. A table classified as swept without this grant fails the
        -- nightly sweep for every table after it.
        GRANT SELECT, DELETE ON provider_quota_snapshots TO siembiot_retention;

        COMMENT ON TABLE provider_quota_snapshots IS
            'Periodic copies of the shared Redis quota counters. Redis is the live '
            'truth; this is the record, and the only path by which quota reaches the '
            'metrics endpoint.';
        """
    )

    # Two new series, added to the one function the metrics endpoint reads.
    #
    # Today's window only. A gauge summing every day since launch would rise forever and
    # alert on nothing, and "how much of today's budget is gone" is the question an
    # operator actually has.
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
            SELECT 'build_info', 'schema_version', version_num, 1::double precision
            FROM alembic_version
        $$;

        DROP TABLE IF EXISTS provider_quota_snapshots;
        """
    )
