"""Recurring assessments, and expiry for stale domain verification.

Two gaps that made this a scanner rather than a monitoring product.

**Nothing ever ran on a schedule.** The sweep only picks up runs that already exist; it
never creates one. Every assessment to date was started by somebody pressing a button,
which means a domain is only as current as the last time a person remembered it. A
score from March describes March.

**Nothing ever expired a verification.** `reverification_due_at` has been written since
migration 0004 and read when authorizing, but no process moved a domain to
`reverification_required` when the date passed. A verification therefore lasted forever
in practice, which is the opposite of what a periodic re-check is for -- and control of
a domain is exactly the fact most likely to have changed since anyone last looked.

Design notes worth keeping:

*Cadence is per domain, not per organization.* An institution's main site and a seldom
used subdomain do not deserve the same frequency, and forcing one number on both means
the important one is checked too rarely or the quiet one too often.

*Quiet hours are stored, and are the organization's local hours.* A run costs the target
DNS queries, a TLS handshake and a page fetch. That is small, but "small" during an
incident at 03:00 is not the same as small at midday, and an institution should be able
to say when it would rather we did not.

*The schedule records intent, never results.* `next_run_at` is a plan; whether a run
happened is the assessment's business. Keeping outcome here would create a second
account of what occurred, and the two would eventually disagree.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0011_assessment_schedules"
down_revision: str | Sequence[str] | None = "0010_assessment_mode"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE TABLE assessment_schedules (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            domain_id uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,

            -- 'off' is a first-class choice rather than a missing row. An organization
            -- that has deliberately paused a domain is saying something different from
            -- one that never configured it, and a report should be able to tell them
            -- apart.
            cadence text NOT NULL DEFAULT 'off',

            -- The mode a scheduled run uses. Passive by default and constrained below:
            -- an unattended run must never be the one that reaches further than a
            -- visitor would, because nobody is watching it happen.
            mode text NOT NULL DEFAULT 'passive_observation',

            -- Local hours during which the scheduler holds off. Null means no
            -- preference. Stored as hours rather than timestamps because the intent is
            -- "not during our night", which recurs, rather than a single window.
            quiet_hours_start smallint NULL,
            quiet_hours_end smallint NULL,
            timezone text NOT NULL DEFAULT 'Europe/Bucharest',

            next_run_at timestamptz NULL,
            last_run_at timestamptz NULL,

            created_by_user_id uuid NOT NULL REFERENCES users(id),
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),

            -- One schedule per domain. Two would mean two answers to "when next", and
            -- whichever the scheduler read first would win silently.
            CONSTRAINT schedule_unique_per_domain UNIQUE (domain_id),
            CONSTRAINT schedule_cadence_valid
                CHECK (cadence IN ('off', 'daily', 'weekly', 'monthly', 'quarterly')),
            CONSTRAINT schedule_mode_valid
                CHECK (mode IN ('passive_observation', 'authorized_assessment')),
            CONSTRAINT schedule_quiet_hours_paired
                CHECK ((quiet_hours_start IS NULL) = (quiet_hours_end IS NULL)),
            CONSTRAINT schedule_quiet_hours_range
                CHECK (
                    quiet_hours_start IS NULL
                    OR (quiet_hours_start BETWEEN 0 AND 23 AND quiet_hours_end BETWEEN 0 AND 23)
                ),
            -- A cadence with nothing scheduled would never fire; 'off' with something
            -- scheduled would fire against an explicit decision to stop.
            CONSTRAINT schedule_next_run_matches_cadence
                CHECK ((cadence = 'off') = (next_run_at IS NULL))
        );

        CREATE INDEX schedule_due_idx ON assessment_schedules (next_run_at)
            WHERE cadence <> 'off';

        COMMENT ON TABLE assessment_schedules IS
            'When a domain should be reassessed. Records intent only: whether a run '
            'happened is the assessment row''s business, and a second account of that '
            'would eventually disagree with the first.';

        ALTER TABLE assessment_schedules ENABLE ROW LEVEL SECURITY;
        ALTER TABLE assessment_schedules FORCE ROW LEVEL SECURITY;

        CREATE POLICY schedules_select ON assessment_schedules
            FOR SELECT USING (app_has_tenant_access(organization_id));
        CREATE POLICY schedules_insert ON assessment_schedules
            FOR INSERT WITH CHECK (app_has_active_membership(organization_id));
        CREATE POLICY schedules_update ON assessment_schedules
            FOR UPDATE USING (app_has_active_membership(organization_id))
            WITH CHECK (app_has_active_membership(organization_id));

        -- The worker owns next_run_at once a run is dispatched, so it needs the same
        -- tenant-scoped write the other orchestration tables give it.
        CREATE POLICY schedules_worker_select ON assessment_schedules
            FOR SELECT USING (app_is_worker_for(organization_id));
        CREATE POLICY schedules_worker_insert ON assessment_schedules
            FOR INSERT WITH CHECK (app_is_worker_for(organization_id));
        CREATE POLICY schedules_worker_update ON assessment_schedules
            FOR UPDATE USING (app_is_worker_for(organization_id))
            WITH CHECK (app_is_worker_for(organization_id));

        GRANT SELECT, INSERT, UPDATE ON assessment_schedules TO siembiot_app;
        GRANT SELECT, INSERT, UPDATE ON assessment_schedules TO siembiot_worker;
        GRANT UPDATE ON domains TO siembiot_worker;

        -- Whether the current moment falls inside an organization's quiet window.
        --
        -- plpgsql rather than sql because it has to survive a timezone name the
        -- database does not know: `now() AT TIME ZONE 'Bad/Zone'` raises, and a raise
        -- inside the sweep's WHERE clause would take down every other tenant's
        -- schedule along with the misconfigured one. Falling back to "not quiet" is
        -- the safe direction -- the run happens, at worst at an hour somebody would
        -- rather it did not, instead of scheduling silently stopping for everyone.
        CREATE FUNCTION app_in_quiet_hours(
            start_hour smallint, end_hour smallint, zone text
        ) RETURNS boolean
        LANGUAGE plpgsql STABLE SET search_path = public, pg_temp AS $$
        DECLARE
            local_hour integer;
        BEGIN
            IF start_hour IS NULL OR end_hour IS NULL THEN
                RETURN false;
            END IF;
            BEGIN
                local_hour := extract(hour FROM (now() AT TIME ZONE zone));
            EXCEPTION WHEN OTHERS THEN
                RETURN false;
            END;

            -- Equal bounds mean an empty window, not a whole silent day. Reading it as
            -- 24 hours would let one mistyped field stop a domain being assessed ever
            -- again, and nothing would report that it had.
            IF start_hour = end_hour THEN
                RETURN false;
            END IF;
            IF start_hour < end_hour THEN
                RETURN local_hour >= start_hour AND local_hour < end_hour;
            END IF;
            -- Wrapping past midnight, which is the common case: 22:00 to 06:00.
            RETURN local_hour >= start_hour OR local_hour < end_hour;
        END;
        $$;

        REVOKE ALL ON FUNCTION app_in_quiet_hours(smallint, smallint, text) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION app_in_quiet_hours(smallint, smallint, text)
            TO siembiot_app, siembiot_worker;

        -- The scheduler's cross-tenant read, in the same shape and with the same
        -- reasoning as app_due_assessments: identifiers and a hostname, nothing more.
        CREATE FUNCTION app_due_schedules(max_rows integer DEFAULT 50)
        RETURNS TABLE (
            schedule_id uuid,
            organization_id uuid,
            domain_id uuid,
            host text,
            mode text
        )
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
            SELECT s.id, s.organization_id, s.domain_id, d.canonical_name, s.mode
            FROM assessment_schedules s
            JOIN domains d ON d.id = s.domain_id
            WHERE s.cadence <> 'off'
              AND s.next_run_at IS NOT NULL
              AND s.next_run_at <= now()
              -- Quiet hours, evaluated in the organization's own timezone. An unknown
              -- timezone would raise and stop the whole sweep, so it falls back rather
              -- than taking every other tenant's schedule down with it.
              AND NOT app_in_quiet_hours(s.quiet_hours_start, s.quiet_hours_end, s.timezone)
              -- A domain whose control is no longer proven is not reassessed on a
              -- timer. Re-verifying is a person's job, and quietly continuing would
              -- mean assessing something nobody currently claims.
              AND (s.mode = 'passive_observation' OR d.ownership_state = 'verified')
              -- Never stack runs. An assessment already in flight for this domain
              -- means the previous one has not finished, and a second would compete
              -- for the same evidence rows.
              AND NOT EXISTS (
                  SELECT 1 FROM assessments a
                  WHERE a.domain_id = s.domain_id
                    AND a.state NOT IN (
                      'completed', 'cancelled', 'partially_completed', 'failed',
                      'expired', 'blocked_by_policy'
                    )
              )
            ORDER BY s.next_run_at
            LIMIT least(greatest(max_rows, 1), 500)
        $$;

        COMMENT ON FUNCTION app_due_schedules(integer) IS
            'Schedules that are due now. Scheduling metadata only; must never be '
            'widened to evidence.';

        REVOKE ALL ON FUNCTION app_due_schedules(integer) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION app_due_schedules(integer) TO siembiot_worker;
        """
    )


def downgrade() -> None:
    op.execute(
        r"""
        DROP FUNCTION IF EXISTS app_due_schedules(integer);
        DROP FUNCTION IF EXISTS app_in_quiet_hours(smallint, smallint, text);
        REVOKE UPDATE ON domains FROM siembiot_worker;
        DROP TABLE IF EXISTS assessment_schedules;
        """
    )
