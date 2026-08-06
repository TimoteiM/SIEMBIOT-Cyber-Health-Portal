"""Record which mode an assessment ran in.

The product has always had two lawful paths to a domain, and the worker has enforced the
distinction by allowlist since Milestone 6. It was never written down on the assessment
itself, which meant a report could not say how it was produced -- and that a run could
only ever be started against a domain someone had proved control of, even when the run
would do nothing a member of the public could not do.

**Passive observation** reads what the target already publishes: DNS, RDAP, Certificate
Transparency, the TLS handshake and the home page a browser would fetch. It needs no
ownership proof because it asks the target for nothing that is not already public.

**Authorized assessment** is anything beyond that, and keeps every existing requirement:
verified domain control, a signed scope manifest, recorded consent.

Passive is not authorized-with-the-checks-off. It is a strictly smaller set of
operations, and the constraint below is what stops that from being quietly reversed: an
authorized run *must* name the authorization it is acting under, enforced by the
database rather than by whichever code path happens to create the row.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0010_assessment_mode"
down_revision: str | Sequence[str] | None = "0009_scheduling_seam"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        -- Existing rows default to passive because that is what they actually were:
        -- the worker has built a passive runtime for every run to date. Backfilling
        -- them as authorized would claim an authorization that was never recorded.
        ALTER TABLE assessments
            ADD COLUMN mode text NOT NULL DEFAULT 'passive_observation',
            ADD CONSTRAINT assessment_mode_valid
                CHECK (mode IN ('passive_observation', 'authorized_assessment'));

        -- The seam between the two modes, enforced where it cannot be bypassed.
        -- Without this, an authorized run could be created with no authorization on
        -- record, and the mode column would be a label rather than a guarantee.
        ALTER TABLE assessments
            ADD CONSTRAINT assessment_authorization_matches_mode
                CHECK (mode = 'passive_observation' OR authorization_id IS NOT NULL);

        COMMENT ON COLUMN assessments.mode IS
            'passive_observation reads only what the target already publishes and needs '
            'no ownership proof. authorized_assessment requires verified control and a '
            'signed authorization, and is constrained above to have one.';
        """
    )

    # The scheduler must hand the worker the mode the row was created with. Without it
    # the worker would fall back to a default, which means a scheduling detail -- not
    # the recorded authorization -- would decide what the platform may do to a domain.
    #
    # Dropped and recreated rather than replaced: changing a function's result columns
    # is not something CREATE OR REPLACE will do.
    op.execute(
        r"""
        DROP FUNCTION IF EXISTS app_due_assessments(integer);

        CREATE FUNCTION app_due_assessments(max_rows integer DEFAULT 50)
        RETURNS TABLE (
            assessment_id uuid,
            organization_id uuid,
            domain_id uuid,
            host text,
            mode text
        )
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
            SELECT a.id, a.organization_id, a.domain_id, d.canonical_name, a.mode
            FROM assessments a
            JOIN domains d ON d.id = a.domain_id
            WHERE a.state NOT IN (
                'draft', 'awaiting_authorization', 'completed', 'cancelled',
                'partially_completed', 'failed', 'expired', 'blocked_by_policy'
            )
              AND NOT EXISTS (
                  SELECT 1 FROM assessment_steps s
                  WHERE s.assessment_id = a.id
                    AND s.state = 'pending'
                    AND s.next_attempt_at IS NOT NULL
                    AND s.next_attempt_at > now()
              )
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
            'returns identifiers, a hostname and the recorded mode, and must never be '
            'widened to evidence.';

        -- Re-granted because the function was dropped: PostgreSQL grants EXECUTE to
        -- PUBLIC on a new function, and the revoke below is what keeps this
        -- cross-tenant read out of reach of the API's role.
        REVOKE ALL ON FUNCTION app_due_assessments(integer) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION app_due_assessments(integer) TO siembiot_worker;
        """
    )


def downgrade() -> None:
    # The function is restored to its 0009 shape first: it selects a.mode, so it must
    # stop doing that before the column can be dropped.
    op.execute(
        r"""
        DROP FUNCTION IF EXISTS app_due_assessments(integer);

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
            WHERE a.state NOT IN (
                'draft', 'awaiting_authorization', 'completed', 'cancelled',
                'partially_completed', 'failed', 'expired', 'blocked_by_policy'
            )
              AND NOT EXISTS (
                  SELECT 1 FROM assessment_steps s
                  WHERE s.assessment_id = a.id
                    AND s.state = 'pending'
                    AND s.next_attempt_at IS NOT NULL
                    AND s.next_attempt_at > now()
              )
              AND NOT EXISTS (
                  SELECT 1 FROM assessment_steps s
                  WHERE s.assessment_id = a.id
                    AND s.lease_expires_at IS NOT NULL
                    AND s.lease_expires_at > now()
              )
            ORDER BY a.created_at
            LIMIT least(greatest(max_rows, 1), 500)
        $$;

        REVOKE ALL ON FUNCTION app_due_assessments(integer) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION app_due_assessments(integer) TO siembiot_worker;

        ALTER TABLE assessments
            DROP CONSTRAINT IF EXISTS assessment_authorization_matches_mode,
            DROP CONSTRAINT IF EXISTS assessment_mode_valid,
            DROP COLUMN IF EXISTS mode;
        """
    )
