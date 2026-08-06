"""Durable orchestration state and asset attribution.

The queue only ever delivers a nudge; these tables are the authority. That inversion is
what makes duplicate and out-of-order delivery harmless, and it only holds if the
database enforces it rather than trusting the worker to remember:

* a completed idempotency key is unique, so a repeat cannot execute twice;
* a lease is a single row, so two workers cannot both hold one step;
* attempts are append-only, so a retry cannot erase the failure that caused it.

Asset candidates are deliberately *candidates*. Discovery is not ownership, so a
candidate carries its attribution confidence and stays unreviewed until a human decides.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0008_orchestration_and_assets"
down_revision: str | Sequence[str] | None = "0007_external_authentication"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        -- Cancellation is a request, not an instant state change: work already running
        -- observes it cooperatively and settles itself.
        ALTER TABLE assessments
            ADD COLUMN cancellation_requested_at timestamptz NULL,
            ADD COLUMN cancellation_reason text NULL,
            ADD CONSTRAINT assessment_cancellation_reason_length
                CHECK (cancellation_reason IS NULL OR length(cancellation_reason) BETWEEN 3 AND 500);

        CREATE TABLE assessment_steps (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            name text NOT NULL,
            state text NOT NULL DEFAULT 'pending',
            attempts integer NOT NULL DEFAULT 0,
            idempotency_key text NULL,
            lease_owner uuid NULL,
            lease_expires_at timestamptz NULL,
            last_error text NULL,
            next_attempt_at timestamptz NULL,
            result jsonb NOT NULL DEFAULT '{}'::jsonb,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT step_state_valid CHECK (state IN (
                'pending', 'running', 'succeeded', 'failed', 'skipped',
                'cancelled', 'dead_lettered'
            )),
            CONSTRAINT step_attempts_not_negative CHECK (attempts >= 0),
            CONSTRAINT step_lease_is_whole CHECK (
                (lease_owner IS NULL) = (lease_expires_at IS NULL)
            ),
            CONSTRAINT step_unique_per_assessment UNIQUE (assessment_id, name)
        );
        CREATE INDEX assessment_steps_org_idx ON assessment_steps (organization_id);
        CREATE INDEX assessment_steps_runnable_idx
            ON assessment_steps (assessment_id, state, next_attempt_at);

        -- Append-only history. A retry must never erase the failure that caused it.
        CREATE TABLE assessment_step_attempts (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            step_name text NOT NULL,
            attempt integer NOT NULL,
            outcome text NOT NULL,
            error text NULL,
            worker_id uuid NULL,
            started_at timestamptz NOT NULL DEFAULT now(),
            finished_at timestamptz NULL,
            CONSTRAINT attempt_outcome_valid CHECK (outcome IN (
                'succeeded', 'retryable_failure', 'permanent_failure', 'cancelled',
                'deduplicated', 'timeout'
            )),
            CONSTRAINT attempt_is_positive CHECK (attempt >= 1),
            CONSTRAINT attempt_unique_per_step UNIQUE (assessment_id, step_name, attempt)
        );
        CREATE INDEX step_attempts_step_idx
            ON assessment_step_attempts (assessment_id, step_name);

        -- The key records *completed* work. Uniqueness is the deduplication guarantee:
        -- a redelivered message cannot insert it twice, so it cannot run twice.
        CREATE TABLE workflow_idempotency_keys (
            key text PRIMARY KEY,
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            step_name text NOT NULL,
            recorded_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT idempotency_key_shape CHECK (length(key) BETWEEN 8 AND 200)
        );
        CREATE INDEX idempotency_keys_assessment_idx
            ON workflow_idempotency_keys (assessment_id);

        CREATE TABLE asset_candidates (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            domain_id uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
            name text NOT NULL,
            source text NOT NULL,
            attribution_confidence numeric(3,2) NOT NULL,
            attribution_basis text NOT NULL,
            shared_hosting boolean NOT NULL DEFAULT false,
            state text NOT NULL DEFAULT 'unreviewed',
            first_seen_at timestamptz NOT NULL DEFAULT now(),
            last_seen_at timestamptz NOT NULL DEFAULT now(),
            observation_count integer NOT NULL DEFAULT 1,
            CONSTRAINT candidate_state_valid CHECK (state IN (
                'unreviewed', 'accepted', 'rejected'
            )),
            CONSTRAINT candidate_source_valid CHECK (source IN (
                'certificate_transparency', 'dns', 'user_declared', 'passive_intelligence'
            )),
            CONSTRAINT candidate_basis_valid CHECK (attribution_basis IN (
                'authorized_domain', 'subdomain_of_authorized_domain', 'unrelated_name'
            )),
            CONSTRAINT candidate_confidence_range CHECK (
                attribution_confidence BETWEEN 0 AND 1
            ),
            CONSTRAINT candidate_seen_order CHECK (last_seen_at >= first_seen_at),
            CONSTRAINT candidate_unique_per_domain UNIQUE (domain_id, name)
        );
        CREATE INDEX asset_candidates_review_idx
            ON asset_candidates (organization_id, state, attribution_confidence DESC);

        -- Every accept or reject is recorded with its actor. An asset entering scope is
        -- a decision about what may be assessed, so it must be attributable.
        CREATE TABLE asset_candidate_decisions (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            candidate_id uuid NOT NULL REFERENCES asset_candidates(id) ON DELETE CASCADE,
            decision text NOT NULL,
            reason text NULL,
            actor_user_id uuid NOT NULL REFERENCES users(id),
            decided_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT decision_valid CHECK (decision IN ('accepted', 'rejected', 'reopened')),
            CONSTRAINT decision_reason_length CHECK (
                reason IS NULL OR length(reason) BETWEEN 3 AND 2000
            )
        );
        CREATE INDEX asset_decisions_candidate_idx
            ON asset_candidate_decisions (candidate_id, decided_at);
        """
    )

    op.execute(
        r"""
        CREATE TRIGGER step_attempts_append_only
            BEFORE UPDATE OR DELETE ON assessment_step_attempts
            FOR EACH ROW EXECUTE FUNCTION prevent_row_mutation();
        CREATE TRIGGER asset_decisions_append_only
            BEFORE UPDATE OR DELETE ON asset_candidate_decisions
            FOR EACH ROW EXECUTE FUNCTION prevent_row_mutation();

        -- A completed key is a fact about work that already happened; rewriting one
        -- would let the same work run a second time.
        CREATE TRIGGER idempotency_keys_append_only
            BEFORE UPDATE ON workflow_idempotency_keys
            FOR EACH ROW EXECUTE FUNCTION prevent_row_mutation();

        CREATE FUNCTION touch_assessment_step() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            NEW.updated_at := now();
            RETURN NEW;
        END
        $$;
        CREATE TRIGGER assessment_steps_touch
            BEFORE UPDATE ON assessment_steps
            FOR EACH ROW EXECUTE FUNCTION touch_assessment_step();
        """
    )

    op.execute(
        r"""
        ALTER TABLE assessment_steps ENABLE ROW LEVEL SECURITY;
        ALTER TABLE assessment_step_attempts ENABLE ROW LEVEL SECURITY;
        ALTER TABLE workflow_idempotency_keys ENABLE ROW LEVEL SECURITY;
        ALTER TABLE asset_candidates ENABLE ROW LEVEL SECURITY;
        ALTER TABLE asset_candidate_decisions ENABLE ROW LEVEL SECURITY;
        ALTER TABLE assessment_steps FORCE ROW LEVEL SECURITY;
        ALTER TABLE assessment_step_attempts FORCE ROW LEVEL SECURITY;
        ALTER TABLE workflow_idempotency_keys FORCE ROW LEVEL SECURITY;
        ALTER TABLE asset_candidates FORCE ROW LEVEL SECURITY;
        ALTER TABLE asset_candidate_decisions FORCE ROW LEVEL SECURITY;

        CREATE POLICY assessment_steps_select ON assessment_steps FOR SELECT
            USING (app_has_tenant_access(organization_id));
        CREATE POLICY assessment_steps_insert ON assessment_steps FOR INSERT
            WITH CHECK (app_has_active_membership(organization_id));
        CREATE POLICY assessment_steps_update ON assessment_steps FOR UPDATE
            USING (app_has_active_membership(organization_id))
            WITH CHECK (app_has_active_membership(organization_id));

        CREATE POLICY step_attempts_select ON assessment_step_attempts FOR SELECT
            USING (app_has_tenant_access(organization_id));
        CREATE POLICY step_attempts_insert ON assessment_step_attempts FOR INSERT
            WITH CHECK (app_has_active_membership(organization_id));

        CREATE POLICY idempotency_keys_select ON workflow_idempotency_keys FOR SELECT
            USING (app_has_tenant_access(organization_id));
        CREATE POLICY idempotency_keys_insert ON workflow_idempotency_keys FOR INSERT
            WITH CHECK (app_has_active_membership(organization_id));

        CREATE POLICY asset_candidates_select ON asset_candidates FOR SELECT
            USING (app_has_tenant_access(organization_id));
        CREATE POLICY asset_candidates_insert ON asset_candidates FOR INSERT
            WITH CHECK (app_has_active_membership(organization_id));
        CREATE POLICY asset_candidates_update ON asset_candidates FOR UPDATE
            USING (app_has_active_membership(organization_id))
            WITH CHECK (app_has_active_membership(organization_id));

        CREATE POLICY asset_decisions_select ON asset_candidate_decisions FOR SELECT
            USING (app_has_tenant_access(organization_id));
        CREATE POLICY asset_decisions_insert ON asset_candidate_decisions FOR INSERT
            WITH CHECK (app_has_active_membership(organization_id));

        GRANT SELECT, INSERT, UPDATE ON assessment_steps, asset_candidates TO siembiot_app;
        GRANT SELECT, INSERT ON assessment_step_attempts, workflow_idempotency_keys,
            asset_candidate_decisions TO siembiot_app;
        """
    )


def downgrade() -> None:
    op.execute(
        r"""
        DROP TABLE IF EXISTS asset_candidate_decisions;
        DROP TABLE IF EXISTS asset_candidates;
        DROP TABLE IF EXISTS workflow_idempotency_keys;
        DROP TABLE IF EXISTS assessment_step_attempts;
        DROP TABLE IF EXISTS assessment_steps;
        DROP FUNCTION IF EXISTS touch_assessment_step();
        ALTER TABLE assessments
            DROP CONSTRAINT IF EXISTS assessment_cancellation_reason_length,
            DROP COLUMN IF EXISTS cancellation_reason,
            DROP COLUMN IF EXISTS cancellation_requested_at;
        """
    )
