"""Work planned against a finding: who owns it, by when, and how it is going.

The product could say what was wrong and, since the remediation catalog, what to do
about it. It had no way to record that anybody intended to. A list of weaknesses with
no owner and no date is a document, not a plan.

**This is not the same thing as accepting a risk.** `finding_suppressions` already
records "we are not going to fix this, and here is why", which is a decision about the
finding. An action records "we are going to fix this, here is who and when", which is
work. Collapsing the two would let an overdue task quietly become an accepted risk by
nobody doing anything, which is exactly the transition that should require somebody to
say so.

The property worth building carefully: **a completed action is an assertion, and the
platform observes.** Somebody marking work done does not change what the next assessment
sees. So the status here is deliberately not allowed to close a finding, and the API
reports the two side by side -- what a person said, and what the evidence shows. Where
they disagree, that disagreement is the most useful thing on the screen: either the fix
did not work, or it was applied somewhere the assessment does not reach.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0013_remediation_actions"
down_revision: str | Sequence[str] | None = "0012_operational_metrics"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE TABLE remediation_actions (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,

            -- What somebody says is happening. Never what the platform believes.
            status text NOT NULL DEFAULT 'planned',

            -- Nullable because unassigned work is a real and common state, and forcing
            -- a name would produce a fictional one. An action with no owner is a
            -- question for a stand-up, not a data error.
            owner_user_id uuid NULL REFERENCES users(id),
            due_at timestamptz NULL,
            note text NULL,

            created_by_user_id uuid NOT NULL REFERENCES users(id),
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            completed_at timestamptz NULL,

            -- One open plan per finding. Two would mean two owners and two dates, and
            -- whichever the interface read first would look like the answer.
            CONSTRAINT action_unique_per_finding UNIQUE (finding_id),
            CONSTRAINT action_status_valid
                CHECK (status IN ('planned', 'in_progress', 'blocked', 'completed')),
            -- A completion time exactly when it is completed, so "when did they say
            -- this was done" is answerable without reading the history.
            CONSTRAINT action_completed_consistent
                CHECK ((status = 'completed') = (completed_at IS NOT NULL)),
            CONSTRAINT action_note_length
                CHECK (note IS NULL OR length(note) BETWEEN 1 AND 2000)
        );

        CREATE INDEX action_org_status_idx ON remediation_actions (organization_id, status);
        CREATE INDEX action_due_idx ON remediation_actions (due_at)
            WHERE status <> 'completed';

        COMMENT ON TABLE remediation_actions IS
            'Work planned against a finding. Status is what somebody asserts; whether '
            'the weakness is actually gone is the finding''s business, and the two are '
            'reported side by side rather than reconciled.';

        -- Append-only, like the other history in this schema. An action that was
        -- overdue for a month and then quietly re-dated should still show that it was.
        CREATE TABLE remediation_action_history (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            action_id uuid NOT NULL REFERENCES remediation_actions(id) ON DELETE CASCADE,
            from_status text NULL,
            to_status text NOT NULL,
            actor_user_id uuid NOT NULL REFERENCES users(id),
            note text NULL,
            occurred_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE INDEX action_history_idx ON remediation_action_history (action_id, occurred_at);

        CREATE TRIGGER remediation_action_history_append_only
            BEFORE UPDATE OR DELETE ON remediation_action_history
            FOR EACH ROW EXECUTE FUNCTION prevent_row_mutation();

        ALTER TABLE remediation_actions ENABLE ROW LEVEL SECURITY;
        ALTER TABLE remediation_actions FORCE ROW LEVEL SECURITY;
        ALTER TABLE remediation_action_history ENABLE ROW LEVEL SECURITY;
        ALTER TABLE remediation_action_history FORCE ROW LEVEL SECURITY;

        CREATE POLICY actions_select ON remediation_actions
            FOR SELECT USING (app_has_tenant_access(organization_id));
        CREATE POLICY actions_insert ON remediation_actions
            FOR INSERT WITH CHECK (app_has_active_membership(organization_id));
        CREATE POLICY actions_update ON remediation_actions
            FOR UPDATE USING (app_has_active_membership(organization_id))
            WITH CHECK (app_has_active_membership(organization_id));

        CREATE POLICY action_history_select ON remediation_action_history
            FOR SELECT USING (app_has_tenant_access(organization_id));
        CREATE POLICY action_history_insert ON remediation_action_history
            FOR INSERT WITH CHECK (app_has_active_membership(organization_id));

        GRANT SELECT, INSERT, UPDATE ON remediation_actions TO siembiot_app;
        GRANT SELECT, INSERT ON remediation_action_history TO siembiot_app;
        """
    )


def downgrade() -> None:
    op.execute(
        r"""
        DROP TABLE IF EXISTS remediation_action_history;
        DROP TABLE IF EXISTS remediation_actions;
        """
    )
