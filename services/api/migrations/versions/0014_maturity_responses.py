"""What an organisation says about its own practice, kept apart from what was observed.

Everything the platform knew until now came from looking at a domain from the outside.
That reaches DNS, mail policy, TLS and web headers, and it reaches nothing at all about
whether backups are restorable, whether anybody would notice an incident at 3am, or
whether access is withdrawn when somebody leaves. Those are most of what actually
protects an organisation, and none of them are observable from the internet. So they are
asked.

**The answers are assertions, and they are stored as such.** This is the same distinction
the remediation roadmap draws between marking work complete and the assessment agreeing
it is gone, and it matters more here, because a questionnaire is the easiest place in any
product of this kind to manufacture a reassuring number. Two design decisions follow:

*The score from this table is never blended with the technical score.* They are different
kinds of evidence and averaging them would let a confident self-report paper over a
measured weakness. The API returns both, separately, and refuses to produce a combined
figure.

*The answer is stored, not the level.* A row records `documented`, not `3`. What somebody
said is a fact about them; what it is worth on a scale is the catalogue's interpretation,
and re-tuning the ladder later must not silently rewrite the meaning of answers already
given. Same separation as findings and their check metadata.

Responses hang off the organisation rather than the domain: a backup policy is not a
property of a hostname.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0014_maturity_responses"
down_revision: str | Sequence[str] | None = "0013_remediation_actions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE TABLE maturity_responses (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

            -- Which catalogue, and which revision of it, the answer was given against.
            -- A question reworded next year is a different question, and a stored answer
            -- that silently reattaches to the new wording is a fabricated response.
            questionnaire_id text NOT NULL,
            questionnaire_version text NOT NULL,
            question_id text NOT NULL,

            -- The rung the respondent chose, by name. Deliberately not the numeric
            -- level: see the module docstring.
            answer text NOT NULL,

            -- Where the supporting documentation lives, if the respondent says it does.
            -- Naming a document is still an assertion -- the platform does not read it,
            -- and nothing here should ever be labelled 'verified' on the strength of a
            -- URL somebody typed into a box.
            evidence_reference text NULL,
            note text NULL,

            answered_by_user_id uuid NOT NULL REFERENCES users(id),
            answered_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),

            CONSTRAINT response_unique_per_question
                UNIQUE (organization_id, questionnaire_id, question_id),
            CONSTRAINT response_answer_valid CHECK (answer IN (
                'absent', 'informal', 'documented', 'verified', 'unknown', 'not_applicable'
            )),
            CONSTRAINT response_note_length
                CHECK (note IS NULL OR length(note) BETWEEN 1 AND 2000),
            CONSTRAINT response_evidence_length
                CHECK (evidence_reference IS NULL OR length(evidence_reference) BETWEEN 1 AND 500)
        );

        CREATE INDEX response_org_idx
            ON maturity_responses (organization_id, questionnaire_id);

        COMMENT ON TABLE maturity_responses IS
            'Self-declared organisational practice. Assertions, never observations, and '
            'never blended into a technical score.';

        -- Append-only, like the other history in this schema. An organisation that
        -- answered "absent" the week before an incident and "verified" the week after
        -- should not be able to make the first answer disappear.
        CREATE TABLE maturity_response_history (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            response_id uuid NOT NULL REFERENCES maturity_responses(id) ON DELETE CASCADE,
            question_id text NOT NULL,
            from_answer text NULL,
            to_answer text NOT NULL,
            actor_user_id uuid NOT NULL REFERENCES users(id),
            occurred_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE INDEX response_history_idx
            ON maturity_response_history (organization_id, occurred_at);

        CREATE TRIGGER maturity_response_history_append_only
            BEFORE UPDATE OR DELETE ON maturity_response_history
            FOR EACH ROW EXECUTE FUNCTION prevent_row_mutation();

        ALTER TABLE maturity_responses ENABLE ROW LEVEL SECURITY;
        ALTER TABLE maturity_responses FORCE ROW LEVEL SECURITY;
        ALTER TABLE maturity_response_history ENABLE ROW LEVEL SECURITY;
        ALTER TABLE maturity_response_history FORCE ROW LEVEL SECURITY;

        CREATE POLICY responses_select ON maturity_responses
            FOR SELECT USING (app_has_tenant_access(organization_id));
        CREATE POLICY responses_insert ON maturity_responses
            FOR INSERT WITH CHECK (app_has_active_membership(organization_id));
        CREATE POLICY responses_update ON maturity_responses
            FOR UPDATE USING (app_has_active_membership(organization_id))
            WITH CHECK (app_has_active_membership(organization_id));

        CREATE POLICY response_history_select ON maturity_response_history
            FOR SELECT USING (app_has_tenant_access(organization_id));
        CREATE POLICY response_history_insert ON maturity_response_history
            FOR INSERT WITH CHECK (app_has_active_membership(organization_id));

        GRANT SELECT, INSERT, UPDATE ON maturity_responses TO siembiot_app;
        GRANT SELECT, INSERT ON maturity_response_history TO siembiot_app;
        """
    )


def downgrade() -> None:
    op.execute(
        r"""
        DROP TABLE IF EXISTS maturity_response_history;
        DROP TABLE IF EXISTS maturity_responses;
        """
    )
