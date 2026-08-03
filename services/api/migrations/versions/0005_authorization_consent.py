"""Capture accepted consent text and freeze authorization core fields."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0005_authorization_consent"
down_revision: str | Sequence[str] | None = "0004_domain_scope_safety"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        ALTER TABLE assessment_authorizations ADD COLUMN consent_text text NULL;
        ALTER TABLE assessment_authorizations ADD CONSTRAINT authorization_consent_text_length
            CHECK (consent_text IS NULL OR length(consent_text) BETWEEN 20 AND 10000);
        ALTER TABLE assessment_authorizations ADD CONSTRAINT active_authorization_has_consent
            CHECK (state = 'draft' OR consent_text IS NOT NULL);

        CREATE FUNCTION prevent_authorization_core_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF OLD.state <> 'draft' AND (
                NEW.organization_id IS DISTINCT FROM OLD.organization_id
                OR NEW.authorized_by_user_id IS DISTINCT FROM OLD.authorized_by_user_id
                OR NEW.policy_version IS DISTINCT FROM OLD.policy_version
                OR NEW.consent_version IS DISTINCT FROM OLD.consent_version
                OR NEW.consent_text IS DISTINCT FROM OLD.consent_text
                OR NEW.consent_text_digest IS DISTINCT FROM OLD.consent_text_digest
                OR NEW.valid_from IS DISTINCT FROM OLD.valid_from
                OR NEW.valid_until IS DISTINCT FROM OLD.valid_until
            ) THEN
                RAISE EXCEPTION 'accepted authorization core fields are immutable'
                    USING ERRCODE = '42501';
            END IF;
            RETURN NEW;
        END
        $$;
        CREATE TRIGGER assessment_authorizations_core_immutable
            BEFORE UPDATE ON assessment_authorizations
            FOR EACH ROW EXECUTE FUNCTION prevent_authorization_core_mutation();
        """
    )


def downgrade() -> None:
    op.execute(
        r"""
        DROP TRIGGER IF EXISTS assessment_authorizations_core_immutable
            ON assessment_authorizations;
        DROP FUNCTION IF EXISTS prevent_authorization_core_mutation();
        ALTER TABLE assessment_authorizations DROP CONSTRAINT IF EXISTS active_authorization_has_consent;
        ALTER TABLE assessment_authorizations DROP CONSTRAINT IF EXISTS authorization_consent_text_length;
        ALTER TABLE assessment_authorizations DROP COLUMN IF EXISTS consent_text;
        """
    )
