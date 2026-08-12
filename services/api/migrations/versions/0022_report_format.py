"""The format a report grant was issued for.

Fixed when the grant is minted, for the same reason the language is: the reader's browser
must not be able to change the form of a document somebody else is accountable for having
sent. A link issued for a PDF produces a PDF.

It also decides availability at the right moment. PDF needs a renderer that a deployment
may not have, and finding that out when the link is clicked -- after it has been sent to
somebody -- is worse than finding out when it is asked for.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0022_report_format"
down_revision: str | Sequence[str] | None = "0021_provider_quota_snapshots"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE report_grants
            ADD COLUMN document_format text NOT NULL DEFAULT 'html'
            CHECK (document_format IN ('html', 'pdf'));

        -- Returned by the claim so the download serves what was issued. The function is
        -- replaced rather than extended: its whole value is that every condition and
        -- every returned field live in one statement.
        --
        -- Dropped first because `CREATE OR REPLACE` cannot change a return type, and the
        -- signature is unchanged so nothing else has to be updated to match.
        DROP FUNCTION IF EXISTS app_claim_report_grant(text);

        CREATE FUNCTION app_claim_report_grant(p_token_hash text)
        RETURNS TABLE (id uuid, organization_id uuid, domain_id uuid,
                       assessment_id uuid, locale text, document_format text)
        LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp AS $$
            UPDATE report_grants SET redeemed_at = now()
            WHERE token_hash = p_token_hash
              AND issued_to_user_id = app_current_user_id()
              AND redeemed_at IS NULL
              AND expires_at > now()
            RETURNING id, organization_id, domain_id, assessment_id, locale, document_format
        $$;

        REVOKE ALL ON FUNCTION app_claim_report_grant(text) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION app_claim_report_grant(text) TO siembiot_app;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP FUNCTION IF EXISTS app_claim_report_grant(text);

        CREATE FUNCTION app_claim_report_grant(p_token_hash text)
        RETURNS TABLE (id uuid, organization_id uuid, domain_id uuid,
                       assessment_id uuid, locale text)
        LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp AS $$
            UPDATE report_grants SET redeemed_at = now()
            WHERE token_hash = p_token_hash
              AND issued_to_user_id = app_current_user_id()
              AND redeemed_at IS NULL
              AND expires_at > now()
            RETURNING id, organization_id, domain_id, assessment_id, locale
        $$;

        REVOKE ALL ON FUNCTION app_claim_report_grant(text) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION app_claim_report_grant(text) TO siembiot_app;

        ALTER TABLE report_grants DROP COLUMN IF EXISTS document_format;
        """
    )
