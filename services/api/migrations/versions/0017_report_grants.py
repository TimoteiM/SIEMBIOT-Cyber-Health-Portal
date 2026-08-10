"""Short-lived, single-use permission to download one report.

A report is the one artefact that leaves this platform: it names an institution's
weaknesses, and once downloaded it lives in a downloads folder, an inbox, and a chat
thread. So the link that produces it is treated as a credential rather than as a URL.

**The token is stored hashed.** A read of this table -- a backup, a log, a support query,
an SQL injection somewhere else -- yields no working download link. Storing it in the
clear would make the table itself the thing worth stealing.

**The grant is bound to the person who asked for it**, and redeeming still requires their
session. The token alone is therefore not enough: a link copied out of browser history,
a referrer header, or a shared screen does nothing for anybody else. A capability URL
would have been simpler and would have meant the opposite.

**Single use, and short.** `redeemed_at` is set on the first successful download, so a
link that leaks after being used is already spent. The expiry bounds the other case,
where it leaks before.

Nothing here stores the report. It is rendered on demand from the stored snapshot, which
is what makes it reproducible -- and means there is no second copy of a confidential
document sitting in a table waiting to be read.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0017_report_grants"
down_revision: str | Sequence[str] | None = "0016_support_access_discovery"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE report_grants (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            domain_id uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,

            -- Which run this report describes. Pinned at mint time rather than resolved
            -- at download: "the latest assessment" can change between the two, and a
            -- report whose contents depend on when the link was clicked is not a report.
            assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,

            -- sha256 of the token. Never the token.
            token_hash text NOT NULL UNIQUE,

            -- Fixed when the grant is minted. The reader's browser must not be able to
            -- change the language of a document somebody else is accountable for.
            locale text NOT NULL CHECK (locale IN ('ro', 'en')),

            issued_to_user_id uuid NOT NULL REFERENCES users(id),
            created_at timestamptz NOT NULL DEFAULT now(),
            expires_at timestamptz NOT NULL,
            redeemed_at timestamptz NULL,

            CONSTRAINT report_grant_expires_after_issue CHECK (expires_at > created_at)
        );

        -- Lookup is by hash, and the unique constraint already indexes it. This one is
        -- for the sweep that removes spent and expired grants.
        CREATE INDEX report_grants_expiry_idx ON report_grants (expires_at);

        ALTER TABLE report_grants ENABLE ROW LEVEL SECURITY;
        ALTER TABLE report_grants FORCE ROW LEVEL SECURITY;

        CREATE POLICY report_grants_select ON report_grants
            FOR SELECT USING (app_has_tenant_access(organization_id));
        CREATE POLICY report_grants_insert ON report_grants
            FOR INSERT WITH CHECK (app_has_tenant_access(organization_id));
        -- Update exists only to stamp `redeemed_at`. Narrowed to rows not yet spent, so
        -- the "single use" property is enforced by the database rather than resting on
        -- the application remembering to check first.
        CREATE POLICY report_grants_update ON report_grants
            FOR UPDATE USING (app_has_tenant_access(organization_id) AND redeemed_at IS NULL)
            WITH CHECK (app_has_tenant_access(organization_id));

        GRANT SELECT, INSERT, UPDATE, DELETE ON report_grants TO siembiot_app;

        -- Redeeming a grant is a chicken-and-egg problem for row-level security: the
        -- token says which organization the row belongs to, and `app_has_tenant_access`
        -- requires that organization to already be set on the connection. So the claim
        -- runs as a definer function -- and does the whole thing in one statement.
        --
        -- Every condition lives here rather than in application `if`s:
        --
        --   * the hash must match, so possession of the token is required;
        --   * the grant must belong to the caller, so a link copied out of history,
        --     a referrer or a screen share is inert in anybody else's hands;
        --   * it must be unspent and unexpired.
        --
        -- All four failures return zero rows and are therefore indistinguishable to the
        -- caller, which is the property a leaked link must not be able to defeat: "this
        -- token existed but is spent" would confirm the link was real.
        --
        -- `UPDATE ... RETURNING` also makes the single use atomic. Two simultaneous
        -- requests cannot both produce a document, because only one can move the row out
        -- of `redeemed_at IS NULL`.
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
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP FUNCTION IF EXISTS app_claim_report_grant(text);
        DROP TABLE IF EXISTS report_grants;
        """
    )
