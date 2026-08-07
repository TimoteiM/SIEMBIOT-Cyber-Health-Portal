"""The one place this product speaks outside the tenant boundary.

Everything so far was private by construction: a row belongs to an organization and
row-level security refuses the rest. Publishing inverts that, and a mistake here is not
a leak of one tenant's data to another -- it is a leak to the internet, about a named
public institution, with their weaknesses in it.

So the boundary is a database boundary rather than a careful-coding boundary. Earlier in
this project the API was briefly connected as a superuser and every RLS policy silently
stopped applying; nothing failed, and one organization's page listed seven tenants'
domains. The lesson taken from that is the shape of this migration.

**A separate schema and a role that cannot see anything else.** The published read model
lives in `observatory`. `siembiot_public` is granted USAGE there and nowhere else --
schema `public`, which holds every tenant table, is revoked from PUBLIC and granted back
only to the three roles that need it. A public route running as `siembiot_public` cannot
select a tenant table, cannot join to one, and cannot name one: the schema does not
resolve. This is not defence in depth behind an allowlist, it is the allowlist.

**No private identifier crosses.** Nothing in `observatory` carries an organization, a
domain or a user id. A published profile is keyed on the registrable domain, which is
public by definition. The consequence is that a copy of the observatory cannot be joined
back to anything, by us or by anybody who obtains it.

**Only what somebody proved is theirs, and agreed to.** A profile may be published only
for a domain whose control was verified and whose organization opted in. Passive
observation needs no proof of control -- deliberately, because it reads only what the
domain already publishes -- but *publishing a named institution's security posture* is a
different act, and doing it for a domain nobody proved they own would be publishing
about a third party.

**Revocation deletes rather than flags.** Withdrawn consent removes the row in the same
transaction. A `visible` flag would leave the data present for anything that forgot to
check it, and the thing that forgets is always a cache or a query written later.

**Nothing is published before a named person says so.** `publication_reviews` records a
privacy and legal decision against a specific methodology version and policy digest.
The projector refuses to run without one. It is a table rather than a configuration flag
because a flag has no author, and this decision needs one.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0015_publication_boundary"
down_revision: str | Sequence[str] | None = "0014_maturity_responses"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Below this many contributing profiles an aggregate is not released. "One of the two
#: county hospitals fails DMARC" names a hospital. Enforced as a CHECK constraint rather
#: than only in the projector: a bug in the code that computes cohorts must not be able
#: to publish a small one.
MINIMUM_COHORT_SIZE = 5


def upgrade() -> None:
    op.execute(
        f"""
        -- The published read model. A separate schema so that access to it can be
        -- granted without granting anything else, which is the whole point.
        CREATE SCHEMA observatory;

        COMMENT ON SCHEMA observatory IS
            'The public read model. Contains no organization, domain or user '
            'identifiers, so nothing here can be joined back to tenant data.';

        CREATE TABLE observatory.profiles (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

            -- The key, and deliberately the only identifier. A hostname is public by
            -- definition; a domain_id would let a copy of this table be correlated with
            -- private records and with URLs in the private application.
            registrable_domain text NOT NULL UNIQUE,

            -- Null where coverage was too low to stand behind a result. Same rule as
            -- the private side: insufficient evidence removes the band rather than
            -- annotating it, and a public page is the last place to publish a number
            -- with a caveat nobody will carry with it.
            band text NULL,
            coverage_percentage numeric(5,2) NOT NULL,

            -- Which methodology and which catalogue produced this. A published claim
            -- that cannot be traced to the rules that made it is not reproducible, and
            -- somebody disputing it deserves to know what was applied.
            methodology_version text NOT NULL,
            policy_digest char(64) NOT NULL,

            observed_at timestamptz NOT NULL,
            published_at timestamptz NOT NULL DEFAULT now(),

            CONSTRAINT profile_band_valid CHECK (band IS NULL OR band IN (
                'resilient', 'managed', 'developing', 'exposed', 'critical'
            )),
            CONSTRAINT profile_coverage_range
                CHECK (coverage_percentage BETWEEN 0 AND 100),
            CONSTRAINT profile_digest_format CHECK (policy_digest ~ '^[0-9a-f]{{64}}$')
        );

        -- Per-check outcomes. Only checks the catalogue classifies as publishable ever
        -- reach here, and only score-bearing results: 'unknown' and 'error' say
        -- something about our collection rather than about the domain, and publishing
        -- them as if they described the institution would be a misattribution.
        CREATE TABLE observatory.profile_checks (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            profile_id uuid NOT NULL
                REFERENCES observatory.profiles(id) ON DELETE CASCADE,
            check_id text NOT NULL,
            result text NOT NULL,
            CONSTRAINT profile_check_unique UNIQUE (profile_id, check_id),
            CONSTRAINT profile_check_result_valid
                CHECK (result IN ('pass', 'fail', 'warning'))
        );

        -- Cohort statistics. The threshold is a constraint, not a convention.
        CREATE TABLE observatory.aggregates (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            check_id text NOT NULL,
            cohort_size integer NOT NULL,
            pass_count integer NOT NULL,
            methodology_version text NOT NULL,
            released_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT aggregate_cohort_threshold
                CHECK (cohort_size >= {MINIMUM_COHORT_SIZE}),
            CONSTRAINT aggregate_counts_sane
                CHECK (pass_count >= 0 AND pass_count <= cohort_size),
            CONSTRAINT aggregate_unique UNIQUE (check_id, methodology_version, released_at)
        );

        -- -- the private side ------------------------------------------------

        -- Opting in. Per domain rather than per organization: an institution may be
        -- willing to publish one site and not another, and a single organization-wide
        -- switch would make that an all-or-nothing decision they would answer with 'no'.
        CREATE TABLE publication_consents (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            domain_id uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
            granted_by_user_id uuid NOT NULL REFERENCES users(id),
            granted_at timestamptz NOT NULL DEFAULT now(),
            revoked_at timestamptz NULL,
            revoked_by_user_id uuid NULL REFERENCES users(id),
            revocation_reason text NULL,
            CONSTRAINT consent_revocation_consistent CHECK (
                (revoked_at IS NULL) = (revoked_by_user_id IS NULL)
            ),
            CONSTRAINT consent_reason_length CHECK (
                revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 1000
            )
        );

        -- At most one live consent per domain. Revoked rows are kept, so "did they ever
        -- agree, and when did they withdraw it" stays answerable after the fact.
        CREATE UNIQUE INDEX consent_one_active_per_domain
            ON publication_consents (domain_id) WHERE revoked_at IS NULL;
        CREATE INDEX consent_org_idx ON publication_consents (organization_id);

        -- The interlock. Not tenant data: a decision about the platform, taken once,
        -- by somebody who can be named.
        CREATE TABLE publication_reviews (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            methodology_version text NOT NULL,
            policy_digest char(64) NOT NULL,
            reviewer_name text NOT NULL,
            reviewer_role text NOT NULL,
            decision text NOT NULL,
            decided_at timestamptz NOT NULL DEFAULT now(),
            notes text NULL,
            CONSTRAINT review_decision_valid CHECK (decision IN ('approved', 'refused')),
            CONSTRAINT review_reviewer_named
                CHECK (length(trim(reviewer_name)) > 0 AND length(trim(reviewer_role)) > 0),
            CONSTRAINT review_digest_format CHECK (policy_digest ~ '^[0-9a-f]{{64}}$'),
            CONSTRAINT review_unique UNIQUE (methodology_version, policy_digest, decided_at)
        );

        COMMENT ON TABLE publication_reviews IS
            'Privacy and legal sign-off for publishing under a given methodology and '
            'catalogue. The projector refuses to run without an approving row. A table '
            'rather than a flag because this decision needs an author.';

        -- Moderation. A domain here is never published, whatever consent says: a
        -- takedown is somebody outside the tenant saying this should come down, and it
        -- has to outrank the tenant's own switch.
        CREATE TABLE publication_takedowns (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            registrable_domain text NOT NULL UNIQUE,
            reason text NOT NULL,
            recorded_by text NOT NULL,
            recorded_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT takedown_reason_length CHECK (length(trim(reason)) BETWEEN 1 AND 2000)
        );

        ALTER TABLE publication_consents ENABLE ROW LEVEL SECURITY;
        ALTER TABLE publication_consents FORCE ROW LEVEL SECURITY;

        CREATE POLICY consents_select ON publication_consents
            FOR SELECT USING (app_has_tenant_access(organization_id));
        CREATE POLICY consents_insert ON publication_consents
            FOR INSERT WITH CHECK (app_has_active_membership(organization_id));
        CREATE POLICY consents_update ON publication_consents
            FOR UPDATE USING (app_has_active_membership(organization_id))
            WITH CHECK (app_has_active_membership(organization_id));

        GRANT SELECT, INSERT, UPDATE ON publication_consents TO siembiot_app;
        GRANT SELECT ON publication_reviews, publication_takedowns TO siembiot_app;

        -- -- the boundary ----------------------------------------------------

        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'siembiot_public') THEN
                CREATE ROLE siembiot_public
                    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
            END IF;
        END
        $$;

        -- PostgreSQL grants USAGE on schema public to PUBLIC by default, so revoking it
        -- from one role achieves nothing. It is revoked from everybody and granted back
        -- to the three roles that hold tenant data -- which leaves siembiot_public
        -- unable to resolve a tenant table at all, rather than merely unable to read it.
        REVOKE USAGE ON SCHEMA public FROM PUBLIC;
        GRANT USAGE ON SCHEMA public TO siembiot_owner, siembiot_app, siembiot_worker;

        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM siembiot_public;
        REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM siembiot_public;

        GRANT USAGE ON SCHEMA observatory TO siembiot_public;
        GRANT SELECT ON ALL TABLES IN SCHEMA observatory TO siembiot_public;
        -- Read-only, permanently. The projector runs as the owner; a public route that
        -- could write to the observatory would be a defacement away from a published
        -- claim nobody made.
        REVOKE INSERT, UPDATE, DELETE, TRUNCATE
            ON ALL TABLES IN SCHEMA observatory FROM siembiot_public;

        -- So a query written without a schema qualifier finds the observatory and not
        -- something it should not have been looking at.
        ALTER ROLE siembiot_public SET search_path = observatory, pg_temp;

        -- The API may take a profile down and may never put one up.
        --
        -- Removal is always safe: the worst outcome of an unpublish nobody asked for is
        -- that a page is missing. Publication is the dangerous direction, so it stays
        -- with the projector running as the owner, behind the review interlock. This
        -- asymmetry is why the grants are listed one at a time rather than as ALL.
        GRANT USAGE ON SCHEMA observatory TO siembiot_app;
        GRANT SELECT ON ALL TABLES IN SCHEMA observatory TO siembiot_app;
        GRANT DELETE ON observatory.profiles TO siembiot_app;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP SCHEMA IF EXISTS observatory CASCADE;
        DROP TABLE IF EXISTS publication_takedowns;
        DROP TABLE IF EXISTS publication_reviews;
        DROP TABLE IF EXISTS publication_consents;
        GRANT USAGE ON SCHEMA public TO PUBLIC;
        """
    )
