"""Create identity, tenancy, session, authorization, and audit foundations."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0001_identity_tenancy_audit"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


SCHEMA_SQL = r"""
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    oidc_issuer text NOT NULL,
    oidc_subject text NOT NULL,
    email text NOT NULL CHECK (length(email) BETWEEN 3 AND 320),
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
    platform_role text NULL CHECK (platform_role IN ('platform_admin', 'public_catalog_moderator')),
    mfa_assurance text NOT NULL DEFAULT 'unknown' CHECK (mfa_assurance IN ('unknown', 'single_factor', 'multi_factor', 'phishing_resistant')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (oidc_issuer, oidc_subject)
);

CREATE TABLE organizations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
    created_by_user_id uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    role text NOT NULL CHECK (role IN ('organization_owner', 'security_admin', 'analyst', 'viewer_auditor', 'maturity_contributor')),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz NULL,
    UNIQUE (organization_id, user_id),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);
CREATE INDEX memberships_user_active_idx ON memberships (user_id, organization_id) WHERE status = 'active';

CREATE TABLE invitations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    email text NOT NULL CHECK (length(email) BETWEEN 3 AND 320),
    role text NOT NULL CHECK (role IN ('organization_owner', 'security_admin', 'analyst', 'viewer_auditor', 'maturity_contributor')),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    invited_by_user_id uuid NOT NULL REFERENCES users(id),
    accepted_by_user_id uuid NULL REFERENCES users(id),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    consumed_at timestamptz NULL
);
CREATE UNIQUE INDEX invitations_one_pending_email_idx ON invitations (organization_id, lower(email)) WHERE status = 'pending';

CREATE TABLE oidc_login_transactions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    state_hash bytea NOT NULL UNIQUE CHECK (octet_length(state_hash) = 32),
    nonce_hash bytea NOT NULL CHECK (octet_length(nonce_hash) = 32),
    pkce_verifier_ciphertext bytea NOT NULL,
    return_path text NOT NULL DEFAULT '/' CHECK (return_path = '/' OR return_path ~ '^/[^/\\]'),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz NULL
);

CREATE TABLE sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    secret_hash bytea NOT NULL UNIQUE CHECK (octet_length(secret_hash) = 32),
    csrf_hash bytea NOT NULL CHECK (octet_length(csrf_hash) = 32),
    oidc_sid text NULL,
    provider_logout_token_ciphertext bytea NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    revoke_reason text NULL CHECK (revoke_reason IS NULL OR length(revoke_reason) <= 200)
);
CREATE INDEX sessions_active_secret_idx ON sessions (secret_hash, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE support_access_grants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    platform_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    reason text NOT NULL CHECK (length(reason) BETWEEN 10 AND 500),
    approved_by_user_id uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    CHECK (platform_user_id <> approved_by_user_id)
);

CREATE TABLE audit_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    actor_type text NOT NULL CHECK (actor_type IN ('user', 'system')),
    actor_id text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 200),
    action text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_.]{2,127}$'),
    resource_type text NOT NULL CHECK (resource_type ~ '^[a-z][a-z0-9_]{1,63}$'),
    resource_id text NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 200),
    request_id text NOT NULL CHECK (request_id ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    correlation_id text NOT NULL CHECK (correlation_id ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    outcome text NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    context jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(context) = 'object'),
    previous_hash bytea NULL CHECK (previous_hash IS NULL OR octet_length(previous_hash) = 32),
    event_hash bytea NULL CHECK (event_hash IS NULL OR octet_length(event_hash) = 32)
);
CREATE INDEX audit_events_tenant_time_idx ON audit_events (organization_id, occurred_at DESC, id DESC);

CREATE FUNCTION app_current_user_id() RETURNS uuid
LANGUAGE sql STABLE AS $$ SELECT nullif(current_setting('app.user_id', true), '')::uuid $$;
CREATE FUNCTION app_current_organization_id() RETURNS uuid
LANGUAGE sql STABLE AS $$ SELECT nullif(current_setting('app.organization_id', true), '')::uuid $$;

CREATE FUNCTION app_has_active_membership(target_organization_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1 FROM memberships
        WHERE organization_id = target_organization_id
          AND user_id = app_current_user_id()
          AND status = 'active'
    )
$$;

CREATE FUNCTION app_has_support_access(target_organization_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1 FROM support_access_grants g
        JOIN users u ON u.id = g.platform_user_id
        WHERE g.organization_id = target_organization_id
          AND g.platform_user_id = app_current_user_id()
          AND g.expires_at > now()
          AND g.revoked_at IS NULL
          AND u.platform_role = 'platform_admin'
          AND u.mfa_assurance = 'phishing_resistant'
    )
$$;

CREATE FUNCTION app_has_tenant_access(target_organization_id uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT target_organization_id = app_current_organization_id()
       AND (app_has_active_membership(target_organization_id) OR app_has_support_access(target_organization_id))
$$;

CREATE FUNCTION app_is_org_creator(target_organization_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1 FROM organizations
        WHERE id = target_organization_id AND created_by_user_id = app_current_user_id()
    )
$$;

CREATE FUNCTION prevent_audit_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit events are immutable' USING ERRCODE = '42501'; END $$;
CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY organizations_select ON organizations FOR SELECT USING (app_has_tenant_access(id));
CREATE POLICY organizations_insert ON organizations FOR INSERT WITH CHECK (
    id = app_current_organization_id() AND created_by_user_id = app_current_user_id()
);
CREATE POLICY organizations_update ON organizations FOR UPDATE USING (app_has_active_membership(id)) WITH CHECK (app_has_active_membership(id));

ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY memberships_select ON memberships FOR SELECT USING (app_has_tenant_access(organization_id));
CREATE POLICY memberships_insert ON memberships FOR INSERT WITH CHECK (
    organization_id = app_current_organization_id()
    AND ((user_id = app_current_user_id() AND role = 'organization_owner' AND app_is_org_creator(organization_id)) OR app_has_active_membership(organization_id))
);
CREATE POLICY memberships_update ON memberships FOR UPDATE USING (app_has_active_membership(organization_id)) WITH CHECK (app_has_active_membership(organization_id));

ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY invitations_all ON invitations FOR ALL USING (app_has_tenant_access(organization_id)) WITH CHECK (app_has_active_membership(organization_id));

ALTER TABLE support_access_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE support_access_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY support_access_visible ON support_access_grants FOR SELECT USING (
    organization_id = app_current_organization_id()
    AND (app_has_active_membership(organization_id) OR platform_user_id = app_current_user_id())
);

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_events_select ON audit_events FOR SELECT USING (
    organization_id IS NULL OR app_has_tenant_access(organization_id)
);
CREATE POLICY audit_events_insert ON audit_events FOR INSERT WITH CHECK (
    (organization_id IS NULL AND actor_id = app_current_user_id()::text)
    OR (organization_id = app_current_organization_id() AND app_has_tenant_access(organization_id))
);

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO siembiot_app;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM siembiot_app;
GRANT SELECT, INSERT, UPDATE ON users, organizations, memberships, invitations, oidc_login_transactions, sessions TO siembiot_app;
GRANT DELETE ON oidc_login_transactions, sessions TO siembiot_app;
GRANT SELECT ON support_access_grants TO siembiot_app;
GRANT SELECT, INSERT ON audit_events TO siembiot_app;
GRANT EXECUTE ON FUNCTION app_current_user_id(), app_current_organization_id(), app_has_active_membership(uuid), app_has_support_access(uuid), app_has_tenant_access(uuid), app_is_org_creator(uuid) TO siembiot_app;
"""


def upgrade() -> None:
    op.execute(SCHEMA_SQL)


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE IF EXISTS audit_events, support_access_grants, sessions,
            oidc_login_transactions, invitations, memberships, organizations, users CASCADE;
        DROP FUNCTION IF EXISTS prevent_audit_mutation();
        DROP FUNCTION IF EXISTS app_is_org_creator(uuid);
        DROP FUNCTION IF EXISTS app_has_tenant_access(uuid);
        DROP FUNCTION IF EXISTS app_has_support_access(uuid);
        DROP FUNCTION IF EXISTS app_has_active_membership(uuid);
        DROP FUNCTION IF EXISTS app_current_organization_id();
        DROP FUNCTION IF EXISTS app_current_user_id();
        """
    )
