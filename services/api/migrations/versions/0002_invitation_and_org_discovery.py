"""Add safe organization discovery and invitation self-acceptance policies."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0002_invites_org_discovery"
down_revision: str | Sequence[str] | None = "0001_identity_tenancy_audit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE FUNCTION app_current_user_email() RETURNS text
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
            SELECT lower(email) FROM users WHERE id = app_current_user_id()
        $$;

        CREATE FUNCTION app_has_pending_invitation(target_organization_id uuid) RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
            SELECT EXISTS (
                SELECT 1 FROM invitations
                WHERE organization_id = target_organization_id
                  AND lower(email) = app_current_user_email()
                  AND status = 'pending'
                  AND expires_at > now()
            )
        $$;

        CREATE FUNCTION app_list_my_organizations()
        RETURNS TABLE (id uuid, name text, slug text, created_at timestamptz, role text)
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
            SELECT o.id, o.name, o.slug, o.created_at, m.role
            FROM memberships m JOIN organizations o ON o.id = m.organization_id
            WHERE m.user_id = app_current_user_id() AND m.status = 'active'
            ORDER BY o.created_at, o.id
        $$;

        DROP POLICY invitations_all ON invitations;
        CREATE POLICY invitations_select ON invitations FOR SELECT USING (
            app_has_tenant_access(organization_id)
            OR (lower(email) = app_current_user_email() AND status = 'pending' AND expires_at > now())
        );
        CREATE POLICY invitations_insert ON invitations FOR INSERT WITH CHECK (
            organization_id = app_current_organization_id()
            AND app_has_active_membership(organization_id)
        );
        CREATE POLICY invitations_update ON invitations FOR UPDATE USING (
            (organization_id = app_current_organization_id() AND app_has_active_membership(organization_id))
            OR (lower(email) = app_current_user_email() AND status = 'pending' AND expires_at > now())
        ) WITH CHECK (
            organization_id = app_current_organization_id()
            AND (app_has_active_membership(organization_id) OR accepted_by_user_id = app_current_user_id())
        );

        DROP POLICY memberships_insert ON memberships;
        CREATE POLICY memberships_insert ON memberships FOR INSERT WITH CHECK (
            organization_id = app_current_organization_id()
            AND (
                (user_id = app_current_user_id() AND role = 'organization_owner' AND app_is_org_creator(organization_id))
                OR app_has_active_membership(organization_id)
                OR (user_id = app_current_user_id() AND app_has_pending_invitation(organization_id))
            )
        );

        GRANT EXECUTE ON FUNCTION app_current_user_email(), app_has_pending_invitation(uuid), app_list_my_organizations() TO siembiot_app;
        """
    )


def downgrade() -> None:
    op.execute(
        r"""
        DROP POLICY memberships_insert ON memberships;
        CREATE POLICY memberships_insert ON memberships FOR INSERT WITH CHECK (
            organization_id = app_current_organization_id()
            AND ((user_id = app_current_user_id() AND role = 'organization_owner' AND app_is_org_creator(organization_id)) OR app_has_active_membership(organization_id))
        );
        DROP POLICY invitations_update ON invitations;
        DROP POLICY invitations_insert ON invitations;
        DROP POLICY invitations_select ON invitations;
        CREATE POLICY invitations_all ON invitations FOR ALL USING (app_has_tenant_access(organization_id)) WITH CHECK (app_has_active_membership(organization_id));
        DROP FUNCTION app_list_my_organizations();
        DROP FUNCTION app_has_pending_invitation(uuid);
        DROP FUNCTION app_current_user_email();
        """
    )
