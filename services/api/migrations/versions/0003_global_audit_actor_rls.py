"""Isolate global audit events by actor for application-role reads."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0003_global_audit_rls"
down_revision: str | Sequence[str] | None = "0002_invites_org_discovery"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        DROP POLICY audit_events_select ON audit_events;
        CREATE POLICY audit_events_select ON audit_events FOR SELECT USING (
            (
                organization_id IS NULL
                AND actor_type = 'user'
                AND actor_id = app_current_user_id()::text
            )
            OR (
                organization_id IS NOT NULL
                AND app_has_tenant_access(organization_id)
            )
        );
        """
    )


def downgrade() -> None:
    op.execute(
        r"""
        DROP POLICY audit_events_select ON audit_events;
        CREATE POLICY audit_events_select ON audit_events FOR SELECT USING (
            organization_id IS NULL OR app_has_tenant_access(organization_id)
        );
        """
    )
