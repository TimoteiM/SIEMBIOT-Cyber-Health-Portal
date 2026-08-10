"""Let a platform administrator find the organizations it may support.

`support_access_grants` and `app_has_support_access` have existed since the first
migration, and row-level security has consulted them on every tenant table ever since. A
platform administrator with a live grant could therefore read a customer's rows the whole
time -- provided it already knew the organization's identifier and typed it into the URL.

`app_list_my_organizations` only ever looked at memberships, so nothing in the product
could tell that administrator which organizations its grants covered. The capability was
reachable and undiscoverable, which in practice meant unusable.

**This widens what is listed, not what may be read.** Every policy still calls
`app_has_tenant_access`, which still requires an active membership or a live grant held
by a `platform_admin` with phishing-resistant MFA. What changes is that a grant now shows
up as an organization the holder can open, rather than as a permission they have to
already know about.

The `role` column returns `platform_support` for these rows. A support grant is not a
membership and must not be displayed as one: whoever is looking at that list should be
able to see, without reading the schema, that they are there as staff rather than as a
member of the organization.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0016_support_access_discovery"
down_revision: str | Sequence[str] | None = "0015_publication_boundary"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION app_list_my_organizations()
        RETURNS TABLE (id uuid, name text, slug text, created_at timestamptz, role text)
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
            SELECT o.id, o.name, o.slug, o.created_at, m.role
            FROM memberships m JOIN organizations o ON o.id = m.organization_id
            WHERE m.user_id = app_current_user_id() AND m.status = 'active'

            UNION

            -- Organizations reachable through a live support grant. The conditions are
            -- the same ones `app_has_support_access` enforces, so this cannot list an
            -- organization whose rows the caller would then be refused: an expired or
            -- revoked grant, or a user who has lost the platform role or its MFA
            -- assurance, disappears from here at the same moment it stops working.
            SELECT o.id, o.name, o.slug, o.created_at, 'platform_support'
            FROM support_access_grants g
            JOIN organizations o ON o.id = g.organization_id
            JOIN users u ON u.id = g.platform_user_id
            WHERE g.platform_user_id = app_current_user_id()
              AND g.expires_at > now()
              AND g.revoked_at IS NULL
              AND u.platform_role = 'platform_admin'
              AND u.mfa_assurance = 'phishing_resistant'

            ORDER BY 4, 1
        $$;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION app_list_my_organizations()
        RETURNS TABLE (id uuid, name text, slug text, created_at timestamptz, role text)
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
            SELECT o.id, o.name, o.slug, o.created_at, m.role
            FROM memberships m JOIN organizations o ON o.id = m.organization_id
            WHERE m.user_id = app_current_user_id() AND m.status = 'active'
            ORDER BY o.created_at, o.id
        $$;
        """
    )
