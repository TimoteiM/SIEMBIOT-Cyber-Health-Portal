"""Move authentication out of this service.

Sessions and the OIDC login handshake are now owned by a separate team upstream, so
the tables that backed them here are dropped. Everything that depends on *who* the
user is stays: users, memberships, roles, support access grants, row-level security
and audit actor attribution are untouched.

``users.oidc_issuer`` and ``users.oidc_subject`` are deliberately kept. They remain
the join key between an upstream identity and a local user, whatever protocol the
upstream layer ends up speaking, so the columns are renamed rather than removed to
avoid implying this service still speaks OIDC itself.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0007_external_authentication"
down_revision: str | Sequence[str] | None = "0006_evidence_scoring_findings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        DROP TABLE IF EXISTS oidc_login_transactions;
        DROP TABLE IF EXISTS sessions;

        -- The identity provider is no longer this service's concern, but the pair
        -- still identifies the upstream principal, so keep the data and drop the
        -- protocol-specific naming.
        ALTER TABLE users RENAME COLUMN oidc_issuer TO identity_issuer;
        ALTER TABLE users RENAME COLUMN oidc_subject TO identity_subject;

        -- Previously maintained by the session row; now recorded against the user.
        ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_at timestamptz NULL;
        """
    )


def downgrade() -> None:
    op.execute(
        r"""
        ALTER TABLE users DROP COLUMN IF EXISTS last_seen_at;
        ALTER TABLE users RENAME COLUMN identity_subject TO oidc_subject;
        ALTER TABLE users RENAME COLUMN identity_issuer TO oidc_issuer;

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
        CREATE INDEX sessions_active_secret_idx ON sessions (secret_hash, expires_at)
            WHERE revoked_at IS NULL;

        CREATE TABLE oidc_login_transactions (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            state_hash bytea NOT NULL UNIQUE CHECK (octet_length(state_hash) = 32),
            nonce_hash bytea NOT NULL CHECK (octet_length(nonce_hash) = 32),
            pkce_verifier_ciphertext bytea NOT NULL,
            return_path text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            expires_at timestamptz NOT NULL,
            consumed_at timestamptz NULL
        );
        """
    )
