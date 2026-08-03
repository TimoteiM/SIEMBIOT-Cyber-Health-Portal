"""Add domain verification, scope authorization, and network safety state."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0004_domain_scope_safety"
down_revision: str | Sequence[str] | None = "0003_global_audit_rls"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE TABLE domains (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            canonical_name text NOT NULL CHECK (
                length(canonical_name) BETWEEN 3 AND 253
                AND canonical_name = lower(canonical_name)
                AND canonical_name !~ '[/:@*[:space:]]'
                AND canonical_name !~ '\.$'
            ),
            unicode_display text NOT NULL CHECK (length(unicode_display) BETWEEN 1 AND 253),
            registrable_domain text NOT NULL CHECK (length(registrable_domain) BETWEEN 3 AND 253),
            warnings jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(warnings) = 'array'),
            ownership_state text NOT NULL DEFAULT 'pending' CHECK (
                ownership_state IN ('pending', 'verified', 'expired', 'failed', 'revoked', 'reverification_required')
            ),
            created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            verified_at timestamptz NULL,
            reverification_due_at timestamptz NULL,
            revoked_at timestamptz NULL,
            UNIQUE (organization_id, canonical_name),
            UNIQUE (organization_id, id)
        );

        CREATE TABLE domain_challenges (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            domain_id uuid NOT NULL,
            method text NOT NULL CHECK (method IN ('dns_txt', 'https_file')),
            token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
            state text NOT NULL DEFAULT 'pending' CHECK (
                state IN ('pending', 'verified', 'expired', 'failed', 'revoked')
            ),
            attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
            max_attempts integer NOT NULL DEFAULT 5 CHECK (max_attempts = 5),
            expires_at timestamptz NOT NULL,
            created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
            created_at timestamptz NOT NULL DEFAULT now(),
            last_attempt_at timestamptz NULL,
            verified_at timestamptz NULL,
            revoked_at timestamptz NULL,
            FOREIGN KEY (organization_id, domain_id) REFERENCES domains(organization_id, id) ON DELETE RESTRICT,
            UNIQUE (organization_id, id),
            CHECK (expires_at > created_at)
        );
        CREATE UNIQUE INDEX domain_challenges_one_pending_idx
            ON domain_challenges (organization_id, domain_id, method) WHERE state = 'pending';
        CREATE INDEX domain_challenges_rate_idx
            ON domain_challenges (organization_id, domain_id, created_at DESC);

        CREATE TABLE domain_verification_events (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            domain_id uuid NOT NULL,
            challenge_id uuid NULL,
            event_type text NOT NULL CHECK (event_type ~ '^[a-z][a-z0-9_]{2,63}$'),
            outcome text NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
            reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{1,63}$'),
            occurred_at timestamptz NOT NULL DEFAULT now(),
            context jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(context) = 'object'),
            FOREIGN KEY (organization_id, domain_id) REFERENCES domains(organization_id, id) ON DELETE RESTRICT,
            FOREIGN KEY (organization_id, challenge_id) REFERENCES domain_challenges(organization_id, id) ON DELETE RESTRICT
        );

        CREATE TABLE assessment_authorizations (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            authorized_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
            state text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'active', 'expired', 'revoked')),
            policy_version text NOT NULL CHECK (policy_version ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
            consent_version text NOT NULL CHECK (consent_version ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
            consent_text_digest bytea NOT NULL CHECK (octet_length(consent_text_digest) = 32),
            valid_from timestamptz NOT NULL,
            valid_until timestamptz NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            activated_at timestamptz NULL,
            revoked_at timestamptz NULL,
            revoked_by_user_id uuid NULL REFERENCES users(id) ON DELETE RESTRICT,
            revocation_reason text NULL CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 10 AND 500),
            UNIQUE (organization_id, id),
            CHECK (valid_until > valid_from),
            CHECK ((state = 'revoked') = (revoked_at IS NOT NULL))
        );

        CREATE TABLE authorization_targets (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            authorization_id uuid NOT NULL,
            domain_id uuid NOT NULL,
            canonical_host text NOT NULL CHECK (
                length(canonical_host) BETWEEN 3 AND 253
                AND canonical_host = lower(canonical_host)
                AND canonical_host !~ '[/:@*[:space:]]'
            ),
            operation_class text NOT NULL CHECK (
                operation_class IN ('dns_verification', 'https_verification', 'passive_assessment', 'active_assessment')
            ),
            created_at timestamptz NOT NULL DEFAULT now(),
            FOREIGN KEY (organization_id, authorization_id)
                REFERENCES assessment_authorizations(organization_id, id) ON DELETE RESTRICT,
            FOREIGN KEY (organization_id, domain_id)
                REFERENCES domains(organization_id, id) ON DELETE RESTRICT,
            UNIQUE (authorization_id, canonical_host, operation_class)
        );

        CREATE TABLE scope_manifests (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            authorization_id uuid NOT NULL,
            manifest_version text NOT NULL CHECK (manifest_version = 'v1'),
            canonical_payload jsonb NOT NULL CHECK (jsonb_typeof(canonical_payload) = 'object'),
            payload_hash bytea NOT NULL UNIQUE CHECK (octet_length(payload_hash) = 32),
            signature bytea NOT NULL CHECK (octet_length(signature) = 64),
            key_id text NOT NULL CHECK (key_id ~ '^[A-Za-z0-9._-]{1,128}$'),
            algorithm text NOT NULL CHECK (algorithm = 'EdDSA'),
            created_at timestamptz NOT NULL DEFAULT now(),
            FOREIGN KEY (organization_id, authorization_id)
                REFERENCES assessment_authorizations(organization_id, id) ON DELETE RESTRICT,
            UNIQUE (organization_id, id)
        );

        CREATE TABLE emergency_controls (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            scope text NOT NULL CHECK (scope IN ('global', 'organization', 'domain', 'operation_class')),
            organization_id uuid NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            domain_id uuid NULL,
            operation_class text NULL CHECK (
                operation_class IS NULL OR operation_class IN (
                    'dns_verification', 'https_verification', 'passive_assessment', 'active_assessment'
                )
            ),
            reason text NOT NULL CHECK (length(reason) BETWEEN 10 AND 500),
            created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
            created_at timestamptz NOT NULL DEFAULT now(),
            expires_at timestamptz NULL,
            deactivated_at timestamptz NULL,
            deactivated_by_user_id uuid NULL REFERENCES users(id) ON DELETE RESTRICT,
            deactivation_reason text NULL CHECK (
                deactivation_reason IS NULL OR length(deactivation_reason) BETWEEN 10 AND 500
            ),
            FOREIGN KEY (organization_id, domain_id) REFERENCES domains(organization_id, id) ON DELETE RESTRICT,
            CHECK (
                (scope = 'global' AND organization_id IS NULL AND domain_id IS NULL AND operation_class IS NULL)
                OR (scope = 'organization' AND organization_id IS NOT NULL AND domain_id IS NULL AND operation_class IS NULL)
                OR (scope = 'domain' AND organization_id IS NOT NULL AND domain_id IS NOT NULL AND operation_class IS NULL)
                OR (scope = 'operation_class' AND organization_id IS NOT NULL AND domain_id IS NULL AND operation_class IS NOT NULL)
            ),
            CHECK (expires_at IS NULL OR expires_at > created_at),
            CHECK ((deactivated_at IS NULL) = (deactivated_by_user_id IS NULL))
        );
        CREATE UNIQUE INDEX emergency_control_one_global_active_idx
            ON emergency_controls ((true)) WHERE scope = 'global' AND deactivated_at IS NULL;
        CREATE UNIQUE INDEX emergency_control_one_org_active_idx
            ON emergency_controls (organization_id) WHERE scope = 'organization' AND deactivated_at IS NULL;
        CREATE UNIQUE INDEX emergency_control_one_domain_active_idx
            ON emergency_controls (organization_id, domain_id) WHERE scope = 'domain' AND deactivated_at IS NULL;
        CREATE UNIQUE INDEX emergency_control_one_operation_active_idx
            ON emergency_controls (organization_id, operation_class)
            WHERE scope = 'operation_class' AND deactivated_at IS NULL;

        CREATE TABLE network_operations (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            domain_id uuid NOT NULL,
            manifest_id uuid NULL,
            operation_class text NOT NULL CHECK (
                operation_class IN ('dns_verification', 'https_verification', 'passive_assessment', 'active_assessment')
            ),
            status text NOT NULL DEFAULT 'queued' CHECK (
                status IN ('queued', 'running', 'succeeded', 'rejected', 'cancelled', 'failed')
            ),
            reason_code text NULL CHECK (reason_code IS NULL OR reason_code ~ '^[a-z][a-z0-9_]{1,63}$'),
            created_at timestamptz NOT NULL DEFAULT now(),
            started_at timestamptz NULL,
            completed_at timestamptz NULL,
            cancel_requested_at timestamptz NULL,
            FOREIGN KEY (organization_id, domain_id) REFERENCES domains(organization_id, id) ON DELETE RESTRICT,
            FOREIGN KEY (organization_id, manifest_id) REFERENCES scope_manifests(organization_id, id) ON DELETE RESTRICT
        );
        CREATE INDEX network_operations_active_idx ON network_operations (organization_id, domain_id)
            WHERE status IN ('queued', 'running');

        CREATE FUNCTION app_is_phishing_resistant_platform_admin() RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
            SELECT EXISTS (
                SELECT 1 FROM users
                WHERE id = app_current_user_id()
                  AND platform_role = 'platform_admin'
                  AND mfa_assurance = 'phishing_resistant'
            )
        $$;

        CREATE FUNCTION prevent_domain_security_record_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'security record is immutable' USING ERRCODE = '42501';
        END
        $$;
        CREATE TRIGGER domain_verification_events_immutable
            BEFORE UPDATE OR DELETE ON domain_verification_events
            FOR EACH ROW EXECUTE FUNCTION prevent_domain_security_record_mutation();
        CREATE TRIGGER scope_manifests_immutable
            BEFORE UPDATE OR DELETE ON scope_manifests
            FOR EACH ROW EXECUTE FUNCTION prevent_domain_security_record_mutation();

        ALTER TABLE domains ENABLE ROW LEVEL SECURITY;
        ALTER TABLE domains FORCE ROW LEVEL SECURITY;
        CREATE POLICY domains_select ON domains FOR SELECT USING (app_has_tenant_access(organization_id));
        CREATE POLICY domains_insert ON domains FOR INSERT WITH CHECK (
            organization_id = app_current_organization_id() AND app_has_active_membership(organization_id)
        );
        CREATE POLICY domains_update ON domains FOR UPDATE USING (
            app_has_active_membership(organization_id)
        ) WITH CHECK (app_has_active_membership(organization_id));

        ALTER TABLE domain_challenges ENABLE ROW LEVEL SECURITY;
        ALTER TABLE domain_challenges FORCE ROW LEVEL SECURITY;
        CREATE POLICY domain_challenges_select ON domain_challenges FOR SELECT USING (app_has_tenant_access(organization_id));
        CREATE POLICY domain_challenges_insert ON domain_challenges FOR INSERT WITH CHECK (app_has_active_membership(organization_id));
        CREATE POLICY domain_challenges_update ON domain_challenges FOR UPDATE USING (
            app_has_active_membership(organization_id)
        ) WITH CHECK (app_has_active_membership(organization_id));

        ALTER TABLE domain_verification_events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE domain_verification_events FORCE ROW LEVEL SECURITY;
        CREATE POLICY domain_verification_events_select ON domain_verification_events FOR SELECT USING (app_has_tenant_access(organization_id));
        CREATE POLICY domain_verification_events_insert ON domain_verification_events FOR INSERT WITH CHECK (app_has_active_membership(organization_id));

        ALTER TABLE assessment_authorizations ENABLE ROW LEVEL SECURITY;
        ALTER TABLE assessment_authorizations FORCE ROW LEVEL SECURITY;
        CREATE POLICY assessment_authorizations_select ON assessment_authorizations FOR SELECT USING (app_has_tenant_access(organization_id));
        CREATE POLICY assessment_authorizations_insert ON assessment_authorizations FOR INSERT WITH CHECK (app_has_active_membership(organization_id));
        CREATE POLICY assessment_authorizations_update ON assessment_authorizations FOR UPDATE USING (
            app_has_active_membership(organization_id)
        ) WITH CHECK (app_has_active_membership(organization_id));

        ALTER TABLE authorization_targets ENABLE ROW LEVEL SECURITY;
        ALTER TABLE authorization_targets FORCE ROW LEVEL SECURITY;
        CREATE POLICY authorization_targets_select ON authorization_targets FOR SELECT USING (app_has_tenant_access(organization_id));
        CREATE POLICY authorization_targets_insert ON authorization_targets FOR INSERT WITH CHECK (app_has_active_membership(organization_id));

        ALTER TABLE scope_manifests ENABLE ROW LEVEL SECURITY;
        ALTER TABLE scope_manifests FORCE ROW LEVEL SECURITY;
        CREATE POLICY scope_manifests_select ON scope_manifests FOR SELECT USING (app_has_tenant_access(organization_id));
        CREATE POLICY scope_manifests_insert ON scope_manifests FOR INSERT WITH CHECK (app_has_active_membership(organization_id));

        ALTER TABLE emergency_controls ENABLE ROW LEVEL SECURITY;
        ALTER TABLE emergency_controls FORCE ROW LEVEL SECURITY;
        CREATE POLICY emergency_controls_select ON emergency_controls FOR SELECT USING (
            (organization_id IS NULL AND app_current_user_id() IS NOT NULL)
            OR (organization_id IS NOT NULL AND app_has_tenant_access(organization_id))
        );
        CREATE POLICY emergency_controls_insert ON emergency_controls FOR INSERT WITH CHECK (
            (organization_id IS NULL AND app_is_phishing_resistant_platform_admin())
            OR (organization_id IS NOT NULL AND app_has_active_membership(organization_id))
        );
        CREATE POLICY emergency_controls_update ON emergency_controls FOR UPDATE USING (
            (organization_id IS NULL AND app_is_phishing_resistant_platform_admin())
            OR (organization_id IS NOT NULL AND app_has_active_membership(organization_id))
        ) WITH CHECK (
            (organization_id IS NULL AND app_is_phishing_resistant_platform_admin())
            OR (organization_id IS NOT NULL AND app_has_active_membership(organization_id))
        );

        ALTER TABLE network_operations ENABLE ROW LEVEL SECURITY;
        ALTER TABLE network_operations FORCE ROW LEVEL SECURITY;
        CREATE POLICY network_operations_select ON network_operations FOR SELECT USING (app_has_tenant_access(organization_id));
        CREATE POLICY network_operations_insert ON network_operations FOR INSERT WITH CHECK (app_has_active_membership(organization_id));
        CREATE POLICY network_operations_update ON network_operations FOR UPDATE USING (
            app_has_active_membership(organization_id)
        ) WITH CHECK (app_has_active_membership(organization_id));

        GRANT SELECT, INSERT, UPDATE ON domains, domain_challenges, assessment_authorizations,
            emergency_controls, network_operations TO siembiot_app;
        GRANT SELECT, INSERT ON domain_verification_events, authorization_targets,
            scope_manifests TO siembiot_app;
        GRANT EXECUTE ON FUNCTION app_is_phishing_resistant_platform_admin() TO siembiot_app;
        """
    )


def downgrade() -> None:
    op.execute(
        r"""
        DROP TABLE IF EXISTS network_operations, emergency_controls, scope_manifests,
            authorization_targets, assessment_authorizations, domain_verification_events,
            domain_challenges, domains CASCADE;
        DROP FUNCTION IF EXISTS prevent_domain_security_record_mutation();
        DROP FUNCTION IF EXISTS app_is_phishing_resistant_platform_admin();
        """
    )
