"""Append-only evidence, deterministic evaluations, score snapshots and findings.

Observations, evaluations and snapshots are immutable history: the database refuses
updates outright, so a completed assessment can always be reproduced exactly. Findings
are the one mutable surface, because they carry lifecycle state, and even there the
identity columns are frozen after insert.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0006_evidence_scoring_findings"
down_revision: str | Sequence[str] | None = "0005_authorization_consent"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE TABLE methodology_versions (
            version text PRIMARY KEY,
            policy_digest char(64) NOT NULL,
            published_at timestamptz NOT NULL DEFAULT now(),
            notice text NOT NULL,
            CONSTRAINT methodology_version_format CHECK (version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
            CONSTRAINT methodology_digest_format CHECK (policy_digest ~ '^[0-9a-f]{64}$')
        );

        CREATE TABLE assessments (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            domain_id uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
            authorization_id uuid NULL REFERENCES assessment_authorizations(id),
            methodology_version text NOT NULL REFERENCES methodology_versions(version),
            state text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            completed_at timestamptz NULL,
            CONSTRAINT assessment_state_valid CHECK (state IN (
                'draft', 'awaiting_authorization', 'queued', 'planning', 'collecting',
                'normalizing', 'evaluating', 'agent_analysis', 'report_generation',
                'completed', 'cancelled', 'partially_completed', 'failed', 'expired',
                'blocked_by_policy'
            )),
            CONSTRAINT assessment_completion_consistent CHECK (
                (state IN ('completed', 'partially_completed')) = (completed_at IS NOT NULL)
            )
        );
        CREATE INDEX assessments_org_domain_idx ON assessments (organization_id, domain_id);

        CREATE TABLE normalized_observations (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            subject_kind text NOT NULL,
            subject_identifier text NOT NULL,
            authorized_domain_id uuid NULL REFERENCES domains(id),
            observation_type text NOT NULL,
            status text NOT NULL,
            attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
            attribution_confidence numeric(3,2) NOT NULL,
            source_confidence numeric(3,2) NOT NULL,
            freshness_confidence numeric(3,2) NOT NULL,
            confidence_reasons text[] NOT NULL DEFAULT '{}',
            adapter_id text NOT NULL,
            adapter_version text NOT NULL,
            collected_at timestamptz NOT NULL,
            observed_at timestamptz NULL,
            from_cache boolean NOT NULL DEFAULT false,
            source_reference text NULL,
            content_hash char(64) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT observation_status_valid CHECK (status IN (
                'observed', 'absent', 'inconclusive', 'not_applicable'
            )),
            CONSTRAINT observation_subject_kind_valid CHECK (subject_kind IN (
                'domain', 'hostname', 'mx_host', 'url', 'ip_address', 'certificate'
            )),
            CONSTRAINT observation_hash_format CHECK (content_hash ~ '^[0-9a-f]{64}$'),
            CONSTRAINT observation_confidence_range CHECK (
                attribution_confidence BETWEEN 0 AND 1
                AND source_confidence BETWEEN 0 AND 1
                AND freshness_confidence BETWEEN 0 AND 1
            ),
            CONSTRAINT observation_absent_carries_no_evidence CHECK (
                status = 'observed' OR attributes = '{}'::jsonb
            ),
            CONSTRAINT observation_unique_per_assessment UNIQUE (
                assessment_id, subject_identifier, observation_type
            )
        );
        CREATE INDEX observations_org_idx ON normalized_observations (organization_id);
        CREATE INDEX observations_hash_idx ON normalized_observations (content_hash);

        CREATE TABLE check_evaluations (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            check_id text NOT NULL,
            check_version text NOT NULL,
            methodology_version text NOT NULL REFERENCES methodology_versions(version),
            pillar text NOT NULL,
            subject_kind text NOT NULL,
            subject_identifier text NOT NULL,
            result text NOT NULL,
            score_bearing boolean NOT NULL,
            weight numeric(6,2) NOT NULL,
            severity text NOT NULL,
            reason_code text NULL,
            observation_ids uuid[] NOT NULL DEFAULT '{}',
            attribution_confidence numeric(3,2) NOT NULL,
            source_confidence numeric(3,2) NOT NULL,
            freshness_confidence numeric(3,2) NOT NULL,
            evaluated_at timestamptz NOT NULL,
            CONSTRAINT evaluation_result_valid CHECK (result IN (
                'pass', 'fail', 'warning', 'unknown', 'error',
                'not_applicable', 'suppressed', 'accepted_risk'
            )),
            CONSTRAINT evaluation_pillar_valid CHECK (pillar IN (
                'dns', 'email', 'web_tls', 'attack_surface', 'reputation', 'exposure_hygiene'
            )),
            CONSTRAINT evaluation_severity_valid CHECK (severity IN (
                'critical', 'high', 'medium', 'low', 'informational'
            )),
            CONSTRAINT evaluation_score_bearing_matches_result CHECK (
                score_bearing = (result IN ('pass', 'fail', 'warning'))
            ),
            CONSTRAINT evaluation_weight_positive CHECK (weight > 0),
            CONSTRAINT evaluation_unique_per_assessment UNIQUE (
                assessment_id, check_id, subject_identifier
            )
        );
        CREATE INDEX evaluations_org_idx ON check_evaluations (organization_id);

        CREATE TABLE score_snapshots (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            methodology_version text NOT NULL REFERENCES methodology_versions(version),
            is_projection boolean NOT NULL DEFAULT false,
            policy_digest char(64) NOT NULL,
            evidence_digest char(64) NOT NULL,
            uncapped_score numeric(5,2) NULL,
            score numeric(5,2) NULL,
            band text NOT NULL,
            coverage_percentage numeric(5,2) NOT NULL,
            coverage_sufficient boolean NOT NULL,
            document jsonb NOT NULL,
            computed_at timestamptz NOT NULL,
            CONSTRAINT snapshot_band_valid CHECK (band IN (
                'resilient', 'managed', 'developing', 'exposed', 'critical',
                'insufficient_coverage'
            )),
            CONSTRAINT snapshot_score_range CHECK (
                (score IS NULL OR score BETWEEN 0 AND 100)
                AND (uncapped_score IS NULL OR uncapped_score BETWEEN 0 AND 100)
            ),
            CONSTRAINT snapshot_cap_only_lowers CHECK (
                score IS NULL OR uncapped_score IS NULL OR score <= uncapped_score
            ),
            CONSTRAINT snapshot_digest_format CHECK (
                policy_digest ~ '^[0-9a-f]{64}$' AND evidence_digest ~ '^[0-9a-f]{64}$'
            ),
            CONSTRAINT snapshot_one_original_per_methodology UNIQUE (
                assessment_id, methodology_version, is_projection
            )
        );
        CREATE INDEX snapshots_org_idx ON score_snapshots (organization_id, computed_at DESC);

        CREATE TABLE findings (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            fingerprint char(64) NOT NULL,
            check_id text NOT NULL,
            check_version text NOT NULL,
            methodology_version text NOT NULL REFERENCES methodology_versions(version),
            pillar text NOT NULL,
            subject_kind text NOT NULL,
            subject_identifier text NOT NULL,
            authorized_domain_id uuid NULL REFERENCES domains(id),
            severity text NOT NULL,
            state text NOT NULL,
            reason_code text NULL,
            public_safety_class text NOT NULL,
            attribution_confidence numeric(3,2) NOT NULL,
            source_confidence numeric(3,2) NOT NULL,
            freshness_confidence numeric(3,2) NOT NULL,
            first_seen_at timestamptz NOT NULL,
            last_seen_at timestamptz NOT NULL,
            resolved_at timestamptz NULL,
            evidence_observation_ids uuid[] NOT NULL DEFAULT '{}',
            CONSTRAINT finding_state_valid CHECK (state IN (
                'open', 'resolved', 'regressed', 'suppressed', 'accepted_risk'
            )),
            CONSTRAINT finding_severity_valid CHECK (severity IN (
                'critical', 'high', 'medium', 'low', 'informational'
            )),
            CONSTRAINT finding_public_safety_valid CHECK (public_safety_class IN (
                'public_aggregate', 'public_profile', 'private_only'
            )),
            CONSTRAINT finding_fingerprint_format CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
            CONSTRAINT finding_resolution_consistent CHECK (
                (state = 'resolved') = (resolved_at IS NOT NULL)
            ),
            CONSTRAINT finding_seen_order CHECK (last_seen_at >= first_seen_at),
            CONSTRAINT finding_unique_per_tenant UNIQUE (organization_id, fingerprint)
        );
        CREATE INDEX findings_org_state_idx ON findings (organization_id, state, severity);

        CREATE TABLE finding_suppressions (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            reason text NOT NULL,
            accepted_risk boolean NOT NULL DEFAULT false,
            actor_user_id uuid NOT NULL REFERENCES users(id),
            created_at timestamptz NOT NULL DEFAULT now(),
            expires_at timestamptz NOT NULL,
            revoked_at timestamptz NULL,
            CONSTRAINT suppression_reason_length CHECK (length(reason) BETWEEN 8 AND 2000),
            CONSTRAINT suppression_must_expire CHECK (expires_at > created_at)
        );
        CREATE INDEX finding_suppressions_finding_idx ON finding_suppressions (finding_id);

        CREATE TABLE finding_history (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            assessment_id uuid NULL REFERENCES assessments(id) ON DELETE SET NULL,
            from_state text NOT NULL,
            to_state text NOT NULL,
            actor_user_id uuid NULL REFERENCES users(id),
            occurred_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT finding_history_states_valid CHECK (
                from_state IN ('open', 'resolved', 'regressed', 'suppressed',
                               'accepted_risk', 'absent')
                AND to_state IN ('open', 'resolved', 'regressed', 'suppressed', 'accepted_risk')
            )
        );
        CREATE INDEX finding_history_finding_idx ON finding_history (finding_id, occurred_at);
        """
    )

    # Immutability. Evidence and scores are history; rewriting them would make a
    # completed assessment unreproducible, so the database refuses rather than trusting
    # the application layer to remember.
    op.execute(
        r"""
        CREATE FUNCTION prevent_row_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION '% rows are append-only', TG_TABLE_NAME USING ERRCODE = '42501';
        END
        $$;

        CREATE TRIGGER observations_append_only
            BEFORE UPDATE OR DELETE ON normalized_observations
            FOR EACH ROW EXECUTE FUNCTION prevent_row_mutation();
        CREATE TRIGGER evaluations_append_only
            BEFORE UPDATE OR DELETE ON check_evaluations
            FOR EACH ROW EXECUTE FUNCTION prevent_row_mutation();
        CREATE TRIGGER snapshots_append_only
            BEFORE UPDATE OR DELETE ON score_snapshots
            FOR EACH ROW EXECUTE FUNCTION prevent_row_mutation();
        CREATE TRIGGER finding_history_append_only
            BEFORE UPDATE OR DELETE ON finding_history
            FOR EACH ROW EXECUTE FUNCTION prevent_row_mutation();

        CREATE FUNCTION prevent_finding_identity_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
                OR NEW.fingerprint IS DISTINCT FROM OLD.fingerprint
                OR NEW.check_id IS DISTINCT FROM OLD.check_id
                OR NEW.subject_identifier IS DISTINCT FROM OLD.subject_identifier
                OR NEW.first_seen_at IS DISTINCT FROM OLD.first_seen_at
            THEN
                RAISE EXCEPTION 'finding identity is immutable' USING ERRCODE = '42501';
            END IF;
            RETURN NEW;
        END
        $$;
        CREATE TRIGGER findings_identity_immutable
            BEFORE UPDATE ON findings
            FOR EACH ROW EXECUTE FUNCTION prevent_finding_identity_mutation();
        """
    )

    # Tenant isolation, mirroring the Milestone 1 helper functions.
    op.execute(
        r"""
        ALTER TABLE assessments ENABLE ROW LEVEL SECURITY;
        ALTER TABLE normalized_observations ENABLE ROW LEVEL SECURITY;
        ALTER TABLE check_evaluations ENABLE ROW LEVEL SECURITY;
        ALTER TABLE score_snapshots ENABLE ROW LEVEL SECURITY;
        ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
        ALTER TABLE finding_suppressions ENABLE ROW LEVEL SECURITY;
        ALTER TABLE finding_history ENABLE ROW LEVEL SECURITY;
        ALTER TABLE assessments FORCE ROW LEVEL SECURITY;
        ALTER TABLE normalized_observations FORCE ROW LEVEL SECURITY;
        ALTER TABLE check_evaluations FORCE ROW LEVEL SECURITY;
        ALTER TABLE score_snapshots FORCE ROW LEVEL SECURITY;
        ALTER TABLE findings FORCE ROW LEVEL SECURITY;
        ALTER TABLE finding_suppressions FORCE ROW LEVEL SECURITY;
        ALTER TABLE finding_history FORCE ROW LEVEL SECURITY;

        CREATE POLICY assessments_select ON assessments FOR SELECT
            USING (app_has_tenant_access(organization_id));
        CREATE POLICY assessments_insert ON assessments FOR INSERT
            WITH CHECK (app_has_active_membership(organization_id));
        CREATE POLICY assessments_update ON assessments FOR UPDATE
            USING (app_has_active_membership(organization_id))
            WITH CHECK (app_has_active_membership(organization_id));

        CREATE POLICY observations_select ON normalized_observations FOR SELECT
            USING (app_has_tenant_access(organization_id));
        CREATE POLICY observations_insert ON normalized_observations FOR INSERT
            WITH CHECK (app_has_active_membership(organization_id));

        CREATE POLICY evaluations_select ON check_evaluations FOR SELECT
            USING (app_has_tenant_access(organization_id));
        CREATE POLICY evaluations_insert ON check_evaluations FOR INSERT
            WITH CHECK (app_has_active_membership(organization_id));

        CREATE POLICY snapshots_select ON score_snapshots FOR SELECT
            USING (app_has_tenant_access(organization_id));
        CREATE POLICY snapshots_insert ON score_snapshots FOR INSERT
            WITH CHECK (app_has_active_membership(organization_id));

        CREATE POLICY findings_select ON findings FOR SELECT
            USING (app_has_tenant_access(organization_id));
        CREATE POLICY findings_insert ON findings FOR INSERT
            WITH CHECK (app_has_active_membership(organization_id));
        CREATE POLICY findings_update ON findings FOR UPDATE
            USING (app_has_active_membership(organization_id))
            WITH CHECK (app_has_active_membership(organization_id));

        CREATE POLICY finding_suppressions_select ON finding_suppressions FOR SELECT
            USING (app_has_tenant_access(organization_id));
        CREATE POLICY finding_suppressions_insert ON finding_suppressions FOR INSERT
            WITH CHECK (app_has_active_membership(organization_id));
        CREATE POLICY finding_suppressions_update ON finding_suppressions FOR UPDATE
            USING (app_has_active_membership(organization_id))
            WITH CHECK (app_has_active_membership(organization_id));

        CREATE POLICY finding_history_select ON finding_history FOR SELECT
            USING (app_has_tenant_access(organization_id));
        CREATE POLICY finding_history_insert ON finding_history FOR INSERT
            WITH CHECK (app_has_active_membership(organization_id));

        GRANT SELECT ON methodology_versions TO siembiot_app;
        GRANT SELECT, INSERT, UPDATE ON assessments, findings, finding_suppressions
            TO siembiot_app;
        GRANT SELECT, INSERT ON normalized_observations, check_evaluations,
            score_snapshots, finding_history TO siembiot_app;
        """
    )


def downgrade() -> None:
    op.execute(
        r"""
        DROP TABLE IF EXISTS finding_history;
        DROP TABLE IF EXISTS finding_suppressions;
        DROP TABLE IF EXISTS findings;
        DROP TABLE IF EXISTS score_snapshots;
        DROP TABLE IF EXISTS check_evaluations;
        DROP TABLE IF EXISTS normalized_observations;
        DROP TABLE IF EXISTS assessments;
        DROP TABLE IF EXISTS methodology_versions;
        DROP FUNCTION IF EXISTS prevent_finding_identity_mutation();
        DROP FUNCTION IF EXISTS prevent_row_mutation();
        """
    )
