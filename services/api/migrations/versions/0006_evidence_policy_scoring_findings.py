"""Add immutable tenant evidence, scoring, and finding history."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0006_evidence_scoring"
down_revision: str | Sequence[str] | None = "0005_authorization_consent"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(r"""
    ALTER TABLE audit_events ADD CONSTRAINT audit_events_organization_id_id_key UNIQUE(organization_id,id);
    CREATE TYPE evidence_mode AS ENUM ('fixture', 'live');
    CREATE TYPE evaluation_outcome AS ENUM ('pass','fail','warning','unknown','error','not_applicable','suppressed','accepted_risk');

    CREATE TABLE raw_artifacts (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
      asset_id uuid NOT NULL, scope_manifest_id uuid NOT NULL, evidence_mode evidence_mode NOT NULL,
      artifact_hash bytea NOT NULL CHECK(octet_length(artifact_hash)=32), hash_version text NOT NULL CHECK(hash_version='sha256-v1'),
      classification text NOT NULL CHECK(classification IN ('public_metadata','private_metadata','sensitive')),
      storage_key text NULL CHECK(storage_key IS NULL OR length(storage_key) BETWEEN 1 AND 512), byte_length bigint NOT NULL CHECK(byte_length>=0),
      publishable boolean NOT NULL DEFAULT false, real_world boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now(),
      FOREIGN KEY(organization_id,asset_id) REFERENCES domains(organization_id,id) ON DELETE RESTRICT,
      FOREIGN KEY(organization_id,scope_manifest_id) REFERENCES scope_manifests(organization_id,id) ON DELETE RESTRICT,
      UNIQUE(organization_id,id,evidence_mode), UNIQUE(organization_id,artifact_hash),
      CHECK(evidence_mode <> 'fixture' OR (NOT publishable AND NOT real_world))
    );
    CREATE TABLE normalized_observations (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
      asset_id uuid NOT NULL, scope_manifest_id uuid NOT NULL, raw_artifact_id uuid NULL, evidence_mode evidence_mode NOT NULL,
      normalized_hash bytea NOT NULL CHECK(octet_length(normalized_hash)=32), hash_version text NOT NULL CHECK(hash_version='sha256-v1'),
      schema_version text NOT NULL CHECK(schema_version='v1'), observation_type text NOT NULL CHECK(observation_type ~ '^[a-z][a-z0-9._-]{1,127}$'),
      source_evidence_id text NOT NULL CHECK(source_evidence_id ~ '^sha256:[a-f0-9]{64}$'), payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'),
      observed_at timestamptz NOT NULL, source_confidence numeric(7,6) NOT NULL CHECK(source_confidence BETWEEN 0 AND 1),
      attribution_confidence numeric(7,6) NOT NULL CHECK(attribution_confidence BETWEEN 0 AND 1),
      publishable boolean NOT NULL DEFAULT false, real_world boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now(),
      FOREIGN KEY(organization_id,asset_id) REFERENCES domains(organization_id,id) ON DELETE RESTRICT,
      FOREIGN KEY(organization_id,scope_manifest_id) REFERENCES scope_manifests(organization_id,id) ON DELETE RESTRICT,
      FOREIGN KEY(organization_id,raw_artifact_id,evidence_mode) REFERENCES raw_artifacts(organization_id,id,evidence_mode) ON DELETE RESTRICT,
      UNIQUE(organization_id,id,evidence_mode), UNIQUE(organization_id,normalized_hash),
      CHECK(evidence_mode <> 'fixture' OR (NOT publishable AND NOT real_world))
    );
    CREATE TABLE check_evaluations (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
      asset_id uuid NOT NULL, scope_manifest_id uuid NOT NULL, evidence_mode evidence_mode NOT NULL,
      evaluation_hash bytea NOT NULL CHECK(octet_length(evaluation_hash)=32), policy_hash bytea NOT NULL CHECK(octet_length(policy_hash)=32),
      check_id text NOT NULL CHECK(check_id ~ '^[a-z][a-z0-9._-]{2,127}$'), methodology_version text NOT NULL,
      scoring_behavior_version text NOT NULL, outcome evaluation_outcome NOT NULL, reason_code text NOT NULL CHECK(reason_code ~ '^[a-z][a-z0-9_]{1,63}$'),
      evaluated_at timestamptz NOT NULL, publishable boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now(),
      FOREIGN KEY(organization_id,asset_id) REFERENCES domains(organization_id,id) ON DELETE RESTRICT,
      FOREIGN KEY(organization_id,scope_manifest_id) REFERENCES scope_manifests(organization_id,id) ON DELETE RESTRICT,
      UNIQUE(organization_id,id,evidence_mode), UNIQUE(organization_id,evaluation_hash), CHECK(evidence_mode <> 'fixture' OR NOT publishable)
    );
    CREATE TABLE evaluation_evidence (
      organization_id uuid NOT NULL, evaluation_id uuid NOT NULL, observation_id uuid NOT NULL, evidence_mode evidence_mode NOT NULL,
      PRIMARY KEY(organization_id,evaluation_id,observation_id),
      FOREIGN KEY(organization_id,evaluation_id,evidence_mode) REFERENCES check_evaluations(organization_id,id,evidence_mode) ON DELETE RESTRICT,
      FOREIGN KEY(organization_id,observation_id,evidence_mode) REFERENCES normalized_observations(organization_id,id,evidence_mode) ON DELETE RESTRICT
    );
    CREATE TABLE score_snapshots (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
      asset_id uuid NOT NULL, scope_manifest_id uuid NOT NULL, evidence_mode evidence_mode NOT NULL,
      snapshot_hash bytea NOT NULL CHECK(octet_length(snapshot_hash)=32), policy_hash bytea NOT NULL CHECK(octet_length(policy_hash)=32),
      methodology_version text NOT NULL, scoring_behavior_version text NOT NULL, technical_posture numeric(9,6) NULL CHECK(technical_posture BETWEEN 0 AND 100),
      coverage numeric(9,6) NOT NULL CHECK(coverage BETWEEN 0 AND 100), evidence_confidence numeric(7,6) NOT NULL CHECK(evidence_confidence BETWEEN 0 AND 1),
      attribution_confidence numeric(7,6) NOT NULL CHECK(attribution_confidence BETWEEN 0 AND 1),
      publishable boolean NOT NULL DEFAULT false, classification text NOT NULL CHECK(classification IN ('DEMO/FIXTURE','PRIVATE')),
      created_at timestamptz NOT NULL DEFAULT now(),
      FOREIGN KEY(organization_id,asset_id) REFERENCES domains(organization_id,id) ON DELETE RESTRICT,
      FOREIGN KEY(organization_id,scope_manifest_id) REFERENCES scope_manifests(organization_id,id) ON DELETE RESTRICT,
      UNIQUE(organization_id,id,evidence_mode), UNIQUE(organization_id,snapshot_hash),
      CHECK(evidence_mode <> 'fixture' OR (NOT publishable AND classification='DEMO/FIXTURE'))
    );
    CREATE TABLE snapshot_evaluations (
      organization_id uuid NOT NULL, snapshot_id uuid NOT NULL, evaluation_id uuid NOT NULL, evidence_mode evidence_mode NOT NULL,
      PRIMARY KEY(organization_id,snapshot_id,evaluation_id),
      FOREIGN KEY(organization_id,snapshot_id,evidence_mode) REFERENCES score_snapshots(organization_id,id,evidence_mode) ON DELETE RESTRICT,
      FOREIGN KEY(organization_id,evaluation_id,evidence_mode) REFERENCES check_evaluations(organization_id,id,evidence_mode) ON DELETE RESTRICT
    );
    CREATE TABLE score_attributions (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
      snapshot_id uuid NOT NULL, evidence_mode evidence_mode NOT NULL, attribution_type text NOT NULL CHECK(attribution_type IN ('evidence','methodology','applicability','coverage','confidence')),
      reason_code text NOT NULL CHECK(reason_code ~ '^[a-z][a-z0-9_]{1,63}$'), details jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(details)='object'), created_at timestamptz NOT NULL DEFAULT now(),
      FOREIGN KEY(organization_id,snapshot_id,evidence_mode) REFERENCES score_snapshots(organization_id,id,evidence_mode) ON DELETE RESTRICT,
      UNIQUE(organization_id,id,evidence_mode)
    );
    CREATE TABLE findings (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
      asset_id uuid NOT NULL, scope_manifest_id uuid NOT NULL, evidence_mode evidence_mode NOT NULL,
      fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32), fingerprint_version text NOT NULL CHECK(fingerprint_version='fingerprint-v1'),
      identity_digest bytea NOT NULL CHECK(octet_length(identity_digest)=32), check_id text NOT NULL, policy_hash bytea NOT NULL CHECK(octet_length(policy_hash)=32),
      attribution_state text NOT NULL CHECK(attribution_state IN ('direct','shared_hosting','uncertain')),
      severity text NOT NULL CHECK(severity IN ('info','low','medium','high','critical')), first_seen_at timestamptz NOT NULL,
      publishable boolean NOT NULL DEFAULT false, classification text NOT NULL CHECK(classification IN ('DEMO/FIXTURE','PRIVATE')), created_at timestamptz NOT NULL DEFAULT now(),
      FOREIGN KEY(organization_id,asset_id) REFERENCES domains(organization_id,id) ON DELETE RESTRICT,
      FOREIGN KEY(organization_id,scope_manifest_id) REFERENCES scope_manifests(organization_id,id) ON DELETE RESTRICT,
      UNIQUE(organization_id,id,evidence_mode), UNIQUE(organization_id,fingerprint),
      CHECK(evidence_mode <> 'fixture' OR (NOT publishable AND classification='DEMO/FIXTURE'))
    );
    CREATE TABLE finding_occurrences (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL, finding_id uuid NOT NULL, evaluation_id uuid NOT NULL,
      evidence_mode evidence_mode NOT NULL, observed_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
      FOREIGN KEY(organization_id,finding_id,evidence_mode) REFERENCES findings(organization_id,id,evidence_mode) ON DELETE RESTRICT,
      FOREIGN KEY(organization_id,evaluation_id,evidence_mode) REFERENCES check_evaluations(organization_id,id,evidence_mode) ON DELETE RESTRICT,
      UNIQUE(organization_id,id,evidence_mode), UNIQUE(organization_id,finding_id,evaluation_id)
    );
    CREATE TABLE finding_events (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL, finding_id uuid NOT NULL, evidence_mode evidence_mode NOT NULL,
      event_hash bytea NOT NULL CHECK(octet_length(event_hash)=32), event_type text NOT NULL CHECK(event_type IN ('observed','suppressed','accepted_risk','reopened','expired_review','remediation_verified')),
      actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT, reason text NOT NULL CHECK(length(reason) BETWEEN 10 AND 1000),
      scope_reference text NOT NULL, occurred_at timestamptz NOT NULL, review_at timestamptz NULL,
      request_id text NOT NULL, correlation_id text NOT NULL, audit_event_id uuid NOT NULL,
      FOREIGN KEY(organization_id,finding_id,evidence_mode) REFERENCES findings(organization_id,id,evidence_mode) ON DELETE RESTRICT,
      FOREIGN KEY(organization_id,audit_event_id) REFERENCES audit_events(organization_id,id) ON DELETE RESTRICT,
      UNIQUE(organization_id,id,evidence_mode), UNIQUE(organization_id,event_hash),
      CHECK(event_type NOT IN ('suppressed','accepted_risk') OR review_at > occurred_at)
    );

    CREATE FUNCTION prevent_evidence_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'evidence history is immutable' USING ERRCODE='42501'; END $$;
    DO $$ DECLARE table_name text; BEGIN
      FOREACH table_name IN ARRAY ARRAY['raw_artifacts','normalized_observations','check_evaluations','evaluation_evidence','score_snapshots','snapshot_evaluations','score_attributions','findings','finding_occurrences','finding_events']
      LOOP EXECUTE format('CREATE TRIGGER %I_immutable BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION prevent_evidence_mutation()', table_name, table_name); END LOOP;
    END $$;
    CREATE FUNCTION validate_finding_event() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE prior_state text; expected_scope text; member_role text;
    BEGIN
      SELECT scope_manifest_id::text INTO expected_scope FROM findings
        WHERE organization_id=NEW.organization_id AND id=NEW.finding_id;
      IF NEW.scope_reference <> expected_scope THEN
        RAISE EXCEPTION 'finding scope mismatch' USING ERRCODE='23514';
      END IF;
      SELECT event_type INTO prior_state FROM finding_events
        WHERE organization_id=NEW.organization_id AND finding_id=NEW.finding_id
        ORDER BY occurred_at DESC,id DESC LIMIT 1;
      IF prior_state IS NULL AND NEW.event_type <> 'observed' THEN
        RAISE EXCEPTION 'first finding event must be observed' USING ERRCODE='23514';
      END IF;
      IF prior_state IS NOT NULL AND NEW.event_type='observed' THEN
        RAISE EXCEPTION 'observed event already exists' USING ERRCODE='23514';
      END IF;
      IF NEW.event_type IN ('suppressed','accepted_risk','remediation_verified')
         AND prior_state NOT IN ('observed','reopened','expired_review') THEN
        RAISE EXCEPTION 'invalid finding transition' USING ERRCODE='23514';
      END IF;
      IF NEW.event_type='reopened' AND prior_state NOT IN ('suppressed','accepted_risk') THEN
        RAISE EXCEPTION 'invalid finding transition' USING ERRCODE='23514';
      END IF;
      IF current_user='siembiot_app' THEN
        SELECT role INTO member_role FROM memberships WHERE organization_id=NEW.organization_id
          AND user_id=app_current_user_id() AND status='active';
        IF member_role NOT IN ('organization_owner','security_admin') OR NEW.actor_id<>app_current_user_id() THEN
          RAISE EXCEPTION 'finding event actor not authorized' USING ERRCODE='42501';
        END IF;
      END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER finding_events_validate BEFORE INSERT ON finding_events
      FOR EACH ROW EXECUTE FUNCTION validate_finding_event();
    CREATE FUNCTION reject_finding_fingerprint_collision() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE existing_digest bytea;
    BEGIN
      SELECT identity_digest INTO existing_digest FROM findings
        WHERE organization_id=NEW.organization_id AND fingerprint=NEW.fingerprint;
      IF existing_digest IS NOT NULL AND existing_digest<>NEW.identity_digest THEN
        RAISE EXCEPTION 'finding_fingerprint_collision' USING ERRCODE='23505';
      END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER findings_collision_guard BEFORE INSERT ON findings
      FOR EACH ROW EXECUTE FUNCTION reject_finding_fingerprint_collision();
    DO $$ DECLARE table_name text; BEGIN
      FOREACH table_name IN ARRAY ARRAY['raw_artifacts','normalized_observations','check_evaluations','evaluation_evidence','score_snapshots','snapshot_evaluations','score_attributions','findings','finding_occurrences','finding_events']
      LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('CREATE POLICY %I_select ON %I FOR SELECT USING ((current_user=''siembiot_worker'' AND organization_id=app_current_organization_id()) OR app_has_tenant_access(organization_id))', table_name, table_name);
        EXECUTE format('CREATE POLICY %I_worker_insert ON %I FOR INSERT WITH CHECK (current_user=''siembiot_worker'' AND organization_id=app_current_organization_id())', table_name, table_name);
      END LOOP;
    END $$;
    CREATE POLICY finding_events_app_insert ON finding_events FOR INSERT TO siembiot_app
      WITH CHECK (organization_id=app_current_organization_id() AND actor_id=app_current_user_id()
        AND EXISTS(SELECT 1 FROM memberships WHERE organization_id=finding_events.organization_id
          AND user_id=app_current_user_id() AND status='active' AND role IN ('organization_owner','security_admin')));
    GRANT USAGE ON SCHEMA public TO siembiot_worker;
    GRANT EXECUTE ON FUNCTION app_current_organization_id() TO siembiot_worker;
    GRANT SELECT,INSERT ON raw_artifacts,normalized_observations,check_evaluations,evaluation_evidence,score_snapshots,snapshot_evaluations,score_attributions,findings,finding_occurrences,finding_events TO siembiot_worker;
    GRANT SELECT ON raw_artifacts,normalized_observations,check_evaluations,evaluation_evidence,score_snapshots,snapshot_evaluations,score_attributions,findings,finding_occurrences,finding_events TO siembiot_app;
    GRANT INSERT ON finding_events TO siembiot_app;
    CREATE VIEW current_finding_states WITH (security_invoker=true) AS
      SELECT DISTINCT ON (f.organization_id,f.id) f.organization_id,f.id AS finding_id,f.evidence_mode,e.event_type AS state,e.occurred_at,e.review_at,(e.review_at IS NOT NULL AND e.review_at<=now()) AS review_due
      FROM findings f LEFT JOIN finding_events e ON e.organization_id=f.organization_id AND e.finding_id=f.id AND e.evidence_mode=f.evidence_mode
      ORDER BY f.organization_id,f.id,e.occurred_at DESC,e.id DESC;
    GRANT SELECT ON current_finding_states TO siembiot_app;
    CREATE VIEW publishable_score_snapshots WITH (security_invoker=true) AS
      SELECT * FROM score_snapshots WHERE evidence_mode='live' AND publishable AND classification='PRIVATE';
    GRANT SELECT ON publishable_score_snapshots TO siembiot_app;
    GRANT SELECT ON publishable_score_snapshots TO siembiot_worker;
    """)


def downgrade() -> None:
    op.execute(r"""
    DROP VIEW IF EXISTS publishable_score_snapshots;
    DROP VIEW IF EXISTS current_finding_states;
    DROP TABLE IF EXISTS finding_events,finding_occurrences,findings,score_attributions,snapshot_evaluations,score_snapshots,evaluation_evidence,check_evaluations,normalized_observations,raw_artifacts CASCADE;
    DROP FUNCTION IF EXISTS prevent_evidence_mutation();
    DROP FUNCTION IF EXISTS validate_finding_event();
    DROP FUNCTION IF EXISTS reject_finding_fingerprint_collision();
    DROP TYPE IF EXISTS evaluation_outcome; DROP TYPE IF EXISTS evidence_mode;
    """)
