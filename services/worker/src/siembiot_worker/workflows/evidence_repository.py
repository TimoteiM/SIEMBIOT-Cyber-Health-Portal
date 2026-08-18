"""Persisting evidence, scores and findings.

The tables this writes to are append-only by trigger, which shapes the code: every
write is an insert, and a re-delivered step must be able to run its insert again
without failing. That is why each statement carries ``ON CONFLICT DO NOTHING`` on the
natural key — the first write wins and a repeat is a no-op, which is exactly the
semantics the engine's idempotency keys promise at a higher level.

Findings are the one exception, because they carry lifecycle state across assessments.
They are reconciled: a finding still present keeps its first-seen date, one that has
disappeared becomes resolved rather than being deleted, and one that returns is marked
regressed. Reconciliation happens in ``siembiot_worker.policy.findings`` so that the
rules live with the findings themselves; this module only reads and writes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import Connection, text

from siembiot_worker.policy.catalog import PolicyCatalog, Result
from siembiot_worker.policy.evidence import (
    CheckEvaluation,
    Confidence,
    NormalizedObservation,
    Subject,
    SubjectKind,
)
from siembiot_worker.policy.findings import Finding, FindingState, HistoryEntry, reconcile
from siembiot_worker.policy.scoring import ScoreSnapshot
from siembiot_worker.workflows.assets import (
    AssetCandidate,
    AttributionBasis,
    CandidateSource,
    CandidateState,
)


@dataclass(frozen=True)
class PersistedCounts:
    """What a persistence step actually wrote, so the caller can report it honestly."""

    observations: int = 0
    evaluations: int = 0
    snapshots: int = 0
    findings: int = 0
    resolved_findings: int = 0
    asset_candidates: int = 0


class EvidenceRepository:
    def __init__(
        self, connection: Connection, organization_id: UUID, domain_id: UUID | None = None
    ) -> None:
        self._connection = connection
        self._organization_id = organization_id
        self._domain_id = domain_id

    # -- observations --------------------------------------------------------

    def save_observations(
        self, assessment_id: UUID, observations: tuple[NormalizedObservation, ...]
    ) -> int:
        written = 0
        for observation in observations:
            result = self._connection.execute(
                text(
                    """
                    INSERT INTO normalized_observations (
                        id, organization_id, assessment_id, subject_kind, subject_identifier,
                        authorized_domain_id, observation_type, status, attributes,
                        attribution_confidence, source_confidence, freshness_confidence,
                        confidence_reasons, adapter_id, adapter_version, collected_at,
                        observed_at, from_cache, source_reference, content_hash
                    ) VALUES (
                        :id, :organization_id, :assessment_id, :subject_kind,
                        :subject_identifier, :authorized_domain_id, :observation_type,
                        :status, CAST(:attributes AS jsonb), :attribution, :source,
                        :freshness, :reasons, :adapter_id, :adapter_version, :collected_at,
                        :observed_at, :from_cache, :source_reference, :content_hash
                    )
                    ON CONFLICT (assessment_id, subject_identifier, observation_type)
                    DO NOTHING
                    RETURNING id
                    """
                ),
                {
                    "id": observation.observation_id,
                    "organization_id": self._organization_id,
                    "assessment_id": assessment_id,
                    "subject_kind": str(observation.subject.kind),
                    "subject_identifier": observation.subject.identifier,
                    "authorized_domain_id": observation.subject.authorized_domain_id
                    or self._domain_id,
                    "observation_type": observation.observation_type,
                    "status": str(observation.status),
                    "attributes": json.dumps(observation.attributes),
                    "attribution": observation.confidence.attribution,
                    "source": observation.confidence.source,
                    "freshness": observation.confidence.freshness,
                    "reasons": list(observation.confidence.reasons),
                    "adapter_id": observation.adapter_id,
                    "adapter_version": observation.adapter_version,
                    "collected_at": observation.collected_at,
                    "observed_at": observation.observed_at,
                    "from_cache": observation.from_cache,
                    "source_reference": observation.source_reference,
                    "content_hash": observation.content_hash,
                },
            ).scalar_one_or_none()
            written += 1 if result is not None else 0
        return written

    def load_observations(self, assessment_id: UUID) -> tuple[NormalizedObservation, ...]:
        rows = self._connection.execute(
            text(
                """
                SELECT id, subject_kind, subject_identifier, authorized_domain_id,
                       observation_type, status, attributes, attribution_confidence,
                       source_confidence, freshness_confidence, confidence_reasons,
                       adapter_id, adapter_version, collected_at, observed_at,
                       from_cache, source_reference
                FROM normalized_observations
                WHERE assessment_id = :assessment_id
                ORDER BY observation_type
                """
            ),
            {"assessment_id": assessment_id},
        ).mappings()
        from siembiot_worker.policy.evidence import ObservationStatus

        return tuple(
            NormalizedObservation(
                observation_id=row["id"],
                organization_id=self._organization_id,
                assessment_id=assessment_id,
                subject=Subject(
                    SubjectKind(row["subject_kind"]),
                    row["subject_identifier"],
                    row["authorized_domain_id"],
                ),
                observation_type=row["observation_type"],
                status=ObservationStatus(row["status"]),
                attributes=dict(row["attributes"] or {}),
                confidence=Confidence(
                    float(row["attribution_confidence"]),
                    float(row["source_confidence"]),
                    float(row["freshness_confidence"]),
                    tuple(row["confidence_reasons"] or ()),
                ),
                adapter_id=row["adapter_id"],
                adapter_version=row["adapter_version"],
                collected_at=row["collected_at"],
                observed_at=row["observed_at"],
                from_cache=row["from_cache"],
                source_reference=row["source_reference"],
            )
            for row in rows
        )

    # -- evaluations ---------------------------------------------------------

    def save_evaluations(
        self, assessment_id: UUID, evaluations: tuple[CheckEvaluation, ...]
    ) -> int:
        written = 0
        for evaluation in evaluations:
            result = self._connection.execute(
                text(
                    """
                    INSERT INTO check_evaluations (
                        id, organization_id, assessment_id, check_id, check_version,
                        methodology_version, pillar, subject_kind, subject_identifier,
                        result, score_bearing, weight, severity, reason_code,
                        observation_ids, attribution_confidence, source_confidence,
                        freshness_confidence, evaluated_at
                    ) VALUES (
                        :id, :organization_id, :assessment_id, :check_id, :check_version,
                        :methodology_version, :pillar, :subject_kind, :subject_identifier,
                        :result, :score_bearing, :weight, :severity, :reason_code,
                        :observation_ids, :attribution, :source, :freshness, :evaluated_at
                    )
                    ON CONFLICT (assessment_id, check_id, subject_identifier) DO NOTHING
                    RETURNING id
                    """
                ),
                {
                    "id": evaluation.evaluation_id,
                    "organization_id": self._organization_id,
                    "assessment_id": assessment_id,
                    "check_id": evaluation.check_id,
                    "check_version": evaluation.check_version,
                    "methodology_version": evaluation.methodology_version,
                    "pillar": str(evaluation.pillar),
                    "subject_kind": str(evaluation.subject.kind),
                    "subject_identifier": evaluation.subject.identifier,
                    "result": evaluation.result,
                    "score_bearing": evaluation.score_bearing,
                    "weight": evaluation.weight,
                    "severity": evaluation.severity,
                    "reason_code": evaluation.reason_code,
                    "observation_ids": list(evaluation.observation_ids),
                    "attribution": evaluation.confidence.attribution,
                    "source": evaluation.confidence.source,
                    "freshness": evaluation.confidence.freshness,
                    "evaluated_at": evaluation.evaluated_at,
                },
            ).scalar_one_or_none()
            written += 1 if result is not None else 0
        return written

    # -- score snapshots -----------------------------------------------------

    def save_snapshot(self, snapshot: ScoreSnapshot) -> bool:
        """Write the snapshot. A second write under the same methodology is refused.

        The unique constraint is the point: recomputing under a newer methodology
        creates a distinct projection rather than overwriting what was published.
        """
        result = self._connection.execute(
            text(
                """
                INSERT INTO score_snapshots (
                    id, organization_id, assessment_id, methodology_version, is_projection,
                    policy_digest, evidence_digest, uncapped_score, score, band,
                    coverage_percentage, coverage_sufficient, document, computed_at
                ) VALUES (
                    :id, :organization_id, :assessment_id, :methodology_version,
                    :is_projection, :policy_digest, :evidence_digest, :uncapped_score,
                    :score, :band, :coverage_percentage, :coverage_sufficient,
                    CAST(:document AS jsonb), :computed_at
                )
                ON CONFLICT (assessment_id, methodology_version, is_projection) DO NOTHING
                RETURNING id
                """
            ),
            {
                "id": snapshot.snapshot_id,
                "organization_id": self._organization_id,
                "assessment_id": snapshot.assessment_id,
                "methodology_version": snapshot.methodology_version,
                "is_projection": snapshot.is_projection,
                "policy_digest": snapshot.policy_digest,
                "evidence_digest": snapshot.evidence_digest,
                "uncapped_score": snapshot.uncapped_score,
                "score": snapshot.score,
                "band": snapshot.band,
                "coverage_percentage": snapshot.coverage.percentage,
                "coverage_sufficient": snapshot.coverage.sufficient,
                "document": json.dumps(snapshot.as_dict()),
                "computed_at": snapshot.computed_at,
            },
        ).scalar_one_or_none()
        return result is not None

    # -- findings ------------------------------------------------------------

    def load_findings(self, catalog: PolicyCatalog) -> tuple[Finding, ...]:
        """What this domain already had, for reconciliation against what this run found.

        Scoped to the domain, not the organization. Reconciliation resolves anything the
        current run did not re-observe, and a run only observes the domain it was aimed
        at -- so loading the tenant's whole set meant assessing one domain marked every
        *other* domain's findings resolved. An institution with two domains lost the
        findings for one of them every time the other was assessed, and the report then
        told them they had no weaknesses. tarom.ro's eight findings were resolved
        thirteen milliseconds after a metrorex.ro run finished.

        The organization filter stays alongside it: row-level security already scopes the
        query, and a second explicit predicate is what makes the intent readable rather
        than dependent on a policy defined elsewhere.
        """
        rows = self._connection.execute(
            text(
                """
                SELECT id, fingerprint, check_id, check_version, methodology_version,
                       pillar, subject_kind, subject_identifier, authorized_domain_id,
                       severity, state, reason_code, public_safety_class,
                       attribution_confidence, source_confidence, freshness_confidence,
                       first_seen_at, last_seen_at, resolved_at, evidence_observation_ids
                FROM findings
                WHERE organization_id = :organization_id
                  AND (:domain_id IS NULL OR authorized_domain_id = :domain_id)
                """
            ),
            {"organization_id": self._organization_id, "domain_id": self._domain_id},
        ).mappings()
        del catalog
        return tuple(
            Finding(
                finding_id=row["id"],
                organization_id=self._organization_id,
                fingerprint=row["fingerprint"],
                check_id=row["check_id"],
                check_version=row["check_version"],
                methodology_version=row["methodology_version"],
                pillar=row["pillar"],
                subject=Subject(
                    SubjectKind(row["subject_kind"]),
                    row["subject_identifier"],
                    row["authorized_domain_id"],
                ),
                severity=row["severity"],
                state=FindingState(row["state"]),
                confidence=Confidence(
                    float(row["attribution_confidence"]),
                    float(row["source_confidence"]),
                    float(row["freshness_confidence"]),
                ),
                public_safety_class=row["public_safety_class"],
                first_seen_at=row["first_seen_at"],
                last_seen_at=row["last_seen_at"],
                resolved_at=row["resolved_at"],
                evidence=tuple(row["evidence_observation_ids"] or ()),
                reason_code=row["reason_code"],
            )
            for row in rows
        )

    def save_findings(
        self,
        assessment_id: UUID,
        current: tuple[Finding, ...],
        *,
        catalog: PolicyCatalog,
        observed_at: datetime,
    ) -> tuple[int, int]:
        """Reconcile this run's findings against what the tenant already had.

        Returns the number of open and newly resolved findings. A finding that vanished
        is resolved rather than deleted, because "this stopped being true" is itself
        information the organization needs.
        """
        previous = self.load_findings(catalog)
        merged = reconcile(previous, current, assessment_id=assessment_id, observed_at=observed_at)
        resolved = 0
        for finding in merged:
            self._upsert_finding(finding)
            self._append_history(finding, assessment_id)
            if finding.state is FindingState.RESOLVED:
                resolved += 1
        return len(merged) - resolved, resolved

    def _upsert_finding(self, finding: Finding) -> None:
        self._connection.execute(
            text(
                """
                INSERT INTO findings (
                    id, organization_id, fingerprint, check_id, check_version,
                    methodology_version, pillar, subject_kind, subject_identifier,
                    authorized_domain_id, severity, state, reason_code,
                    public_safety_class, attribution_confidence, source_confidence,
                    freshness_confidence, first_seen_at, last_seen_at, resolved_at,
                    evidence_observation_ids
                ) VALUES (
                    :id, :organization_id, :fingerprint, :check_id, :check_version,
                    :methodology_version, :pillar, :subject_kind, :subject_identifier,
                    :authorized_domain_id, :severity, :state, :reason_code,
                    :public_safety_class, :attribution, :source, :freshness,
                    :first_seen_at, :last_seen_at, :resolved_at, :evidence
                )
                ON CONFLICT (organization_id, fingerprint) DO UPDATE SET
                    state = excluded.state,
                    severity = excluded.severity,
                    check_version = excluded.check_version,
                    methodology_version = excluded.methodology_version,
                    reason_code = excluded.reason_code,
                    last_seen_at = excluded.last_seen_at,
                    resolved_at = excluded.resolved_at,
                    evidence_observation_ids = excluded.evidence_observation_ids,
                    attribution_confidence = excluded.attribution_confidence,
                    source_confidence = excluded.source_confidence,
                    freshness_confidence = excluded.freshness_confidence
                """
            ),
            {
                "id": finding.finding_id,
                "organization_id": self._organization_id,
                "fingerprint": finding.fingerprint,
                "check_id": finding.check_id,
                "check_version": finding.check_version,
                "methodology_version": finding.methodology_version,
                "pillar": finding.pillar,
                "subject_kind": str(finding.subject.kind),
                "subject_identifier": finding.subject.identifier,
                "authorized_domain_id": finding.subject.authorized_domain_id or self._domain_id,
                "severity": finding.severity,
                "state": str(finding.state),
                "reason_code": finding.reason_code,
                "public_safety_class": finding.public_safety_class,
                "attribution": finding.confidence.attribution,
                "source": finding.confidence.source,
                "freshness": finding.confidence.freshness,
                "first_seen_at": finding.first_seen_at,
                "last_seen_at": finding.last_seen_at,
                "resolved_at": finding.resolved_at,
                "evidence": list(finding.evidence),
            },
        )

    def _append_history(self, finding: Finding, assessment_id: UUID) -> None:
        for entry in finding.history:
            self._insert_history_entry(finding.finding_id, entry, assessment_id)

    def _insert_history_entry(
        self, finding_id: UUID, entry: HistoryEntry, assessment_id: UUID
    ) -> None:
        self._connection.execute(
            text(
                """
                INSERT INTO finding_history (
                    id, organization_id, finding_id, assessment_id, from_state,
                    to_state, actor_user_id, occurred_at
                )
                SELECT gen_random_uuid(), :organization_id, :finding_id, :assessment_id,
                       :from_state, :to_state, :actor_user_id, :occurred_at
                WHERE NOT EXISTS (
                    SELECT 1 FROM finding_history
                    WHERE finding_id = :finding_id
                      AND from_state = :from_state
                      AND to_state = :to_state
                      AND occurred_at = :occurred_at
                )
                """
            ),
            {
                "organization_id": self._organization_id,
                "finding_id": finding_id,
                "assessment_id": entry.assessment_id or assessment_id,
                "from_state": entry.from_state,
                "to_state": entry.to_state,
                "actor_user_id": entry.actor_id,
                "occurred_at": entry.at,
            },
        )

    # -- asset candidates ----------------------------------------------------

    def save_asset_candidates(self, domain_id: UUID, candidates: tuple[AssetCandidate, ...]) -> int:
        """Record candidates without disturbing a decision already made about one."""
        written = 0
        for candidate in candidates:
            result = self._connection.execute(
                text(
                    """
                    INSERT INTO asset_candidates (
                        organization_id, domain_id, name, source, attribution_confidence,
                        attribution_basis, shared_hosting, state, first_seen_at,
                        last_seen_at, observation_count
                    ) VALUES (
                        :organization_id, :domain_id, :name, :source, :confidence,
                        :basis, :shared_hosting, :state, :first_seen_at, :last_seen_at,
                        :observation_count
                    )
                    ON CONFLICT (domain_id, name) DO UPDATE SET
                        last_seen_at = GREATEST(
                            asset_candidates.last_seen_at, excluded.last_seen_at
                        ),
                        observation_count = asset_candidates.observation_count
                            + excluded.observation_count,
                        attribution_confidence = GREATEST(
                            asset_candidates.attribution_confidence,
                            excluded.attribution_confidence
                        ),
                        shared_hosting = asset_candidates.shared_hosting
                            OR excluded.shared_hosting
                    RETURNING id
                    """
                ),
                {
                    "organization_id": self._organization_id,
                    "domain_id": domain_id,
                    "name": candidate.name,
                    "source": str(candidate.source),
                    "confidence": candidate.attribution_confidence,
                    "basis": str(candidate.attribution_basis),
                    "shared_hosting": candidate.shared_hosting,
                    "state": str(candidate.state),
                    "first_seen_at": candidate.first_seen_at,
                    "last_seen_at": candidate.last_seen_at,
                    "observation_count": candidate.observation_count,
                },
            ).scalar_one_or_none()
            written += 1 if result is not None else 0
        return written

    def load_asset_candidates(self, domain_id: UUID) -> tuple[AssetCandidate, ...]:
        rows = self._connection.execute(
            text(
                """
                SELECT name, source, attribution_confidence, attribution_basis,
                       shared_hosting, state, first_seen_at, last_seen_at,
                       observation_count
                FROM asset_candidates
                WHERE domain_id = :domain_id
                ORDER BY attribution_confidence DESC, name
                """
            ),
            {"domain_id": domain_id},
        ).mappings()
        return tuple(
            AssetCandidate(
                name=row["name"],
                source=CandidateSource(row["source"]),
                attribution_confidence=float(row["attribution_confidence"]),
                attribution_basis=AttributionBasis(row["attribution_basis"]),
                first_seen_at=row["first_seen_at"],
                last_seen_at=row["last_seen_at"],
                observation_count=row["observation_count"],
                shared_hosting=row["shared_hosting"],
                state=CandidateState(row["state"]),
            )
            for row in rows
        )

    def decide_candidate(
        self,
        domain_id: UUID,
        name: str,
        decision: CandidateState,
        *,
        actor_user_id: UUID,
        reason: str | None = None,
    ) -> bool:
        """Accept or reject a candidate, recording who decided and why."""
        if decision is CandidateState.UNREVIEWED:
            raise ValueError("decision_must_accept_or_reject")
        candidate_id = self._connection.execute(
            text(
                """
                UPDATE asset_candidates SET state = :state
                WHERE domain_id = :domain_id AND name = :name AND state <> :state
                RETURNING id
                """
            ),
            {"state": str(decision), "domain_id": domain_id, "name": name},
        ).scalar_one_or_none()
        if candidate_id is None:
            return False
        self._connection.execute(
            text(
                """
                INSERT INTO asset_candidate_decisions (
                    organization_id, candidate_id, decision, reason, actor_user_id
                ) VALUES (
                    :organization_id, :candidate_id, :decision, :reason, :actor_user_id
                )
                """
            ),
            {
                "organization_id": self._organization_id,
                "candidate_id": candidate_id,
                "decision": str(decision),
                "reason": reason,
                "actor_user_id": actor_user_id,
            },
        )
        return True


def persist_assessment(
    repository: EvidenceRepository,
    *,
    assessment_id: UUID,
    domain_id: UUID,
    catalog: PolicyCatalog,
    observations: tuple[NormalizedObservation, ...],
    evaluations: tuple[CheckEvaluation, ...],
    snapshot: ScoreSnapshot | None,
    findings: tuple[Finding, ...],
    asset_candidates: tuple[AssetCandidate, ...],
    observed_at: datetime,
) -> PersistedCounts:
    """Write one assessment's output. Safe to call twice for the same run."""
    written_observations = repository.save_observations(assessment_id, observations)
    written_evaluations = repository.save_evaluations(assessment_id, evaluations)
    written_snapshots = 1 if snapshot and repository.save_snapshot(snapshot) else 0
    open_findings, resolved = repository.save_findings(
        assessment_id, findings, catalog=catalog, observed_at=observed_at
    )
    written_candidates = repository.save_asset_candidates(domain_id, asset_candidates)
    return PersistedCounts(
        observations=written_observations,
        evaluations=written_evaluations,
        snapshots=written_snapshots,
        findings=open_findings,
        resolved_findings=resolved,
        asset_candidates=written_candidates,
    )


def score_bearing_results() -> frozenset[str]:
    """Exposed so a caller can assert the database check matches the policy engine."""
    return frozenset({str(Result.PASS), str(Result.FAIL), str(Result.WARNING)})
