"""Persisting a real assessment and reading it back.

The point of this file is the round trip: a run's evidence, score and findings go to
the database and come back unchanged, a repeated write is harmless, and a second
assessment reconciles against the first instead of duplicating it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import psycopg
import pytest
from siembiot_worker.policy.catalog import Result, load_catalog
from siembiot_worker.policy.evidence import (
    CheckEvaluation,
    Confidence,
    NormalizedObservation,
    ObservationStatus,
    Subject,
    SubjectKind,
)
from siembiot_worker.policy.findings import FindingState, derive_findings
from siembiot_worker.policy.scoring import ScoreSnapshot, compute_score
from siembiot_worker.workflows.assets import (
    AssetCandidate,
    AttributionBasis,
    CandidateSource,
    CandidateState,
)
from siembiot_worker.workflows.evidence_repository import (
    EvidenceRepository,
    PersistedCounts,
    persist_assessment,
)
from sqlalchemy import Connection, create_engine

CATALOG = load_catalog()
NOW = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
LATER = NOW + timedelta(days=7)
HOST = "example.test"
SUBJECT = Subject(SubjectKind.DOMAIN, HOST)


@dataclass(frozen=True)
class Seeded:
    """One tenant with a verified domain and the assessments to write against."""

    organization_id: UUID
    user_id: UUID
    domain_id: UUID
    assessments: tuple[UUID, ...]


def seed(owner_url: str, *, assessments: int = 1) -> Seeded:
    organization_id, user_id = str(uuid4()), str(uuid4())
    domain_id = str(uuid4())
    assessment_ids = [str(uuid4()) for _ in range(assessments)]
    with psycopg.connect(owner_url) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Evidence user')",
            (user_id, user_id, f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Tenant', %s, %s)",
            (organization_id, f"ev-{organization_id[:12]}", user_id),
        )
        owner.execute(
            "INSERT INTO memberships (organization_id, user_id, role, status) "
            "VALUES (%s, %s, 'organization_owner', 'active')",
            (organization_id, user_id),
        )
        owner.execute(
            "INSERT INTO methodology_versions (version, policy_digest, notice) "
            "VALUES (%s, %s, 'test') ON CONFLICT (version) DO NOTHING",
            (CATALOG.methodology.version, CATALOG.digest),
        )
        owner.execute(
            "INSERT INTO domains (id, organization_id, canonical_name, unicode_display, "
            "registrable_domain, ownership_state, created_by_user_id) "
            "VALUES (%s, %s, %s, %s, %s, 'verified', %s)",
            (domain_id, organization_id, HOST, HOST, HOST, user_id),
        )
        for assessment_id in assessment_ids:
            owner.execute(
                "INSERT INTO assessments (id, organization_id, domain_id, "
                "methodology_version, state) VALUES (%s, %s, %s, %s, 'collecting')",
                (assessment_id, organization_id, domain_id, CATALOG.methodology.version),
            )
    return Seeded(
        organization_id=UUID(organization_id),
        user_id=UUID(user_id),
        domain_id=UUID(domain_id),
        assessments=tuple(UUID(item) for item in assessment_ids),
    )


def repository(url: str, fixture: Seeded) -> tuple[EvidenceRepository, Connection]:
    engine = create_engine(url.replace("postgresql://", "postgresql+psycopg://"))
    connection = engine.connect()
    return (
        EvidenceRepository(connection, fixture.organization_id, fixture.domain_id),
        connection,
    )


def observation(
    assessment_id: UUID,
    observation_type: str,
    status: ObservationStatus = ObservationStatus.OBSERVED,
    attributes: dict[str, object] | None = None,
    organization_id: UUID | None = None,
) -> NormalizedObservation:
    return NormalizedObservation(
        observation_id=uuid4(),
        organization_id=organization_id or uuid4(),
        assessment_id=assessment_id,
        subject=SUBJECT,
        observation_type=observation_type,
        status=status,
        attributes=attributes or {},
        confidence=Confidence(1.0, 1.0, 1.0, ("evidence_aged",)),
        adapter_id="dns_resilience",
        adapter_version="1.0.0",
        collected_at=NOW,
    )


def evaluation(assessment_id: UUID, check_id: str, result: Result) -> CheckEvaluation:
    check = CATALOG.by_id(check_id)
    return CheckEvaluation(
        evaluation_id=uuid4(),
        organization_id=uuid4(),
        assessment_id=assessment_id,
        check_id=check_id,
        check_version=check.version,
        methodology_version=CATALOG.methodology.version,
        pillar=check.pillar,
        subject=SUBJECT,
        result=str(result),
        weight=check.weight,
        severity=str(check.severity),
        confidence=Confidence(1.0, 1.0, 1.0),
        observation_ids=(),
        evaluated_at=NOW,
    )


def full_run(
    assessment_id: UUID, *, dnssec: str = "unsigned"
) -> tuple[tuple[NormalizedObservation, ...], tuple[CheckEvaluation, ...], ScoreSnapshot]:
    observations = (
        observation(assessment_id, "dns.dnssec", attributes={"state": dnssec}),
        observation(assessment_id, "dns.caa", ObservationStatus.ABSENT),
    )
    evaluations = tuple(
        evaluation(
            assessment_id,
            check.check_id,
            Result.FAIL
            if check.check_id == "A.dnssec_enabled" and dnssec == "unsigned"
            else Result.PASS,
        )
        for check in CATALOG.checks
    )
    snapshot = compute_score(
        CATALOG,
        evaluations,
        observations,
        snapshot_id=uuid4(),
        organization_id=uuid4(),
        assessment_id=assessment_id,
        computed_at=NOW,
    )
    return observations, evaluations, snapshot


# -- round trip --------------------------------------------------------------


def test_an_assessment_round_trips_through_the_database(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed(postgres_database["owner_url"])
    assessment = fixture.assessments[0]
    store, connection = repository(postgres_database["owner_url"], fixture)
    try:
        observations, evaluations, snapshot = full_run(assessment)
        findings = derive_findings(
            CATALOG,
            evaluations,
            organization_id=fixture.organization_id,
            assessment_id=assessment,
            observed_at=NOW,
        )
        counts = persist_assessment(
            store,
            assessment_id=assessment,
            domain_id=fixture.domain_id,
            catalog=CATALOG,
            observations=observations,
            evaluations=evaluations,
            snapshot=snapshot,
            findings=findings,
            asset_candidates=(),
            observed_at=NOW,
        )
        connection.commit()

        assert counts.observations == len(observations)
        assert counts.evaluations == len(evaluations)
        assert counts.snapshots == 1
        assert counts.findings == len(findings)

        loaded = store.load_observations(assessment)
        assert {item.observation_type for item in loaded} == {"dns.dnssec", "dns.caa"}
        dnssec = next(item for item in loaded if item.observation_type == "dns.dnssec")
        assert dnssec.attributes == {"state": "unsigned"}
        assert dnssec.confidence.reasons == ("evidence_aged",)
    finally:
        connection.close()


def test_writing_the_same_assessment_twice_is_harmless(
    postgres_database: dict[str, str],
) -> None:
    """A redelivered step must be able to run its write again."""
    fixture = seed(postgres_database["owner_url"])
    assessment = fixture.assessments[0]
    store, connection = repository(postgres_database["owner_url"], fixture)
    try:
        observations, evaluations, snapshot = full_run(assessment)

        def write() -> PersistedCounts:
            return persist_assessment(
                store,
                assessment_id=assessment,
                domain_id=fixture.domain_id,
                catalog=CATALOG,
                observations=observations,
                evaluations=evaluations,
                snapshot=snapshot,
                findings=(),
                asset_candidates=(),
                observed_at=NOW,
            )

        first = write()
        connection.commit()
        second = write()
        connection.commit()

        assert first.observations > 0
        assert second.observations == 0  # nothing new to write
        assert second.snapshots == 0
        assert len(store.load_observations(assessment)) == len(observations)
    finally:
        connection.close()


def test_a_second_snapshot_under_the_same_methodology_is_refused(
    postgres_database: dict[str, str],
) -> None:
    """Recomputing must create a projection, never overwrite what was published."""
    fixture = seed(postgres_database["owner_url"])
    assessment = fixture.assessments[0]
    store, connection = repository(postgres_database["owner_url"], fixture)
    try:
        _, _, snapshot = full_run(assessment)
        assert store.save_snapshot(snapshot) is True
        connection.commit()
        assert store.save_snapshot(snapshot) is False
        connection.commit()
    finally:
        connection.close()


# -- findings across assessments ---------------------------------------------


def test_a_finding_that_persists_keeps_its_first_seen_date(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed(postgres_database["owner_url"], assessments=2)
    first_run, second_run = fixture.assessments
    store, connection = repository(postgres_database["owner_url"], fixture)
    organization = fixture.organization_id
    try:
        for assessment, moment in ((first_run, NOW), (second_run, LATER)):
            _, evaluations, _ = full_run(assessment)
            findings = derive_findings(
                CATALOG,
                evaluations,
                organization_id=organization,
                assessment_id=assessment,
                observed_at=moment,
            )
            store.save_findings(assessment, findings, catalog=CATALOG, observed_at=moment)
            connection.commit()

        stored = store.load_findings(CATALOG)
        dnssec = next(item for item in stored if item.check_id == "A.dnssec_enabled")
        assert dnssec.first_seen_at == NOW
        assert dnssec.last_seen_at == LATER
        assert dnssec.state is FindingState.OPEN
    finally:
        connection.close()


def test_a_finding_that_disappears_is_resolved_rather_than_deleted(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed(postgres_database["owner_url"], assessments=2)
    first_run, second_run = fixture.assessments
    store, connection = repository(postgres_database["owner_url"], fixture)
    organization = fixture.organization_id
    try:
        _, failing, _ = full_run(first_run, dnssec="unsigned")
        store.save_findings(
            first_run,
            derive_findings(
                CATALOG,
                failing,
                organization_id=organization,
                assessment_id=first_run,
                observed_at=NOW,
            ),
            catalog=CATALOG,
            observed_at=NOW,
        )
        connection.commit()

        # The next run finds nothing wrong at all.
        store.save_findings(second_run, (), catalog=CATALOG, observed_at=LATER)
        connection.commit()

        stored = store.load_findings(CATALOG)
        assert stored, "the finding must still exist"
        assert all(item.state is FindingState.RESOLVED for item in stored)
        assert all(item.resolved_at == LATER for item in stored)
    finally:
        connection.close()


def test_finding_history_records_the_transition(postgres_database: dict[str, str]) -> None:
    fixture = seed(postgres_database["owner_url"], assessments=2)
    first_run, second_run = fixture.assessments
    store, connection = repository(postgres_database["owner_url"], fixture)
    organization = fixture.organization_id
    try:
        _, failing, _ = full_run(first_run)
        store.save_findings(
            first_run,
            derive_findings(
                CATALOG,
                failing,
                organization_id=organization,
                assessment_id=first_run,
                observed_at=NOW,
            ),
            catalog=CATALOG,
            observed_at=NOW,
        )
        connection.commit()
        store.save_findings(second_run, (), catalog=CATALOG, observed_at=LATER)
        connection.commit()
    finally:
        connection.close()

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        transitions = owner.execute(
            "SELECT from_state, to_state FROM finding_history "
            "WHERE organization_id = %s ORDER BY occurred_at",
            (str(fixture.organization_id),),
        ).fetchall()
        assert ("absent", "open") in transitions
        assert ("open", "resolved") in transitions


# -- asset candidates --------------------------------------------------------


def candidate(name: str, confidence: float = 0.9) -> AssetCandidate:
    return AssetCandidate(
        name=name,
        source=CandidateSource.CERTIFICATE_TRANSPARENCY,
        attribution_confidence=confidence,
        attribution_basis=AttributionBasis.SUBDOMAIN,
        first_seen_at=NOW,
        last_seen_at=NOW,
    )


def test_asset_candidates_round_trip_unreviewed(postgres_database: dict[str, str]) -> None:
    fixture = seed(postgres_database["owner_url"])
    domain = fixture.domain_id
    store, connection = repository(postgres_database["owner_url"], fixture)
    try:
        store.save_asset_candidates(domain, (candidate("www.example.test"),))
        connection.commit()
        loaded = store.load_asset_candidates(domain)
        assert len(loaded) == 1
        assert loaded[0].needs_review is True
        assert loaded[0].in_scope is False
    finally:
        connection.close()


def test_re_observing_a_candidate_accumulates_rather_than_duplicates(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed(postgres_database["owner_url"])
    domain = fixture.domain_id
    store, connection = repository(postgres_database["owner_url"], fixture)
    try:
        store.save_asset_candidates(domain, (candidate("www.example.test", 0.5),))
        connection.commit()
        store.save_asset_candidates(domain, (candidate("www.example.test", 0.9),))
        connection.commit()
        loaded = store.load_asset_candidates(domain)
        assert len(loaded) == 1
        assert loaded[0].observation_count == 2
        assert loaded[0].attribution_confidence == 0.9
    finally:
        connection.close()


def test_accepting_a_candidate_records_the_decision(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed(postgres_database["owner_url"])
    domain = fixture.domain_id
    actor = fixture.user_id
    store, connection = repository(postgres_database["owner_url"], fixture)
    try:
        store.save_asset_candidates(domain, (candidate("www.example.test"),))
        assert (
            store.decide_candidate(
                domain,
                "www.example.test",
                CandidateState.ACCEPTED,
                actor_user_id=actor,
                reason="Confirmed ours",
            )
            is True
        )
        connection.commit()
        assert store.load_asset_candidates(domain)[0].in_scope is True
    finally:
        connection.close()

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        decisions = owner.execute(
            "SELECT decision, reason, actor_user_id::text FROM asset_candidate_decisions "
            "WHERE organization_id = %s",
            (str(fixture.organization_id),),
        ).fetchall()
        assert decisions == [("accepted", "Confirmed ours", str(actor))]


def test_repeating_a_decision_writes_no_second_record(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed(postgres_database["owner_url"])
    domain = fixture.domain_id
    actor = fixture.user_id
    store, connection = repository(postgres_database["owner_url"], fixture)
    try:
        store.save_asset_candidates(domain, (candidate("www.example.test"),))
        store.decide_candidate(
            domain, "www.example.test", CandidateState.ACCEPTED, actor_user_id=actor
        )
        connection.commit()
        assert (
            store.decide_candidate(
                domain, "www.example.test", CandidateState.ACCEPTED, actor_user_id=actor
            )
            is False
        )
        connection.commit()
    finally:
        connection.close()


def test_a_decision_cannot_return_a_candidate_to_unreviewed(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed(postgres_database["owner_url"])
    domain = fixture.domain_id
    store, connection = repository(postgres_database["owner_url"], fixture)
    try:
        with pytest.raises(ValueError, match="decision_must_accept_or_reject"):
            store.decide_candidate(
                domain,
                "www.example.test",
                CandidateState.UNREVIEWED,
                actor_user_id=fixture.user_id,
            )
    finally:
        connection.close()


# -- the score itself --------------------------------------------------------


def test_the_persisted_snapshot_matches_the_computed_one(
    postgres_database: dict[str, str],
) -> None:
    fixture = seed(postgres_database["owner_url"])
    assessment = fixture.assessments[0]
    store, connection = repository(postgres_database["owner_url"], fixture)
    try:
        _, _, snapshot = full_run(assessment)
        store.save_snapshot(snapshot)
        connection.commit()
    finally:
        connection.close()

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        row = owner.execute(
            "SELECT score, band, policy_digest, coverage_sufficient "
            "FROM score_snapshots WHERE assessment_id = %s",
            (str(assessment),),
        ).fetchone()
        assert row is not None
        assert float(row[0]) == snapshot.score
        assert row[1] == snapshot.band
        assert row[2] == CATALOG.digest
        assert row[3] is snapshot.coverage.sufficient


def test_assessing_one_domain_does_not_resolve_another_domains_findings(
    postgres_database: dict[str, str],
) -> None:
    """The bug that told an institution it had no weaknesses.

    Reconciliation resolves whatever the current run did not re-observe, and a run only
    observes the domain it was aimed at. Loading the tenant's whole set therefore meant
    assessing one domain marked every *other* domain's findings resolved -- silently, and
    with the report then reading "no weaknesses identified" for a domain that had eight.

    Observed in the real database before it was found in the code: tarom.ro's eight
    findings were resolved thirteen milliseconds after a metrorex.ro run completed, both
    domains belonging to one organization.
    """
    fixture = seed(postgres_database["owner_url"], assessments=2)
    first_run, second_run = fixture.assessments

    sibling_id = str(uuid4())
    sibling_host = f"sibling-{sibling_id[:8]}.example.test"
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        owner.execute(
            "INSERT INTO domains (id, organization_id, canonical_name, unicode_display, "
            "registrable_domain, ownership_state, created_by_user_id) "
            "VALUES (%s, %s, %s, %s, %s, 'verified', %s)",
            (
                sibling_id,
                str(fixture.organization_id),
                sibling_host,
                sibling_host,
                sibling_host,
                str(fixture.user_id),
            ),
        )

    store, connection = repository(postgres_database["owner_url"], fixture)
    try:
        _, failing, _ = full_run(first_run, dnssec="unsigned")
        store.save_findings(
            first_run,
            derive_findings(
                CATALOG,
                failing,
                organization_id=fixture.organization_id,
                assessment_id=first_run,
                observed_at=NOW,
            ),
            catalog=CATALOG,
            observed_at=NOW,
        )
        connection.commit()
        assert store.load_findings(CATALOG), "the first domain must have findings to lose"

        # A run for the sibling domain, which finds nothing of its own.
        sibling_store = EvidenceRepository(connection, fixture.organization_id, UUID(sibling_id))
        sibling_store.save_findings(second_run, (), catalog=CATALOG, observed_at=LATER)
        connection.commit()

        surviving = store.load_findings(CATALOG)
        assert surviving, "the first domain's findings disappeared entirely"
        assert all(item.state is FindingState.OPEN for item in surviving), (
            "a run for a sibling domain resolved this domain's findings"
        )
    finally:
        connection.close()
