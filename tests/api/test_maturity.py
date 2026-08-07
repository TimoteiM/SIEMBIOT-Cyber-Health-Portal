"""What an organisation says about itself, and what that may and may not turn into.

A self-assessment questionnaire is the easiest place in a product like this to
manufacture a reassuring number. Most of this file exists to prove that it cannot:
that "I do not know" never reads as "no", that a self-declared figure is never blended
with a measured one, and that where the platform can see the same subject, a claim it
disagrees with is reported as a disagreement rather than smoothed over.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "api" / "src"))

from siembiot.config import Settings  # noqa: E402
from siembiot.identity import Principal  # noqa: E402
from siembiot.main import create_app  # noqa: E402
from siembiot.maturity import (  # noqa: E402
    CLAIM_LEVEL,
    MAX_LEVEL,
    corroborate,
    load_questionnaire,
    observed_result,
    score,
)

BASE_URL = "https://portal.example.test"
METHODOLOGY = "1.0.0"
DIGEST = "f" * 64

#: A question the platform can also look at for itself.
CORROBORATED_QUESTION = "hygiene_training.email_authentication"
CORROBORATED_CHECK = "B.dmarc_enforced"


class NullIdentityResolver:
    def resolve(self, request: object) -> None:  # pragma: no cover - never consulted
        return None


@dataclass(frozen=True)
class Tenant:
    organization_id: UUID
    user_id: UUID
    domain_id: UUID


def seed(owner_url: str, *, role: str = "organization_owner") -> Tenant:
    organization_id, user_id, domain_id = uuid4(), uuid4(), uuid4()
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Ana Popescu')",
            (str(user_id), str(user_id), f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, 'Tenant', %s, %s)",
            (str(organization_id), f"mt-{organization_id.hex[:12]}", str(user_id)),
        )
        owner.execute(
            "INSERT INTO memberships (organization_id, user_id, role, status) "
            "VALUES (%s, %s, %s, 'active')",
            (str(organization_id), str(user_id), role),
        )
        owner.execute(
            "INSERT INTO methodology_versions (version, policy_digest, notice) "
            "VALUES (%s, %s, 'test') ON CONFLICT (version) DO NOTHING",
            (METHODOLOGY, DIGEST),
        )
        owner.execute(
            "INSERT INTO domains (id, organization_id, canonical_name, unicode_display, "
            "registrable_domain, ownership_state, created_by_user_id) "
            "VALUES (%s, %s, 'mat.test', 'mat.test', 'mat.test', 'verified', %s)",
            (str(domain_id), str(organization_id), str(user_id)),
        )
    return Tenant(organization_id, user_id, domain_id)


def add_evaluation(
    owner_url: str,
    tenant: Tenant,
    *,
    check_id: str = CORROBORATED_CHECK,
    result: str = "fail",
    subject: str = "mat.test",
    age: timedelta = timedelta(0),
) -> None:
    """Record what the technical assessment saw for one check."""
    assessment_id, evaluation_id = uuid4(), uuid4()
    evaluated_at = datetime.now(UTC) - age
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO assessments (id, organization_id, domain_id, methodology_version, "
            "state, completed_at) VALUES (%s, %s, %s, %s, 'completed', %s)",
            (
                str(assessment_id),
                str(tenant.organization_id),
                str(tenant.domain_id),
                METHODOLOGY,
                evaluated_at,
            ),
        )
        owner.execute(
            "INSERT INTO check_evaluations (id, organization_id, assessment_id, check_id, "
            "check_version, methodology_version, pillar, subject_kind, subject_identifier, "
            "result, score_bearing, weight, severity, attribution_confidence, "
            "source_confidence, freshness_confidence, evaluated_at) "
            "VALUES (%s, %s, %s, %s, '1.0.0', %s, 'email', 'domain', %s, %s, %s, 10, "
            "'high', 1.00, 1.00, 1.00, %s)",
            (
                str(evaluation_id),
                str(tenant.organization_id),
                str(assessment_id),
                check_id,
                METHODOLOGY,
                subject,
                result,
                result in {"pass", "fail", "warning"},
                evaluated_at,
            ),
        )


def client_for(postgres_database: dict[str, str], tenant: Tenant) -> TestClient:
    from siembiot.auth import current_principal, require_trusted_origin

    app = create_app(
        settings=Settings(
            environment="test",
            public_base_url=BASE_URL,
            app_database_url=postgres_database["app_url"].replace(
                "postgresql://", "postgresql+psycopg://"
            ),
        ),
        identity_resolver=NullIdentityResolver(),
    )
    principal = Principal(
        user_id=tenant.user_id, email="ana@example.test", display_name="Ana Popescu"
    )
    app.dependency_overrides[current_principal] = lambda: principal
    app.dependency_overrides[require_trusted_origin] = lambda: principal
    return TestClient(app, base_url=BASE_URL)


def answer_url(tenant: Tenant, question_id: str) -> str:
    return f"/api/v1/organizations/{tenant.organization_id}/maturity/answers/{question_id}"


def read(client: TestClient, tenant: Tenant) -> dict[str, Any]:
    body: dict[str, Any] = client.get(
        f"/api/v1/organizations/{tenant.organization_id}/maturity"
    ).json()
    return body


def question_in(body: dict[str, Any], question_id: str) -> dict[str, Any]:
    for section in body["sections"]:
        for question in section["questions"]:
            if question["question_id"] == question_id:
                return dict(question)
    raise AssertionError(f"{question_id} is not in the questionnaire")


def answer_everything(client: TestClient, tenant: Tenant, answer: str) -> None:
    for question in load_questionnaire().questions:
        client.put(answer_url(tenant, question.question_id), json={"answer": answer})


# -- not knowing is not the same as not having -------------------------------


def test_unknown_reduces_completeness_rather_than_scoring_zero() -> None:
    """The property the whole scale rests on.

    An organisation that does not know whether its backups restore is in a worse
    position than one that knows they do not -- but it is not making the same
    statement, and one number cannot say both. Scoring "unknown" as zero would let a
    blank form read as a catalogue of failures.
    """
    questionnaire = load_questionnaire()
    first = questionnaire.questions[0].question_id

    unknown = score(questionnaire, {first: "unknown"})
    absent = score(questionnaire, {first: "absent"})

    assert unknown.answered_count == 0
    assert absent.answered_count == 1
    # The one absent answer scores zero and drags the average down; the unknown one
    # leaves the average alone and shows up as missing instead.
    assert unknown.completeness_percentage < 100.0
    assert absent.sections[0].percentage == 0.0
    assert unknown.sections[0].percentage is None


def test_an_unanswered_question_and_an_explicit_unknown_are_treated_alike() -> None:
    """A form left blank is not a claim, and neither is saying so out loud."""
    questionnaire = load_questionnaire()
    first = questionnaire.questions[0].question_id

    blank = score(questionnaire, {})
    stated = score(questionnaire, {first: "unknown"})

    assert blank.completeness_percentage == stated.completeness_percentage
    assert blank.self_declared_percentage == stated.self_declared_percentage is None


def test_not_applicable_leaves_the_denominator_entirely() -> None:
    """Different from unknown: a question that does not apply is not missing evidence.

    Counting it as unanswered would push an organisation below the completeness floor
    for questions it was right not to answer.
    """
    questionnaire = load_questionnaire()
    first = questionnaire.questions[0].question_id
    rest = {
        question.question_id: "documented"
        for question in questionnaire.questions
        if question.question_id != first
    }

    excluded = score(questionnaire, {**rest, first: "not_applicable"})
    missing = score(questionnaire, {**rest, first: "unknown"})

    assert excluded.not_applicable_count == 1
    # Answering everything that applies is complete, even with a question set aside.
    assert excluded.completeness_percentage == 100.0
    assert missing.completeness_percentage < 100.0


def test_everything_marked_not_applicable_yields_no_score_rather_than_a_perfect_one() -> None:
    questionnaire = load_questionnaire()
    result = score(
        questionnaire,
        {question.question_id: "not_applicable" for question in questionnaire.questions},
    )
    assert result.self_declared_percentage is None
    assert result.comparable is False
    assert result.incomparable_reason == "nothing_applicable"


# -- withholding rather than caveating ---------------------------------------


def test_a_score_is_withheld_below_the_completeness_floor() -> None:
    """A caveat beside a number loses to the number.

    Mirrors the technical side, where insufficient coverage removes the band rather
    than annotating it.
    """
    questionnaire = load_questionnaire()
    one = questionnaire.questions[0].question_id

    sparse = score(questionnaire, {one: "verified"})
    assert sparse.completeness_percentage < questionnaire.minimum_completeness_percentage
    assert sparse.comparable is False
    assert sparse.incomparable_reason == "insufficient_completeness"
    assert sparse.self_declared_percentage is None


def test_a_fully_answered_questionnaire_scores() -> None:
    questionnaire = load_questionnaire()
    answers = {question.question_id: "verified" for question in questionnaire.questions}
    result = score(questionnaire, answers)

    assert result.comparable is True
    assert result.self_declared_percentage == 100.0
    assert result.completeness_percentage == 100.0


def test_the_score_is_weighted_by_question() -> None:
    """ "Have you tested a restore" and "do you keep a supplier list" are not equal."""
    questionnaire = load_questionnaire()
    weights = {question.weight for question in questionnaire.questions}
    assert len(weights) > 1, "a weighted score with uniform weights is an unweighted score"

    heavy = max(questionnaire.questions, key=lambda item: item.weight)
    light = min(questionnaire.questions, key=lambda item: item.weight)
    base = {question.question_id: "verified" for question in questionnaire.questions}

    lost_heavy = score(questionnaire, {**base, heavy.question_id: "absent"})
    lost_light = score(questionnaire, {**base, light.question_id: "absent"})
    assert lost_heavy.self_declared_percentage is not None
    assert lost_light.self_declared_percentage is not None
    assert lost_heavy.self_declared_percentage < lost_light.self_declared_percentage


def test_scoring_is_deterministic() -> None:
    questionnaire = load_questionnaire()
    answers = {question.question_id: "documented" for question in questionnaire.questions}
    assert score(questionnaire, answers) == score(questionnaire, answers)


# -- declaration against observation -----------------------------------------


@pytest.mark.parametrize(
    ("answer", "observation", "expected"),
    [
        ("verified", "problem", "contradicted"),
        ("documented", "problem", "contradicted"),
        ("informal", "problem", "consistent"),
        ("absent", "problem", "consistent"),
        ("verified", "pass", "consistent"),
        ("absent", "pass", "understated"),
        ("informal", "pass", "understated"),
        ("verified", "not_assessed", "not_observed"),
        ("verified", "inconclusive", "not_observed"),
        ("unknown", "pass", "not_observed"),
        ("not_applicable", "problem", "not_observed"),
    ],
)
def test_corroboration_reads_every_pairing_the_way_it_should(
    answer: str, observation: str, expected: str
) -> None:
    questionnaire = load_questionnaire()
    assert corroborate(questionnaire, answer, observation) == expected  # type: ignore[arg-type]


def test_an_inconclusive_check_never_reads_as_agreement() -> None:
    """The failure that would make this field worse than absent.

    A check that could not run is not a check that succeeded, and reporting it as
    agreement would turn "we could not look" into "we confirmed your claim".
    """
    questionnaire = load_questionnaire()
    for answer in ("absent", "informal", "documented", "verified"):
        assert corroborate(questionnaire, answer, "inconclusive") == "not_observed"
        assert corroborate(questionnaire, answer, "not_assessed") == "not_observed"


def test_the_worst_result_across_subjects_wins() -> None:
    """One badly configured domain is not averaged away by the well configured ones.

    The claim is about the organisation's domains, and it is false if it is false for
    one of them -- which will be the one that gets used.
    """
    assert observed_result(["pass", "pass", "fail"]) == "problem"
    assert observed_result(["pass", "pass"]) == "pass"
    assert observed_result(["pass", "unknown"]) == "pass"
    assert observed_result(["unknown", "error"]) == "inconclusive"
    assert observed_result([]) == "not_assessed"


def test_a_claim_the_assessment_disagrees_with_is_reported_as_a_disagreement(
    postgres_database: dict[str, str],
) -> None:
    """The sentence this feature exists to produce."""
    tenant = seed(postgres_database["owner_url"])
    add_evaluation(postgres_database["owner_url"], tenant, result="fail")

    with client_for(postgres_database, tenant) as client:
        body = client.put(
            answer_url(tenant, CORROBORATED_QUESTION), json={"answer": "verified"}
        ).json()

    question = question_in(body, CORROBORATED_QUESTION)
    assert question["observed"] == "problem"
    assert question["corroboration"] == "contradicted"
    assert body["contradicted_count"] == 1


def test_a_claim_the_assessment_agrees_with_is_reported_as_agreement(
    postgres_database: dict[str, str],
) -> None:
    tenant = seed(postgres_database["owner_url"])
    add_evaluation(postgres_database["owner_url"], tenant, result="pass")

    with client_for(postgres_database, tenant) as client:
        body = client.put(
            answer_url(tenant, CORROBORATED_QUESTION), json={"answer": "documented"}
        ).json()

    question = question_in(body, CORROBORATED_QUESTION)
    assert question["corroboration"] == "consistent"
    assert body["contradicted_count"] == 0


def test_a_stale_evaluation_stops_corroborating(postgres_database: dict[str, str]) -> None:
    """Two missed quarterly runs means assessment has stopped, not that it ran a while ago.

    A pass from a year ago quietly confirming today's claim would be the worst reading
    available: agreement resting on evidence that no longer describes anything.
    """
    tenant = seed(postgres_database["owner_url"])
    add_evaluation(postgres_database["owner_url"], tenant, result="pass", age=timedelta(days=200))

    with client_for(postgres_database, tenant) as client:
        body = client.put(
            answer_url(tenant, CORROBORATED_QUESTION), json={"answer": "verified"}
        ).json()

    question = question_in(body, CORROBORATED_QUESTION)
    assert question["observed"] == "not_assessed"
    assert question["corroboration"] == "not_observed"


def test_an_answer_never_changes_what_was_observed(postgres_database: dict[str, str]) -> None:
    """Nothing typed into the questionnaire touches the evidence."""
    tenant = seed(postgres_database["owner_url"])
    add_evaluation(postgres_database["owner_url"], tenant, result="fail")

    with client_for(postgres_database, tenant) as client:
        client.put(answer_url(tenant, CORROBORATED_QUESTION), json={"answer": "verified"})

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        row = owner.execute(
            "SELECT result FROM check_evaluations WHERE organization_id = %s",
            (str(tenant.organization_id),),
        ).fetchone()
    assert row is not None and row[0] == "fail"


# -- the two scores stay apart -----------------------------------------------


def test_the_response_carries_no_combined_figure(postgres_database: dict[str, str]) -> None:
    """The whole point of the separation, checked at the contract rather than in prose.

    A field averaging a self-report with a measurement would look like a summary and
    mean nothing, and it would let a confident declaration cover a measured weakness.
    """
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        body = read(client, tenant)

    forbidden = {"score", "band", "overall_score", "combined_score", "total_percentage"}
    assert forbidden.isdisjoint(body)
    # The one percentage it does carry says in its own name where it came from.
    assert "self_declared_percentage" in body


def test_the_self_declared_score_gets_no_band(postgres_database: dict[str, str]) -> None:
    """A band is earned by observation.

    Giving a self-report the same five labels as a measured score invites reading them
    as the same kind of statement, and from there to averaging them is one short step.
    """
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        answer_everything(client, tenant, "verified")
        body = read(client, tenant)

    assert body["self_declared_percentage"] == 100.0
    assert "band" not in body


def test_the_notice_says_these_are_declarations(postgres_database: dict[str, str]) -> None:
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        body = read(client, tenant)

    assert "declara" in body["notice_ro"].lower()
    assert "declarations" in body["notice_en"].lower()
    assert body["review_status"] == "draft"


# -- the record of what was said ---------------------------------------------


def test_changing_an_answer_is_recorded(postgres_database: dict[str, str]) -> None:
    """An organisation that answered one way before an incident and another way after."""
    tenant = seed(postgres_database["owner_url"])
    question_id = "continuity.restore_tested"

    with client_for(postgres_database, tenant) as client:
        client.put(answer_url(tenant, question_id), json={"answer": "absent"})
        client.put(answer_url(tenant, question_id), json={"answer": "verified"})

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        rows = owner.execute(
            "SELECT from_answer, to_answer FROM maturity_response_history "
            "WHERE organization_id = %s ORDER BY occurred_at",
            (str(tenant.organization_id),),
        ).fetchall()

    assert rows == [(None, "absent"), ("absent", "verified")]


def test_history_cannot_be_rewritten(postgres_database: dict[str, str]) -> None:
    tenant = seed(postgres_database["owner_url"])
    question_id = "continuity.restore_tested"

    with client_for(postgres_database, tenant) as client:
        client.put(answer_url(tenant, question_id), json={"answer": "absent"})

    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="append-only"):
            owner.execute(
                "UPDATE maturity_response_history SET to_answer = 'verified' "
                "WHERE organization_id = %s",
                (str(tenant.organization_id),),
            )


def test_re_answering_the_same_way_writes_no_history(postgres_database: dict[str, str]) -> None:
    """Otherwise the transitions worth reconstructing are buried in note edits."""
    tenant = seed(postgres_database["owner_url"])
    question_id = "continuity.restore_tested"

    with client_for(postgres_database, tenant) as client:
        client.put(answer_url(tenant, question_id), json={"answer": "documented"})
        client.put(
            answer_url(tenant, question_id), json={"answer": "documented", "note": "revised"}
        )

    with psycopg.connect(postgres_database["owner_url"]) as owner:
        count = owner.execute(
            "SELECT count(*) FROM maturity_response_history WHERE organization_id = %s",
            (str(tenant.organization_id),),
        ).fetchone()
    assert count is not None and count[0] == 1


def test_citing_a_document_is_stored_but_promotes_nothing(
    postgres_database: dict[str, str],
) -> None:
    """The platform does not read what a URL points at.

    Letting a reference raise an answer's standing would turn a text box into evidence.
    """
    tenant = seed(postgres_database["owner_url"])
    question_id = "continuity.restore_tested"

    with client_for(postgres_database, tenant) as client:
        bare = client.put(answer_url(tenant, question_id), json={"answer": "informal"}).json()
        cited = client.put(
            answer_url(tenant, question_id),
            json={"answer": "informal", "evidence_reference": "https://intranet.test/policy"},
        ).json()

    assert question_in(cited, question_id)["evidence_reference"] == "https://intranet.test/policy"
    assert bare["completeness_percentage"] == cited["completeness_percentage"]
    assert question_in(bare, question_id)["answer"] == question_in(cited, question_id)["answer"]


# -- the catalogue itself ----------------------------------------------------


def test_an_unknown_question_is_not_answerable(postgres_database: dict[str, str]) -> None:
    tenant = seed(postgres_database["owner_url"])
    with client_for(postgres_database, tenant) as client:
        response = client.put(answer_url(tenant, "made.up_question"), json={"answer": "verified"})
    assert response.status_code == 404


def test_every_question_is_bilingual_and_explained() -> None:
    """Romanian is the source language, and English is not allowed to lag behind it."""
    for question in load_questionnaire().questions:
        for field in (question.title_ro, question.title_en, question.help_ro, question.help_en):
            assert field.strip(), question.question_id
            assert field.strip().endswith("."), f"{question.question_id}: should read as a sentence"


def test_romanian_carries_its_diacritics() -> None:
    """Romanian without diacritics reads as a machine wrote it, because one did."""
    questionnaire = load_questionnaire()
    romanian = " ".join(
        text
        for question in questionnaire.questions
        for text in (question.title_ro, question.help_ro)
    )
    assert set("șțăîâ") <= set(romanian.lower())


def test_no_cis_control_text_is_reproduced() -> None:
    """Copyrighted text, and mapping to it is a licensing decision rather than a code one.

    The field is present and empty on purpose: populating it later is a data change,
    and an approximation written now would be read as authoritative.
    """
    for section in load_questionnaire().sections:
        assert section.cis_reference is None
        assert section.nis2_reference.startswith("Article 21(2)")


def test_every_nis2_measure_category_is_covered() -> None:
    """All ten of Article 21(2). A questionnaire missing one is silently incomplete."""
    references = {section.nis2_reference for section in load_questionnaire().sections}
    expected = {f"Article 21(2)({letter})" for letter in "abcdefghij"}
    assert references == expected


def test_the_ladder_is_the_scale_the_scoring_assumes() -> None:
    """The rungs skip 1 and 4 deliberately; the top rung still has to be the maximum."""
    questionnaire = load_questionnaire()
    levels = [rung.level for rung in questionnaire.ladder if rung.scored]
    assert max(level for level in levels if level is not None) == MAX_LEVEL
    assert min(level for level in levels if level is not None) == 0
    claimed = [rung.answer for rung in questionnaire.ladder if (rung.level or 0) >= CLAIM_LEVEL]
    assert claimed == ["documented", "verified"]


def test_corroborated_questions_name_a_check_that_exists() -> None:
    """A typo here would silently disable corroboration rather than fail."""
    from siembiot.check_metadata import load_check_metadata

    known = set(load_check_metadata())
    for question in load_questionnaire().questions:
        if question.corroborating_check_id:
            assert question.corroborating_check_id in known, question.question_id


def test_most_questions_are_not_observable() -> None:
    """Which is the reason for asking at all.

    If this ever inverts, the questionnaire has drifted into asking about things the
    platform already measures, and it should be measuring them instead.
    """
    questions = load_questionnaire().questions
    observable = [q for q in questions if q.corroborating_check_id]
    assert 0 < len(observable) < len(questions) / 4
