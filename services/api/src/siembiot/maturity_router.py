"""Reading and answering the self-assessment.

Two endpoints. One returns the questionnaire with whatever has been answered, the score
those answers produce, and -- for the few questions that overlap something observable --
what the assessment has to say about the same subject. The other records one answer.

There is no endpoint that combines this score with the technical one, and adding one
would be a mistake worth arguing about rather than a convenience. See `maturity`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy import Connection, text
from sqlalchemy.engine import RowMapping

from siembiot.audit import append_audit_event
from siembiot.auth import current_principal, require_trusted_origin
from siembiot.authorization import Action
from siembiot.contracts import (
    CORROBORATION,
    MATURITY_ANSWERS,
    OBSERVED_RESULT,
    AnswerUpsert,
    LadderRungResponse,
    MaturityResponse,
    QuestionResponse,
    SectionResponse,
)
from siembiot.db import Database
from siembiot.errors import AppError
from siembiot.identity import Principal
from siembiot.maturity import (
    Questionnaire,
    corroborate,
    load_questionnaire,
    observed_result,
    score,
)
from siembiot.organizations import authorize

#: Beyond this, an evaluation stops corroborating anything. Two missed quarterly runs
#: (the loosest cadence the scheduler offers is 91 days), which means assessment has
#: stopped rather than merely run a while ago. A stale pass silently agreeing with a
#: claim would be the worst reading this file could produce: it would confirm a
#: declaration using evidence that no longer describes anything.
CORROBORATION_HORIZON = timedelta(days=182)


def _database(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def _observations(
    connection: Connection, organization_id: UUID, check_ids: list[str]
) -> dict[str, OBSERVED_RESULT]:
    """The latest result of each corroborating check, per subject, reduced per check.

    `DISTINCT ON` rather than a join against the newest assessment: a check can be
    evaluated for several subjects, and each subject's own most recent result is the
    one that speaks to it. Reducing across subjects is the catalogue's business.
    """
    if not check_ids:
        return {}

    rows = connection.execute(
        text(
            """
            SELECT DISTINCT ON (check_id, subject_identifier) check_id, result
            FROM check_evaluations
            WHERE organization_id = :organization_id
              AND check_id = ANY(:check_ids)
              AND evaluated_at >= :horizon
            ORDER BY check_id, subject_identifier, evaluated_at DESC
            """
        ),
        {
            "organization_id": organization_id,
            "check_ids": check_ids,
            "horizon": datetime.now(UTC) - CORROBORATION_HORIZON,
        },
    ).mappings()

    grouped: dict[str, list[str]] = {check_id: [] for check_id in check_ids}
    for row in rows:
        grouped[str(row["check_id"])].append(str(row["result"]))
    return {check_id: observed_result(results) for check_id, results in grouped.items()}


def _answers(
    connection: Connection, organization_id: UUID, questionnaire: Questionnaire
) -> dict[str, RowMapping]:
    """Answers given against this questionnaire, at this version.

    Filtered on version rather than merely on identifier. A question reworded in a later
    revision is a different question, and letting an old answer reattach to new wording
    would put a response in somebody's mouth that they never gave.
    """
    rows = connection.execute(
        text(
            """
            SELECT r.question_id, r.answer, r.evidence_reference, r.note,
                   r.updated_at, u.display_name AS answered_by_display_name
            FROM maturity_responses r
            LEFT JOIN users u ON u.id = r.answered_by_user_id
            WHERE r.organization_id = :organization_id
              AND r.questionnaire_id = :questionnaire_id
              AND r.questionnaire_version = :version
            """
        ),
        {
            "organization_id": organization_id,
            "questionnaire_id": questionnaire.questionnaire_id,
            "version": questionnaire.version,
        },
    ).mappings()
    return {str(row["question_id"]): row for row in rows}


def build_maturity_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/organizations", tags=["maturity"])

    @router.get("/{organization_id}/maturity", response_model=MaturityResponse)
    def index(
        organization_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> MaturityResponse:
        questionnaire = load_questionnaire()
        check_ids = sorted(
            {
                question.corroborating_check_id
                for question in questionnaire.questions
                if question.corroborating_check_id
            }
        )

        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.ORGANIZATION_READ)
            stored = _answers(connection, organization_id, questionnaire)
            observed = _observations(connection, organization_id, check_ids)

        totals = score(questionnaire, {key: str(row["answer"]) for key, row in stored.items()})
        by_section = {item.section_id: item for item in totals.sections}

        sections: list[SectionResponse] = []
        contradicted = 0
        for section in questionnaire.sections:
            questions: list[QuestionResponse] = []
            for question in section.questions:
                row = stored.get(question.question_id)
                answer = cast(MATURITY_ANSWERS, row["answer"]) if row else None

                observation: OBSERVED_RESULT | None = None
                relation: CORROBORATION | None = None
                if question.corroborating_check_id:
                    observation = observed.get(question.corroborating_check_id, "not_assessed")
                    # Reported even with no answer, so the questionnaire can show what
                    # the platform already knows before anybody types anything.
                    relation = (
                        corroborate(questionnaire, answer, observation)
                        if answer
                        else "not_observed"
                    )
                    if relation == "contradicted":
                        contradicted += 1

                questions.append(
                    QuestionResponse(
                        question_id=question.question_id,
                        nis2_reference=question.nis2_reference,
                        weight=question.weight,
                        title_ro=question.title_ro,
                        title_en=question.title_en,
                        help_ro=question.help_ro,
                        help_en=question.help_en,
                        corroborating_check_id=question.corroborating_check_id,
                        answer=answer,
                        evidence_reference=row["evidence_reference"] if row else None,
                        note=row["note"] if row else None,
                        answered_at=row["updated_at"] if row else None,
                        answered_by_display_name=(row["answered_by_display_name"] if row else None),
                        observed=observation,
                        corroboration=relation,
                    )
                )

            summary = by_section[section.section_id]
            sections.append(
                SectionResponse(
                    section_id=section.section_id,
                    nis2_reference=section.nis2_reference,
                    cis_reference=section.cis_reference,
                    title_ro=section.title_ro,
                    title_en=section.title_en,
                    percentage=summary.percentage,
                    completeness_percentage=summary.completeness_percentage,
                    questions=questions,
                )
            )

        return MaturityResponse(
            organization_id=organization_id,
            questionnaire_id=questionnaire.questionnaire_id,
            questionnaire_version=questionnaire.version,
            review_status=questionnaire.review_status,
            notice_ro=questionnaire.notice_ro,
            notice_en=questionnaire.notice_en,
            ladder=[
                LadderRungResponse(
                    answer=rung.answer,
                    level=rung.level,
                    scored=rung.scored,
                    label_ro=rung.label_ro,
                    label_en=rung.label_en,
                )
                for rung in questionnaire.ladder
            ],
            self_declared_percentage=totals.self_declared_percentage,
            completeness_percentage=totals.completeness_percentage,
            minimum_completeness_percentage=questionnaire.minimum_completeness_percentage,
            comparable=totals.comparable,
            incomparable_reason=totals.incomparable_reason,
            answered_count=totals.answered_count,
            unanswered_count=totals.unanswered_count,
            not_applicable_count=totals.not_applicable_count,
            contradicted_count=contradicted,
            sections=sections,
        )

    @router.put(
        "/{organization_id}/maturity/answers/{question_id}",
        response_model=MaturityResponse,
    )
    def answer(
        organization_id: UUID,
        question_id: str,
        payload: AnswerUpsert,
        request: Request,
        principal: Principal = Depends(require_trusted_origin),
    ) -> MaturityResponse:
        """Record one answer, and return the whole questionnaire.

        Authorized with `ORGANIZATION_UPDATE`: an answer here is a statement made on
        behalf of the organisation, not a note about an assessment, so it sits with the
        people who can speak for it rather than with everybody who can read a report.

        Returns the full document because a single answer changes the score, the
        completeness, and possibly whether a score is shown at all. Returning only the
        stored row would leave every client to recompute that, and clients that
        recompute a score eventually disagree with the server about it.
        """
        questionnaire = load_questionnaire()
        known = {question.question_id for question in questionnaire.questions}
        if question_id not in known:
            raise AppError(404, "not_found", "The requested resource was not found.")

        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.ORGANIZATION_UPDATE)

            previous = connection.execute(
                text(
                    "SELECT answer FROM maturity_responses "
                    "WHERE organization_id = :organization_id "
                    "AND questionnaire_id = :questionnaire_id AND question_id = :question_id"
                ),
                {
                    "organization_id": organization_id,
                    "questionnaire_id": questionnaire.questionnaire_id,
                    "question_id": question_id,
                },
            ).scalar_one_or_none()

            row = (
                connection.execute(
                    text(
                        """
                        INSERT INTO maturity_responses (
                            organization_id, questionnaire_id, questionnaire_version,
                            question_id, answer, evidence_reference, note,
                            answered_by_user_id
                        ) VALUES (
                            :organization_id, :questionnaire_id, :version,
                            :question_id, :answer, :evidence_reference, :note, :actor
                        )
                        ON CONFLICT (organization_id, questionnaire_id, question_id)
                        DO UPDATE SET
                            questionnaire_version = excluded.questionnaire_version,
                            answer = excluded.answer,
                            evidence_reference = excluded.evidence_reference,
                            note = excluded.note,
                            answered_by_user_id = excluded.answered_by_user_id,
                            updated_at = now()
                        RETURNING id
                        """
                    ),
                    {
                        "organization_id": organization_id,
                        "questionnaire_id": questionnaire.questionnaire_id,
                        "version": questionnaire.version,
                        "question_id": question_id,
                        "answer": payload.answer,
                        "evidence_reference": payload.evidence_reference,
                        "note": payload.note,
                        "actor": principal.user_id,
                    },
                )
                .mappings()
                .one()
            )

            if previous != payload.answer:
                # Only on a change of answer. Recording every edit of a note would bury
                # the changes somebody actually wants to reconstruct -- and the change
                # worth reconstructing is an organisation that answered one way before
                # an incident and another way afterwards.
                connection.execute(
                    text(
                        """
                        INSERT INTO maturity_response_history (
                            organization_id, response_id, question_id,
                            from_answer, to_answer, actor_user_id
                        ) VALUES (
                            :organization_id, :response_id, :question_id,
                            :from_answer, :to_answer, :actor
                        )
                        """
                    ),
                    {
                        "organization_id": organization_id,
                        "response_id": row["id"],
                        "question_id": question_id,
                        "from_answer": previous,
                        "to_answer": payload.answer,
                        "actor": principal.user_id,
                    },
                )

            append_audit_event(
                connection,
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(principal.user_id),
                action="maturity.answer_changed",
                resource_type="maturity_question",
                resource_id=question_id,
                request_id=cast(str, request.state.request_id),
                correlation_id=request.state.correlation_id,
                outcome="success",
                context={"answer": payload.answer, "previous": previous or "none"},
            )

        return index(organization_id, request, principal)

    return router
