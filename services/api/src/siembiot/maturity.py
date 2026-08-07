"""The self-assessment catalogue, and what a set of answers adds up to.

Two things live here and nothing else: reading the questionnaire out of the shared
policy package, and turning answers into numbers. No database, no request handling.

**The number this produces is not comparable with the technical score and must never be
combined with one.** They answer different questions with different reliability: one is
what the platform observed from outside, the other is what somebody typed about their own
organisation. An average of the two would be a number with no meaning that nonetheless
looks like a summary, and it would let a confident self-report cover a measured weakness.
So the two are reported side by side, and the API has no endpoint that adds them up.

**"I do not know" reduces completeness rather than scoring zero.** Exactly as an unknown
check reduces coverage rather than failing, because not knowing whether you have backups
is a different statement from knowing you have none -- worse in some ways, but not the
same, and one number cannot say both. Below the completeness floor the score is withheld
rather than shown with a caveat, since a caveat next to a number loses to the number.

**Where a question overlaps something observable, the answer is checked against it.**
Only a handful do -- most of what protects an organisation is invisible from the internet,
which is the reason to ask at all -- but for those few, an organisation asserting that
its mail is protected while the assessment watches mail go unprotected is the single most
useful sentence this module can produce.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, cast, get_args

POLICY_ROOT = Path(__file__).resolve().parents[4] / "packages" / "policy"

#: The rung a respondent chose, by name. The numeric level is the catalogue's reading of
#: it and is deliberately not what gets stored.
MATURITY_ANSWERS = Literal[
    "absent", "informal", "documented", "verified", "unknown", "not_applicable"
]

#: What the technical assessment has to say about the same subject, reduced to the only
#: distinctions that matter here. `inconclusive` is kept apart from `pass` on purpose:
#: a check that could not run is not a check that succeeded.
OBSERVED_RESULT = Literal["pass", "problem", "inconclusive", "not_assessed"]

#: How a declaration and an observation relate. Same shape as the roadmap's verification
#: field, and for the same reason.
CORROBORATION = Literal[
    # Declaration and observation agree, in either direction.
    "consistent",
    # Claimed in place; the assessment sees the problem anyway.
    "contradicted",
    # Claimed absent or informal; the assessment sees it working. Worth surfacing --
    # an organisation underrating itself will spend effort where it is not needed.
    "understated",
    # Nothing observed, or nothing conclusive. Never reported as agreement.
    "not_observed",
]

#: Results the technical side treats as evidence of a weakness.
PROBLEM_RESULTS = frozenset({"fail", "warning"})
#: Results that mean the check ran but decided nothing.
INCONCLUSIVE_RESULTS = frozenset({"unknown", "error", "not_applicable"})

#: At or above this level the respondent is claiming the practice is in place. Below it
#: they are saying it is not, or not properly. The corroboration reading turns on this
#: single threshold, so it is named rather than written as a bare 3.
CLAIM_LEVEL = 3

#: Maximum rung, and therefore the divisor that turns levels into a percentage.
MAX_LEVEL = 5


class MaturityError(RuntimeError):
    pass


@dataclass(frozen=True)
class LadderRung:
    answer: MATURITY_ANSWERS
    #: None where the rung is not scored, which is not the same as a level of zero.
    level: int | None
    scored: bool
    label_ro: str
    label_en: str
    #: Why an unscored rung is unscored: it either shrinks the denominator or leaves it.
    effect: str | None


@dataclass(frozen=True)
class Question:
    question_id: str
    section_id: str
    nis2_reference: str
    weight: int
    #: The check whose result speaks to the same subject, where one exists. Almost always
    #: absent: governance, training and recovery are not observable from the internet.
    corroborating_check_id: str | None
    title_ro: str
    title_en: str
    help_ro: str
    help_en: str


@dataclass(frozen=True)
class Section:
    section_id: str
    nis2_reference: str
    #: Present in the schema, unpopulated. Mapping to CIS Controls text is a licensing
    #: decision, and an approximation written here would be read as authoritative.
    cis_reference: str | None
    title_ro: str
    title_en: str
    questions: tuple[Question, ...]


@dataclass(frozen=True)
class Questionnaire:
    questionnaire_id: str
    version: str
    review_status: str
    notice_ro: str
    notice_en: str
    minimum_completeness_percentage: int
    ladder: tuple[LadderRung, ...]
    sections: tuple[Section, ...]

    @property
    def questions(self) -> tuple[Question, ...]:
        return tuple(question for section in self.sections for question in section.questions)

    def rung(self, answer: str) -> LadderRung:
        for rung in self.ladder:
            if rung.answer == answer:
                return rung
        raise MaturityError(f"no ladder rung named {answer!r}")


@dataclass(frozen=True)
class SectionScore:
    section_id: str
    #: None where nothing in the section was answered, or everything was marked not
    #: applicable. A section with no answers scores nothing rather than zero.
    percentage: float | None
    completeness_percentage: float
    answered_weight: int
    applicable_weight: int


@dataclass(frozen=True)
class MaturityScore:
    """Deliberately without a band.

    The technical score earns a band because it rests on observation. Giving this the
    same five labels would invite reading them as the same kind of statement, and from
    there to averaging them is one small step that somebody will eventually take.
    """

    #: Withheld below the completeness floor rather than shown alongside a warning.
    self_declared_percentage: float | None
    completeness_percentage: float
    comparable: bool
    incomparable_reason: str | None
    answered_count: int
    unanswered_count: int
    not_applicable_count: int
    sections: tuple[SectionScore, ...]


def _rung(raw: dict[str, Any]) -> LadderRung:
    answer = str(raw["answer"])
    if answer not in get_args(MATURITY_ANSWERS):
        raise MaturityError(f"unknown ladder answer {answer!r}")
    level = raw.get("level")
    scored = bool(raw["scored"])
    if scored == (level is None):
        raise MaturityError(f"{answer}: a scored rung needs a level and an unscored one must not")
    return LadderRung(
        answer=cast(MATURITY_ANSWERS, answer),
        level=int(level) if level is not None else None,
        scored=scored,
        label_ro=str(raw["label_ro"]),
        label_en=str(raw["label_en"]),
        effect=str(raw["effect"]) if raw.get("effect") else None,
    )


def _question(raw: dict[str, Any], section_id: str, reference: str) -> Question:
    weight = int(raw["weight"])
    if weight < 1:
        raise MaturityError(f"{raw['question_id']}: weight must be positive")
    return Question(
        question_id=str(raw["question_id"]),
        section_id=section_id,
        nis2_reference=reference,
        weight=weight,
        corroborating_check_id=(
            str(raw["corroborating_check_id"]) if raw.get("corroborating_check_id") else None
        ),
        title_ro=str(raw["title_ro"]),
        title_en=str(raw["title_en"]),
        help_ro=str(raw["help_ro"]),
        help_en=str(raw["help_en"]),
    )


@lru_cache(maxsize=8)
def load_questionnaire(version: str = "1.0.0") -> Questionnaire:
    """The questionnaire, validated on the way in.

    A malformed catalogue stops the module from loading rather than producing a failed
    request for a reader who did nothing wrong, at an hour nobody is watching the logs.
    """
    path = POLICY_ROOT / "maturity" / f"v{version.split('.')[0]}" / "nis2_baseline.json"
    if not path.is_file():
        raise MaturityError(f"no maturity questionnaire for version {version}")

    raw = json.loads(path.read_text(encoding="utf-8"))
    ladder = tuple(_rung(item) for item in raw["answer_ladder"])
    if {rung.answer for rung in ladder} != set(get_args(MATURITY_ANSWERS)):
        raise MaturityError("the ladder must define every answer the schema allows, and no more")

    sections: list[Section] = []
    seen: set[str] = set()
    for item in raw["sections"]:
        questions = tuple(
            _question(entry, str(item["section_id"]), str(item["nis2_reference"]))
            for entry in item["questions"]
        )
        for question in questions:
            if question.question_id in seen:
                raise MaturityError(f"duplicate question {question.question_id}")
            seen.add(question.question_id)
        sections.append(
            Section(
                section_id=str(item["section_id"]),
                nis2_reference=str(item["nis2_reference"]),
                cis_reference=str(item["cis_reference"]) if item.get("cis_reference") else None,
                title_ro=str(item["title_ro"]),
                title_en=str(item["title_en"]),
                questions=questions,
            )
        )

    if not sections:
        raise MaturityError("empty maturity questionnaire")

    return Questionnaire(
        questionnaire_id=str(raw["questionnaire_id"]),
        version=str(raw["version"]),
        review_status=str(raw["review_status"]),
        notice_ro=str(raw["notice_ro"]),
        notice_en=str(raw["notice_en"]),
        minimum_completeness_percentage=int(raw["minimum_completeness_percentage"]),
        ladder=ladder,
        sections=tuple(sections),
    )


def _percentage(part: float, whole: float) -> float:
    return round(part / whole * 100, 1)


def score(questionnaire: Questionnaire, answers: dict[str, str]) -> MaturityScore:
    """Turn answers into a score, or decline to.

    Weighted by question, because "have you tested a restore" and "do you have a
    supplier list" are not worth the same. Unanswered questions and explicit "I do not
    know" are treated identically: both mean nobody has said, and a form left blank is
    not a claim.
    """
    section_scores: list[SectionScore] = []
    total_points = 0.0
    total_scored_weight = 0
    total_applicable_weight = 0
    answered = unanswered = not_applicable = 0

    for section in questionnaire.sections:
        points = 0.0
        scored_weight = 0
        applicable_weight = 0

        for question in section.questions:
            given = answers.get(question.question_id)
            rung = questionnaire.rung(given) if given else None

            if rung is not None and rung.answer == "not_applicable":
                # Leaves the denominator entirely: it is neither answered nor missing.
                not_applicable += 1
                continue

            applicable_weight += question.weight
            if rung is None or not rung.scored:
                unanswered += 1
                continue

            answered += 1
            scored_weight += question.weight
            points += (rung.level or 0) * question.weight

        total_points += points
        total_scored_weight += scored_weight
        total_applicable_weight += applicable_weight

        section_scores.append(
            SectionScore(
                section_id=section.section_id,
                percentage=(
                    _percentage(points, scored_weight * MAX_LEVEL) if scored_weight else None
                ),
                completeness_percentage=(
                    _percentage(scored_weight, applicable_weight) if applicable_weight else 100.0
                ),
                answered_weight=scored_weight,
                applicable_weight=applicable_weight,
            )
        )

    completeness = (
        _percentage(total_scored_weight, total_applicable_weight)
        if total_applicable_weight
        else 100.0
    )

    if not total_applicable_weight:
        # Every question marked not applicable. Not a failure and not a score.
        reason: str | None = "nothing_applicable"
    elif completeness < questionnaire.minimum_completeness_percentage:
        reason = "insufficient_completeness"
    else:
        reason = None

    return MaturityScore(
        self_declared_percentage=(
            _percentage(total_points, total_scored_weight * MAX_LEVEL)
            if reason is None and total_scored_weight
            else None
        ),
        completeness_percentage=completeness,
        comparable=reason is None,
        incomparable_reason=reason,
        answered_count=answered,
        unanswered_count=unanswered,
        not_applicable_count=not_applicable,
        sections=tuple(section_scores),
    )


def observed_result(results: list[str]) -> OBSERVED_RESULT:
    """Reduce every evaluation of one check across an organisation to a single reading.

    The worst result wins. A question like "the organisation's domains are configured
    so nobody can send mail in their name" is false if it is false for one domain, and
    an average across domains would let a well-configured majority hide the exception
    that is actually being exploited.
    """
    if not results:
        return "not_assessed"
    if any(result in PROBLEM_RESULTS for result in results):
        return "problem"
    if any(result == "pass" for result in results):
        # At least one clear pass and nothing failing. Inconclusive results elsewhere do
        # not demote it: something was observed working and nothing was observed broken.
        return "pass"
    return "inconclusive"


def corroborate(
    questionnaire: Questionnaire, answer: str, observation: OBSERVED_RESULT
) -> CORROBORATION:
    """How one declaration sits against what was observed about the same subject."""
    rung = questionnaire.rung(answer)
    if not rung.scored or observation in {"inconclusive", "not_assessed"}:
        # Nothing to compare. Reported as such rather than quietly as agreement, which
        # is the failure mode that would make this field worse than useless.
        return "not_observed"

    claims_in_place = (rung.level or 0) >= CLAIM_LEVEL
    if observation == "problem":
        return "contradicted" if claims_in_place else "consistent"
    return "consistent" if claims_in_place else "understated"
