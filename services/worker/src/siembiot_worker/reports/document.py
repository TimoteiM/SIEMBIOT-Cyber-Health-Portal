"""What a report says, separated from how it looks.

Plain data, assembled by the caller from what is already stored. Rendering never reads a
database, a clock or a file, which is what makes a report reproducible: the same stored
snapshot renders to the same bytes next year, and a report that cannot be reproduced
cannot be defended when somebody disputes it.

`generated_at` is passed in rather than read, for the same reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

#: Most urgent first. Matches the API's ordering, which is not alphabetical.
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "informational")


@dataclass(frozen=True)
class ReportFinding:
    check_id: str
    severity: str
    #: What the finding is about: usually the domain, sometimes a discovered host. Read
    #: from evidence, so it is treated as hostile text all the way to the page.
    subject: str
    title_ro: str
    title_en: str
    rationale_ro: str
    rationale_en: str
    reason_code: str | None = None
    remediation_summary_ro: str | None = None
    remediation_summary_en: str | None = None
    remediation_steps_ro: tuple[str, ...] = ()
    remediation_steps_en: tuple[str, ...] = ()
    #: Kept and rendered rather than dropped. A caveat exists because following the
    #: guidance without it can break something, and an instruction separated from its
    #: warning is worse than no instruction.
    remediation_caveat_ro: str | None = None
    remediation_caveat_en: str | None = None
    #: Draft guidance is labelled as draft on the page. A public body acting on advice
    #: nobody has reviewed should be told that is what it is.
    remediation_review_status: str | None = None

    #: What the collectors actually saw, as name/value pairs in the order the evidence
    #: recorded them.
    #:
    #: A finding without its evidence asks an institution to take the platform's word for
    #: it, which is precisely what a tool assessing public bodies should not do. Every
    #: value here came from somebody else's infrastructure and is treated as hostile text
    #: all the way to the page.
    evidence: tuple[tuple[str, str], ...] = ()
    #: `observed`, `absent`, `inconclusive`, `not_applicable`. Shown because "we looked
    #: and it was not there" and "we could not look" are different statements and a
    #: reader acts differently on each.
    evidence_status: str | None = None
    #: Which collector observation the evidence came from. Carried because a handful of
    #: attribute names mean different things depending on it -- days until expiry is a
    #: certificate on one and the domain registration itself on another -- and the
    #: renderer cannot tell them apart from the name alone.
    evidence_type: str | None = None
    #: Attributes the row cap left out. Rendered rather than dropped, because a reader
    #: who is not told the list was cut has no way to know it was.
    evidence_omitted: int = 0


@dataclass(frozen=True)
class ReportPillar:
    pillar: str
    score: float | None
    weight: float


@dataclass(frozen=True)
class ReportCheck:
    """One check and how it came out, whatever the outcome.

    The report listed only what failed. An institution reading it could see eight things
    to fix and no indication that five others were tested and are fine, or -- the one that
    matters -- that four could not be tested at all. Absence of red is not green, and a
    document that shows only red invites exactly that reading.
    """

    check_id: str
    title_ro: str
    title_en: str
    #: `pass`, `fail`, `warning`, `unknown` or `not_applicable`, as the evaluator recorded
    #: it. Not collapsed to good/bad here: the renderer needs the difference between "we
    #: tested this and it is wrong" and "we could not test this", and so does the reader.
    outcome: str


@dataclass(frozen=True)
class ReportEvidence:
    """One observation, as it sits behind a claim a reader wants to check."""

    observation_type: str
    subject: str
    status: str
    attributes: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ReportInsight:
    """One sentence the model wrote about this run's evidence.

    Kept apart from `ReportFinding` on purpose. A finding is deterministic: the same
    evidence and the same catalogue produce it every time, and it can be defended line by
    line. This cannot -- it is a reading, it may differ between runs, and the report has
    to say so rather than let the two blur into one voice.

    `support` is the evidence the claim cited. Every sentence here passed a validator
    that drops anything not tied to an observation this run actually made, so a claim
    without support does not reach this far; carrying the identifiers is what lets a
    reader check that months later.
    """

    text: str
    #: `measured`, `inferred` or `recommended` -- what the model says it is doing. Shown,
    #: because "this follows from the evidence" and "this is my suggestion" are different
    #: claims and a reader is entitled to know which one they are reading.
    kind: str
    #: The evidence behind the sentence, resolved rather than referenced.
    #:
    #: This used to be a list of identifiers. An identifier is not evidence: it proves a
    #: link exists to somebody who can query the database, and tells a reader nothing at
    #: all. What is carried now is the observation itself -- what was looked at, how it
    #: came back, and the values recorded -- so the claim can be checked by reading rather
    #: than by trusting.
    evidence: tuple[ReportEvidence, ...] = ()


@dataclass(frozen=True)
class ReportDocument:
    organization_name: str
    domain: str
    score: float | None
    band: str | None
    coverage_percentage: float
    coverage_sufficient: bool
    methodology_version: str
    policy_digest: str
    assessment_mode: str
    observed_at: datetime
    generated_at: datetime
    #: When the observations behind this score were removed under retention.
    #:
    #: A report carries a policy digest and a methodology version so a disputed result
    #: can be checked against the catalogue that produced it. Once the evidence is gone
    #: it cannot be recomputed, and a document that still printed those digests without
    #: saying so would invite exactly the wrong conclusion.
    evidence_erased_at: datetime | None = None
    pillars: tuple[ReportPillar, ...] = ()
    findings: tuple[ReportFinding, ...] = ()
    #: Every check the assessment evaluated, including the ones that passed and the ones
    #: it could not determine. Separate from `findings`, which is only what is wrong.
    checks: tuple[ReportCheck, ...] = ()
    #: The model's reading of this run, when one was produced and configured. Empty is
    #: the ordinary case: no key, no gateway, or a model that returned nothing usable.
    insights: tuple[ReportInsight, ...] = ()
    #: Checks that could not be determined. Named, not counted: "we could not tell about
    #: these three things" is a different statement from "coverage 91%", and only the
    #: first one tells a reader what to go and look at.
    undetermined_checks: tuple[str, ...] = ()
    #: Checks withheld because the run had no authorization to perform them. Separated
    #: from undetermined so a passive report does not read as though it tried and failed.
    withheld_checks: tuple[str, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def findings_by_severity(self) -> tuple[ReportFinding, ...]:
        """Most urgent first, then by check identifier.

        The tie-break is what makes the order total. Without it two findings of equal
        severity could swap places between renders of the same snapshot, and a report
        that differs from itself is not reproducible in any sense a reader would accept.
        """
        rank = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
        return tuple(
            sorted(
                self.findings,
                key=lambda finding: (
                    rank.get(finding.severity, len(SEVERITY_ORDER)),
                    finding.check_id,
                    finding.subject,
                ),
            )
        )
