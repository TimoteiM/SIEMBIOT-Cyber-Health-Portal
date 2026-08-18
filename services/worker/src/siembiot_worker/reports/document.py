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


@dataclass(frozen=True)
class ReportPillar:
    pillar: str
    score: float | None
    weight: float


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
