from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    contract_version: Literal["v1"] = "v1"


class HealthResponse(ContractModel):
    """Liveness: this process is running and not wedged.

    Deliberately answers without touching the database. A liveness probe that fails
    during a database outage makes an orchestrator restart every replica, which does
    not fix the database and does delay recovery once it returns.
    """

    status: Literal["ok"] = "ok"


class ReadinessResponse(ContractModel):
    """Readiness: this process can serve a request right now.

    Separate from liveness because the two answers have different consequences. Not
    ready removes a replica from rotation; not alive restarts it. Confusing them turns
    a recoverable dependency outage into a restart loop.
    """

    ready: bool
    #: Named so an operator reading a failed probe knows which dependency to look at,
    #: without needing to correlate against logs.
    checks: dict[str, bool] = Field(default_factory=dict)


class ErrorBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str
    message: str
    request_id: str


class ErrorEnvelope(ContractModel):
    error: ErrorBody


class UserResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    email: str = Field(min_length=3, max_length=320)
    display_name: str


class SessionResponse(ContractModel):
    authenticated: Literal[True] = True
    user: UserResponse


class OrganizationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(pattern=r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class OrganizationResponse(ContractModel):
    id: UUID
    name: str
    slug: str
    created_at: datetime


class MembershipUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal[
        "organization_owner",
        "security_admin",
        "analyst",
        "viewer_auditor",
        "maturity_contributor",
    ]


class MembershipResponse(ContractModel):
    id: UUID
    organization_id: UUID
    user_id: UUID
    role: str
    status: str
    created_at: datetime


class InvitationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=320)
    role: Literal[
        "organization_owner",
        "security_admin",
        "analyst",
        "viewer_auditor",
        "maturity_contributor",
    ]


class InvitationAccept(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=32, max_length=256)


class InvitationResponse(ContractModel):
    id: UUID
    organization_id: UUID
    email: str
    role: str
    status: str
    expires_at: datetime
    created_at: datetime


class InvitationCreatedResponse(InvitationResponse):
    acceptance_token: str


class AuditEventResponse(ContractModel):
    id: UUID
    organization_id: UUID | None
    actor: dict[str, str]
    action: str
    resource: dict[str, str]
    request_id: str
    correlation_id: str
    occurred_at: datetime
    outcome: str
    context: dict[str, Any]


class DomainCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: str = Field(min_length=1, max_length=253)


class DomainResponse(ContractModel):
    id: UUID
    organization_id: UUID
    canonical_name: str
    unicode_display: str
    registrable_domain: str
    warnings: list[Literal["idn_present", "mixed_scripts"]]
    ownership_state: Literal[
        "pending", "verified", "expired", "failed", "revoked", "reverification_required"
    ]
    created_at: datetime


class DomainChallengeCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: Literal["dns_txt", "https_file"]


class DomainChallengeResponse(ContractModel):
    id: UUID
    domain_id: UUID
    method: Literal["dns_txt", "https_file"]
    state: Literal["pending", "verified", "expired", "failed", "revoked"]
    expires_at: datetime
    attempts_remaining: int = Field(ge=0, le=5)
    verification_location: str


class DomainChallengeCreatedResponse(DomainChallengeResponse):
    verification_token: str = Field(min_length=32, max_length=256)


class AssessmentAuthorizationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain_ids: list[UUID] = Field(min_length=1, max_length=100)
    operation_classes: list[
        Literal[
            "dns_verification",
            "https_verification",
            "passive_assessment",
            "active_assessment",
        ]
    ] = Field(min_length=1, max_length=4)
    policy_version: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    consent_version: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    consent_text: str = Field(min_length=20, max_length=10_000)
    valid_from: datetime
    valid_until: datetime


class AssessmentAuthorizationResponse(ContractModel):
    id: UUID
    organization_id: UUID
    state: Literal["draft", "active", "expired", "revoked"]
    policy_version: str
    consent_version: str
    valid_from: datetime
    valid_until: datetime
    operation_classes: list[str]


class AuthorizationRevoke(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=10, max_length=500)


class ScopeManifestResponse(ContractModel):
    id: UUID
    authorization_id: UUID
    manifest_version: Literal["v1"] = "v1"
    payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    key_id: str
    algorithm: Literal["EdDSA"] = "EdDSA"
    created_at: datetime


class EmergencyControlCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: Literal["global", "organization", "domain", "operation_class"]
    domain_id: UUID | None = None
    operation_class: (
        Literal["dns_verification", "https_verification", "passive_assessment", "active_assessment"]
        | None
    ) = None
    reason: str = Field(min_length=10, max_length=500)
    expires_at: datetime | None = None


class EmergencyControlResponse(ContractModel):
    id: UUID
    scope: Literal["global", "organization", "domain", "operation_class"]
    organization_id: UUID | None = None
    domain_id: UUID | None = None
    operation_class: str | None = None
    reason: str
    active: bool
    created_at: datetime
    expires_at: datetime | None = None


class EmergencyControlDeactivate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=10, max_length=500)


class NetworkDecisionResponse(ContractModel):
    allowed: bool
    reason_code: Literal[
        "allowed",
        "invalid_target",
        "forbidden_address",
        "mixed_dns_answers",
        "forbidden_port",
        "redirect_not_authorized",
        "manifest_inactive",
        "authorization_revoked",
        "emergency_control_active",
        "budget_exceeded",
        "timeout",
        "response_too_large",
        "cancelled",
    ]
    operation_class: str
    policy_version: str


ASSESSMENT_STATES = Literal[
    "draft",
    "awaiting_authorization",
    "queued",
    "planning",
    "collecting",
    "normalizing",
    "evaluating",
    "agent_analysis",
    "report_generation",
    "completed",
    "cancelled",
    "partially_completed",
    "failed",
    "expired",
    "blocked_by_policy",
]

#: Passive observation reads only what the target already publishes, so it needs no
#: proof of control. Authorized assessment can reach past what a visitor sees, and
#: requires verified control and a signed authorization.
ASSESSMENT_MODES = Literal["passive_observation", "authorized_assessment"]

STEP_STATES = Literal[
    "pending", "running", "succeeded", "failed", "skipped", "cancelled", "dead_lettered"
]


class AssessmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain_id: UUID
    #: Defaults to passive observation, the mode that reads only what the target
    #: already publishes. Defaulting to the wider mode would mean a caller who omitted
    #: the field got the more intrusive behaviour by accident.
    mode: ASSESSMENT_MODES = "passive_observation"
    #: Selectors are never guessed, so an organization that uses DKIM declares them.
    dkim_selectors: list[str] = Field(default_factory=list, max_length=10)


class AssessmentStepResponse(ContractModel):
    name: str
    state: STEP_STATES
    attempts: int
    last_error: str | None = None


class AssessmentProgressResponse(ContractModel):
    """Progress counted from settled steps, never from elapsed time."""

    total_steps: int
    settled_steps: int
    succeeded_steps: int
    percentage: float
    failed_steps: list[str]


class AssessmentResponse(ContractModel):
    id: UUID
    organization_id: UUID
    domain_id: UUID
    state: ASSESSMENT_STATES
    #: How this run was produced. Reported so a result can never be read without
    #: knowing what it was allowed to look at.
    mode: ASSESSMENT_MODES
    methodology_version: str
    created_at: datetime
    completed_at: datetime | None = None
    cancellation_requested: bool = False
    progress: AssessmentProgressResponse
    steps: list[AssessmentStepResponse] = Field(default_factory=list)
    score: float | None = None
    band: str | None = None
    coverage_percentage: float | None = None


class AssessmentCancel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=3, max_length=500)


class AssetCandidateResponse(ContractModel):
    id: UUID
    domain_id: UUID
    name: str
    source: Literal["certificate_transparency", "dns", "user_declared", "passive_intelligence"]
    attribution_confidence: float = Field(ge=0, le=1)
    attribution_basis: Literal[
        "authorized_domain", "subdomain_of_authorized_domain", "unrelated_name"
    ]
    shared_hosting: bool
    state: Literal["unreviewed", "accepted", "rejected"]
    first_seen_at: datetime
    last_seen_at: datetime
    observation_count: int


class AssetCandidateDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    #: Deliberately excludes "unreviewed": a decision cannot be un-made, only changed.
    decision: Literal["accepted", "rejected"]
    reason: str | None = Field(default=None, min_length=3, max_length=2000)


#: Ordered most to least urgent. The order is part of the contract: a client that
#: sorts by this list shows the same priority the methodology assigns.
FINDING_SEVERITIES = Literal["critical", "high", "medium", "low", "informational"]
FINDING_STATES = Literal["open", "resolved", "regressed", "suppressed", "accepted_risk"]


class FindingConfidenceResponse(ContractModel):
    """Three separate confidences, never averaged into one reassuring number.

    Attribution, source and freshness fail independently and mean different things: a
    finding can rest on excellent evidence about an asset that may not be yours. A
    single blended figure would hide exactly the distinction a reader needs.
    """

    attribution: float
    source: float
    freshness: float


class RemediationResponse(ContractModel):
    """What to do about a finding, in both languages.

    `review_status` is part of the contract rather than a detail: guidance drafted
    from a standard and guidance signed off by a reviewer carry different weight, and
    a reader who cannot tell them apart will act on both the same way.
    """

    template_id: str
    version: str
    review_status: Literal["draft", "reviewed"]
    effort: Literal["low", "medium", "high"]
    summary_ro: str
    summary_en: str
    steps_ro: list[str] = Field(default_factory=list)
    steps_en: list[str] = Field(default_factory=list)
    verification_ro: str
    verification_en: str
    #: Present only where following the guidance can break something. Absent means no
    #: obvious failure mode, not that the caveat was omitted for brevity.
    caveat_ro: str | None = None
    caveat_en: str | None = None
    references: list[str] = Field(default_factory=list)


class FindingResponse(ContractModel):
    id: UUID
    check_id: str
    check_version: str
    methodology_version: str
    pillar: str
    #: Which of the six pillars, as the methodology letters them.
    pillar_letter: str
    severity: FINDING_SEVERITIES
    state: FINDING_STATES
    subject_kind: str
    subject_identifier: str
    #: Why the check reached this result -- the specific condition, not the category.
    reason_code: str | None = None
    title_ro: str
    title_en: str
    rationale_ro: str
    rationale_en: str
    #: Named by the catalog. `remediation` carries the guidance itself; the bare
    #: identifier stays so a client can reference it even when guidance is missing.
    remediation_template: str | None = None
    remediation: RemediationResponse | None = None
    references: list[str] = Field(default_factory=list)
    confidence: FindingConfidenceResponse
    #: How long this has been true. A finding first seen months ago is a different
    #: conversation from one that appeared yesterday.
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None = None
    #: How many observations the conclusion rests on. Not the observations themselves:
    #: evidence is fetched deliberately, not attached to every list response.
    evidence_count: int = 0


class FindingSummaryResponse(ContractModel):
    """Counts by severity, so a reader sees the shape before the list."""

    total: int
    open: int
    by_severity: dict[str, int]


class DomainFindingsResponse(ContractModel):
    domain_id: UUID
    assessment_id: UUID | None = None
    methodology_version: str | None = None
    #: Absent when no assessment has completed yet -- distinct from a score of zero.
    score: float | None = None
    band: str | None = None
    coverage_percentage: float | None = None
    summary: FindingSummaryResponse
    findings: list[FindingResponse] = Field(default_factory=list)


#: Cadences the scheduler knows how to advance. 'off' is a first-class choice: an
#: organization that paused a domain is saying something different from one that never
#: configured it.
SCHEDULE_CADENCES = Literal["off", "daily", "weekly", "monthly", "quarterly"]


class ScheduleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cadence: SCHEDULE_CADENCES
    #: Passive by default. An unattended run must never be the one that reaches past
    #: what a visitor sees, because nobody is watching it happen.
    mode: ASSESSMENT_MODES = "passive_observation"
    #: Local hours to hold off during. Both or neither; the database enforces the pair.
    quiet_hours_start: int | None = Field(default=None, ge=0, le=23)
    quiet_hours_end: int | None = Field(default=None, ge=0, le=23)
    timezone: str = Field(default="Europe/Bucharest", max_length=64)


class ScheduleResponse(ContractModel):
    domain_id: UUID
    cadence: SCHEDULE_CADENCES
    mode: ASSESSMENT_MODES
    quiet_hours_start: int | None = None
    quiet_hours_end: int | None = None
    timezone: str
    #: Absent exactly when the cadence is 'off'. The database holds the two together.
    next_run_at: datetime | None = None
    last_run_at: datetime | None = None


class HistoryPointResponse(ContractModel):
    """One completed assessment, as a point on a timeline."""

    assessment_id: UUID
    completed_at: datetime
    mode: ASSESSMENT_MODES
    methodology_version: str
    score: float
    band: str
    coverage_percentage: float
    #: False below the methodology's coverage floor. Such a run has a number but not a
    #: result, so a chart must not draw it as one point among equals.
    coverage_sufficient: bool


class FindingChangeResponse(ContractModel):
    check_id: str
    severity: FINDING_SEVERITIES
    title_ro: str
    title_en: str


class AssessmentChangeResponse(ContractModel):
    """What moved between two runs, and whether the comparison means anything.

    `comparable` is the honest part. A score that rose because coverage fell is not an
    improvement -- it is a different question, answered against less evidence. When the
    two runs did not see the same amount, the deltas are still reported but the flag
    says not to read them as progress.
    """

    previous_assessment_id: UUID
    current_assessment_id: UUID
    score_delta: float
    coverage_delta: float
    comparable: bool
    #: Why not, when it is not: 'insufficient_coverage' or 'coverage_moved'.
    incomparable_reason: str | None = None
    resolved: list[FindingChangeResponse] = Field(default_factory=list)
    opened: list[FindingChangeResponse] = Field(default_factory=list)
    #: Findings present before and still present now. Counted rather than listed: the
    #: list a reader needs on this screen is what changed.
    unchanged_count: int = 0


class DomainHistoryResponse(ContractModel):
    domain_id: UUID
    #: Oldest first, so a chart can render it without reversing.
    points: list[HistoryPointResponse] = Field(default_factory=list)
    #: Absent until a domain has two completed runs to compare.
    change: AssessmentChangeResponse | None = None


#: What somebody says is happening to the work. Never what the platform believes about
#: the weakness itself, which is the finding's state.
ACTION_STATUSES = Literal["planned", "in_progress", "blocked", "completed"]

#: How the assertion and the evidence relate. This is the field worth reading.
ACTION_VERIFICATION = Literal[
    # Marked done, and the next assessment agrees the weakness is gone.
    "confirmed",
    # Marked done, and the weakness is still observed. Either the fix did not work or
    # it was applied somewhere the assessment does not reach.
    "asserted_not_observed",
    # Gone, without anybody recording that they fixed it. Worth knowing: it may have
    # been somebody outside the tool, or a change nobody intended.
    "resolved_without_action",
    # Still open and still being worked on. The ordinary case.
    "in_flight",
]


class ActionUpsert(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: ACTION_STATUSES = "planned"
    #: Absent is a real state: unassigned work is common, and requiring a name here
    #: would produce a fictional one.
    owner_user_id: UUID | None = None
    due_at: datetime | None = None
    note: str | None = Field(default=None, min_length=1, max_length=2000)


class ActionResponse(ContractModel):
    id: UUID
    finding_id: UUID
    check_id: str
    title_ro: str
    title_en: str
    severity: FINDING_SEVERITIES
    status: ACTION_STATUSES
    owner_user_id: UUID | None = None
    owner_display_name: str | None = None
    due_at: datetime | None = None
    note: str | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    #: The finding's own state, carried alongside so the two are never read apart.
    finding_state: FINDING_STATES
    verification: ACTION_VERIFICATION
    #: Past its date and not finished. Computed here so every client agrees on it.
    overdue: bool = False


class RoadmapResponse(ContractModel):
    domain_id: UUID
    actions: list[ActionResponse] = Field(default_factory=list)
    #: Open findings with nobody assigned to them. The gap between what is known and
    #: what anybody intends to do, which is the number a manager actually wants.
    unplanned_count: int = 0
    overdue_count: int = 0
    #: Actions asserted complete whose weakness is still observed.
    contradicted_count: int = 0


# -- self-assessment ---------------------------------------------------------
#
# Everything below carries declarations rather than observations, and the contract is
# shaped to keep that visible at every layer. There is deliberately no field anywhere
# that combines a self-declared figure with a measured one.

MATURITY_ANSWERS = Literal[
    "absent", "informal", "documented", "verified", "unknown", "not_applicable"
]

#: What the technical assessment saw about the same subject, where it could see anything.
OBSERVED_RESULT = Literal["pass", "problem", "inconclusive", "not_assessed"]

CORROBORATION = Literal["consistent", "contradicted", "understated", "not_observed"]


class LadderRungResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answer: MATURITY_ANSWERS
    #: Absent where the rung is not scored. Not zero: "I do not know" is not "no".
    level: int | None = None
    scored: bool
    label_ro: str
    label_en: str


class AnswerUpsert(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answer: MATURITY_ANSWERS
    #: Where the supporting document lives, if the respondent says one does. Naming a
    #: document is still an assertion; the platform does not read it, and nothing is
    #: promoted on the strength of a string in this field.
    evidence_reference: str | None = Field(default=None, min_length=1, max_length=500)
    note: str | None = Field(default=None, min_length=1, max_length=2000)


class QuestionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question_id: str
    nis2_reference: str
    weight: int
    title_ro: str
    title_en: str
    help_ro: str
    help_en: str
    #: Absent for most questions, because most of what protects an organisation cannot
    #: be seen from the internet. That is the reason for asking rather than a gap.
    corroborating_check_id: str | None = None
    answer: MATURITY_ANSWERS | None = None
    evidence_reference: str | None = None
    note: str | None = None
    answered_at: datetime | None = None
    answered_by_display_name: str | None = None
    #: What the assessment saw, and how it sits against the answer. Both carried so a
    #: client cannot show one without the other.
    observed: OBSERVED_RESULT | None = None
    corroboration: CORROBORATION | None = None


class SectionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    section_id: str
    nis2_reference: str
    #: Present and null until a mapping to CIS Controls clears licensing review. An
    #: approximation written here would be read as authoritative.
    cis_reference: str | None = None
    title_ro: str
    title_en: str
    percentage: float | None = None
    completeness_percentage: float
    questions: list[QuestionResponse] = Field(default_factory=list)


class MaturityResponse(ContractModel):
    organization_id: UUID
    questionnaire_id: str
    questionnaire_version: str
    #: 'draft' until a named owner signs the questions off. Shown, not hidden.
    review_status: str
    notice_ro: str
    notice_en: str
    ladder: list[LadderRungResponse] = Field(default_factory=list)
    #: Withheld, not caveated, below the completeness floor. A caveat beside a number
    #: loses to the number.
    self_declared_percentage: float | None = None
    completeness_percentage: float
    minimum_completeness_percentage: int
    comparable: bool
    incomparable_reason: str | None = None
    answered_count: int = 0
    unanswered_count: int = 0
    not_applicable_count: int = 0
    #: Answers claiming a practice is in place where the assessment observes otherwise.
    contradicted_count: int = 0
    sections: list[SectionResponse] = Field(default_factory=list)


# -- publication -------------------------------------------------------------


class ConsentWithdrawal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    #: Optional. Somebody withdrawing consent does not owe an explanation, and demanding
    #: one is friction on exactly the action that must never have friction.
    reason: str | None = Field(default=None, min_length=1, max_length=1000)


class ConsentResponse(ContractModel):
    domain_id: UUID
    consented: bool
    granted_at: datetime | None = None
    #: Whether anything is on a public page right now. Reported separately from consent
    #: rather than inferred from it: consent is permission, and this is fact. Somebody
    #: asking "are we published" is asking the second question.
    published_at: datetime | None = None


# -- the public observatory --------------------------------------------------
#
# The published shape. Every field here is one somebody outside the tenant can read, so
# the list is deliberately short and adding to it is a decision rather than a detail.
# There is no score, no evidence, no identifier, and no organisation name.

PUBLISHED_BANDS = Literal["resilient", "managed", "developing", "exposed", "critical"]

#: Only outcomes that describe the domain. `unknown` and `error` describe our own
#: collection and are never published.
PUBLISHED_RESULTS = Literal["pass", "fail", "warning"]


class ObservatorySummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    registrable_domain: str
    #: Absent where coverage was too low to stand behind a result.
    band: PUBLISHED_BANDS | None = None
    coverage_percentage: float
    methodology_version: str
    observed_at: datetime
    published_at: datetime


class ObservatoryListResponse(ContractModel):
    total: int = 0
    profiles: list[ObservatorySummary] = Field(default_factory=list)


class PublishedCheckResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check_id: str
    result: PUBLISHED_RESULTS
    #: From the versioned policy catalogue, which is itself published. Carried here so a
    #: public page does not need its own copy of the catalogue to render a sentence --
    #: two copies of a title drift, and the drift shows up as a public page describing a
    #: check differently from the methodology that produced it.
    title_ro: str
    title_en: str


class ObservatoryProfileResponse(ContractModel):
    registrable_domain: str
    band: PUBLISHED_BANDS | None = None
    coverage_percentage: float
    #: Carried so a published claim can be traced to the rules that produced it. Anybody
    #: disputing a result deserves to know exactly what was applied.
    methodology_version: str
    policy_digest: str
    observed_at: datetime
    published_at: datetime
    checks: list[PublishedCheckResponse] = Field(default_factory=list)


class ObservatoryAggregateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check_id: str
    #: Never below the cohort threshold; thin cohorts are absent rather than rounded.
    cohort_size: int
    pass_count: int
    methodology_version: str
    released_at: datetime


class ObservatoryAggregatesResponse(ContractModel):
    aggregates: list[ObservatoryAggregateResponse] = Field(default_factory=list)
