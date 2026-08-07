from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    contract_version: Literal["v1"] = "v1"


class HealthResponse(ContractModel):
    status: Literal["ok"] = "ok"


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
