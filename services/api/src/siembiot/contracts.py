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


class CollectionExecutionModes(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fixture: Literal["available"] = "available"
    unavailable: Literal["structured_result_state"] = "structured_result_state"
    disabled_by_policy: Literal["structured_result_state"] = "structured_result_state"
    live: Literal["future_requires_explicit_activation"] = "future_requires_explicit_activation"


class CollectionCapabilityResponse(ContractModel):
    milestone_status: Literal["fixture_validation_only"] = "fixture_validation_only"
    fixture_only: Literal[True] = True
    live_execution: Literal[False] = False
    publishable: Literal[False] = False
    execution_modes: CollectionExecutionModes = Field(default_factory=CollectionExecutionModes)
    restricted_egress_boundary: Literal["required_before_live_activation"] = (
        "required_before_live_activation"
    )
    report_banner: Literal["FIXTURE DATA — NOT A LIVE ASSESSMENT"] = (
        "FIXTURE DATA — NOT A LIVE ASSESSMENT"
    )


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
    expires_at: datetime
    csrf_token: str


class LogoutResponse(ContractModel):
    logout_url: str | None


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
