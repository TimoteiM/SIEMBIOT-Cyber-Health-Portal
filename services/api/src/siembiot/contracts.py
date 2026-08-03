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
