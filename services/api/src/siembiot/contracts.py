from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


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
