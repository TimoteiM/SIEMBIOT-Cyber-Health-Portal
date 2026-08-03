from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Classification = Literal["public_metadata", "private_metadata", "sensitive"]


class AdapterDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    adapter_id: str = Field(pattern=r"^[a-z][a-z0-9._-]{1,63}$")
    adapter_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    capabilities: tuple[str, ...] = Field(min_length=1)
    terms_note: str = Field(min_length=1, max_length=512)
    input_classification: Classification
    output_classification: Classification
    required_secret_names: tuple[str, ...]
    health_semantics: str = Field(min_length=1, max_length=128)
    timeout_seconds: float = Field(gt=0, le=30)
    rate_unit: str = Field(min_length=1, max_length=64)
    cost_unit: str = Field(min_length=1, max_length=64)
    cache_ttl_seconds: int = Field(ge=0, le=86_400)
    fixture_support: Literal[True]
    output_schema: str = Field(pattern=r"^[a-z][a-z0-9.-]+\.v[0-9]+$")
    retries_allowed: bool = False

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(
            not capability or capability != capability.lower() for capability in value
        ):
            raise ValueError("invalid_capabilities")
        return value

    @model_validator(mode="after")
    def fixture_requires_zero_secrets(self) -> AdapterDescriptor:
        if self.required_secret_names:
            raise ValueError("fixture_adapter_requires_no_secrets")
        return self
