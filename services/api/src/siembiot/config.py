from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SIEMBIOT_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    environment: str = "development"
    public_base_url: str = "http://localhost:3000"

    #: SIEMBIOT_APP_DATABASE_URL -- the least-privileged role.
    #:
    #: Named for the role it carries, not for "the database", because the distinction
    #: is load-bearing: SIEMBIOT_DATABASE_URL names the owner, the owner is a superuser,
    #: and superusers bypass row-level security even where it is declared FORCE.
    #: Serving from the owner therefore switches off tenant isolation completely and
    #: silently -- every query still succeeds, and every organization can read every
    #: other one's rows. SIEMBIOT_DATABASE_URL is the migration credential and nothing
    #: else.
    #:
    #: `Database.verify_least_privilege` re-checks this against the live connection at
    #: startup, because a variable is a claim and the connected role is the fact.
    app_database_url: str = "postgresql+psycopg://siembiot_app:CHANGEME@127.0.0.1:5432/siembiot"
    # Authentication is owned by a separate team and terminates upstream. The
    # gateway proves it is the caller with this shared secret; without it, identity
    # headers are ignored. Required outside development.
    identity_gateway_secret: str | None = None
    domain_challenge_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    domain_challenge_create_limit_per_hour: int = Field(default=3, ge=1, le=20)
    domain_reverification_days: int = Field(default=30, ge=1, le=365)
