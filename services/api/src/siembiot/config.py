from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SIEMBIOT_", extra="ignore")

    environment: str = "development"
    public_base_url: str = "http://localhost:3000"
    database_url: str = "postgresql+psycopg://siembiot_app:CHANGEME@127.0.0.1:5432/siembiot"
    oidc_issuer: str = "http://localhost:8080/realms/siembiot"
    oidc_client_id: str = "siembiot-web"
    oidc_client_secret: str | None = None
    session_encryption_key: str | None = None
    session_ttl_seconds: int = Field(default=28800, ge=300, le=86400)
    oidc_transaction_ttl_seconds: int = Field(default=600, ge=60, le=900)

    @property
    def callback_url(self) -> str:
        return f"{self.public_base_url.rstrip('/')}/api/v1/auth/callback"
