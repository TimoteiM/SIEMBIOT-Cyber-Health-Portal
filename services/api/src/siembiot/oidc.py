from __future__ import annotations

from typing import Any, Protocol
from urllib.parse import urlencode

import httpx
import jwt

from siembiot.config import Settings


class OIDCClient(Protocol):
    issuer: str

    def authorization_url(
        self, *, state: str, nonce: str, code_challenge: str, redirect_uri: str
    ) -> str: ...

    def exchange_code(
        self, *, code: str, code_verifier: str, redirect_uri: str
    ) -> dict[str, Any]: ...

    def logout_url(self, *, post_logout_redirect_uri: str) -> str | None: ...


class StandardOIDCClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.issuer = settings.oidc_issuer.rstrip("/")
        self._metadata: dict[str, Any] | None = None

    def _discover(self) -> dict[str, Any]:
        if self._metadata is None:
            url = f"{self.issuer}/.well-known/openid-configuration"
            with httpx.Client(timeout=5.0, follow_redirects=False) as client:
                response = client.get(url, headers={"Accept": "application/json"})
                response.raise_for_status()
                if len(response.content) > 256_000:
                    raise ValueError("OIDC discovery document is too large")
                metadata = response.json()
            if metadata.get("issuer") != self.issuer:
                raise ValueError("OIDC discovery issuer mismatch")
            for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                if not isinstance(metadata.get(field), str):
                    raise ValueError(f"OIDC discovery is missing {field}")
            self._metadata = metadata
        return self._metadata

    def authorization_url(
        self, *, state: str, nonce: str, code_challenge: str, redirect_uri: str
    ) -> str:
        metadata = self._discover()
        query = urlencode(
            {
                "client_id": self.settings.oidc_client_id,
                "response_type": "code",
                "scope": "openid email profile",
                "redirect_uri": redirect_uri,
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"{metadata['authorization_endpoint']}?{query}"

    def exchange_code(self, *, code: str, code_verifier: str, redirect_uri: str) -> dict[str, Any]:
        metadata = self._discover()
        form = {
            "grant_type": "authorization_code",
            "client_id": self.settings.oidc_client_id,
            "code": code,
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri,
        }
        if self.settings.oidc_client_secret:
            form["client_secret"] = self.settings.oidc_client_secret
        with httpx.Client(timeout=5.0, follow_redirects=False) as client:
            response = client.post(metadata["token_endpoint"], data=form)
            response.raise_for_status()
            if len(response.content) > 256_000:
                raise ValueError("OIDC token response is too large")
            token_response = response.json()
        id_token = token_response.get("id_token")
        if not isinstance(id_token, str):
            raise ValueError("OIDC token response is missing id_token")
        key_client = jwt.PyJWKClient(metadata["jwks_uri"], timeout=5)
        signing_key = key_client.get_signing_key_from_jwt(id_token)
        claims: dict[str, Any] = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=self.settings.oidc_client_id,
            issuer=self.issuer,
            options={"require": ["exp", "iat", "iss", "sub", "aud", "nonce"]},
        )
        return claims

    def logout_url(self, *, post_logout_redirect_uri: str) -> str | None:
        endpoint = self._discover().get("end_session_endpoint")
        if not isinstance(endpoint, str):
            return None
        return f"{endpoint}?{urlencode({'post_logout_redirect_uri': post_logout_redirect_uri})}"
