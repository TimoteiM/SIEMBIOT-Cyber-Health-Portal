from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from siembiot.auth import current_principal, require_trusted_origin
from siembiot.config import Settings
from siembiot.identity import NullIdentityResolver
from siembiot.main import create_app
from siembiot_worker.network_safety.broker import NetworkSafetyBroker, PolicyAuthorizer
from siembiot_worker.network_safety.models import (
    BrokerCheckpoint,
    NetworkBudget,
    TransportResponse,
)
from siembiot_worker.network_safety.url_policy import VerificationDestination
from test_domains import MutableTXTResolver, seed_owner


class FixedResolver:
    def resolve(self, host: str) -> tuple[str, ...]:
        assert host == "example.com"
        return ("8.8.8.8",)


class MutableVerificationTransport:
    def __init__(self) -> None:
        self.body = b""
        self.calls: list[VerificationDestination] = []

    def get(
        self,
        destination: VerificationDestination,
        address: str,
        budget: NetworkBudget,
        checkpoint: Callable[[BrokerCheckpoint], None],
    ) -> TransportResponse:
        assert address == "8.8.8.8"
        self.calls.append(destination)
        checkpoint(BrokerCheckpoint.AFTER_HEADERS)
        checkpoint(BrokerCheckpoint.BODY_CHUNK)
        return TransportResponse(200, {}, self.body)


def test_https_challenge_uses_policy_broker_and_exact_token(
    postgres_database: dict[str, str],
) -> None:
    organization_id, principal = seed_owner(postgres_database["owner_url"])
    transport = MutableVerificationTransport()

    def factory(
        policy: PolicyAuthorizer, recorder: Callable[[dict[str, object]], None]
    ) -> NetworkSafetyBroker:
        return NetworkSafetyBroker(
            resolver=FixedResolver(),
            transport=transport,
            policy=policy,
            record_decision=recorder,
        )

    settings = Settings(
        environment="test",
        public_base_url="https://portal.example.test",
        database_url=postgres_database["app_url"].replace("postgresql://", "postgresql+psycopg://"),
    )
    app = create_app(
        settings=settings,
        txt_resolver=MutableTXTResolver(),
        identity_resolver=NullIdentityResolver(),
        network_broker_factory=factory,
    )
    app.dependency_overrides[current_principal] = lambda: principal
    app.dependency_overrides[require_trusted_origin] = lambda: principal
    with TestClient(app, base_url="https://portal.example.test") as client:
        domain = client.post(
            f"/api/v1/organizations/{organization_id}/domains",
            json={"domain": "example.com"},
        ).json()
        challenge = client.post(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}/challenges",
            json={"method": "https_file"},
        ).json()
        transport.body = challenge["verification_token"].encode()

        verified = client.post(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}"
            f"/challenges/{challenge['id']}/verify"
        )
        assert verified.status_code == 200
        assert verified.json()["ownership_state"] == "verified"
        assert transport.calls[0].url == ("https://example.com/.well-known/tyche-verification.txt")


@pytest.mark.parametrize("control_scope", ["organization", "domain", "operation_class"])
def test_https_verification_is_blocked_and_recovers_after_kill_switch(
    postgres_database: dict[str, str], control_scope: str
) -> None:
    organization_id, principal = seed_owner(postgres_database["owner_url"])
    transport = MutableVerificationTransport()

    def factory(
        policy: PolicyAuthorizer, recorder: Callable[[dict[str, object]], None]
    ) -> NetworkSafetyBroker:
        return NetworkSafetyBroker(
            resolver=FixedResolver(),
            transport=transport,
            policy=policy,
            record_decision=recorder,
        )

    settings = Settings(
        environment="test",
        public_base_url="https://portal.example.test",
        database_url=postgres_database["app_url"].replace("postgresql://", "postgresql+psycopg://"),
    )
    app = create_app(
        settings=settings,
        network_broker_factory=factory,
        identity_resolver=NullIdentityResolver(),
    )
    app.dependency_overrides[current_principal] = lambda: principal
    app.dependency_overrides[require_trusted_origin] = lambda: principal
    with TestClient(app, base_url="https://portal.example.test") as client:
        domain = client.post(
            f"/api/v1/organizations/{organization_id}/domains",
            json={"domain": "example.com"},
        ).json()
        challenge = client.post(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}/challenges",
            json={"method": "https_file"},
        ).json()
        transport.body = challenge["verification_token"].encode()
        control_payload: dict[str, object] = {
            "scope": control_scope,
            "reason": "Confirmed destination safety incident",
        }
        if control_scope == "domain":
            control_payload["domain_id"] = domain["id"]
        if control_scope == "operation_class":
            control_payload["operation_class"] = "https_verification"
        control = client.post(
            f"/api/v1/organizations/{organization_id}/emergency-controls",
            json=control_payload,
        )
        assert control.status_code == 201

        blocked = client.post(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}"
            f"/challenges/{challenge['id']}/verify"
        )
        assert blocked.status_code == 409
        assert blocked.json()["error"]["code"] == "emergency_control_active"
        assert transport.calls == []

        stopped = client.post(
            f"/api/v1/organizations/{organization_id}/emergency-controls/"
            f"{control.json()['id']}/deactivate",
            json={"reason": "Incident reviewed and destination cleared"},
        )
        assert stopped.status_code == 200
        verified = client.post(
            f"/api/v1/organizations/{organization_id}/domains/{domain['id']}"
            f"/challenges/{challenge['id']}/verify"
        )
        assert verified.status_code == 200
