from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID, uuid4

from siembiot_worker.network_safety.broker import NetworkSafetyBroker, PolicyAuthorizer
from siembiot_worker.network_safety.models import (
    BrokerCheckpoint,
    BrokerResult,
    PolicyDecision,
    VerificationFetchRequest,
)
from siembiot_worker.network_safety.resolver import SystemResolver
from siembiot_worker.network_safety.transport import BoundedHTTPTransport
from siembiot_worker.network_safety.url_policy import VerificationDestination
from sqlalchemy import Connection, text

from siembiot.domains.challenges import token_matches_digest

DecisionRecorder = Callable[[dict[str, object]], None]
NetworkBrokerFactory = Callable[[PolicyAuthorizer, DecisionRecorder], NetworkSafetyBroker]


def default_network_broker_factory(
    policy: PolicyAuthorizer, recorder: DecisionRecorder
) -> NetworkSafetyBroker:
    return NetworkSafetyBroker(
        resolver=SystemResolver(),
        transport=BoundedHTTPTransport(),
        policy=policy,
        record_decision=recorder,
    )


class DatabaseNetworkPolicy:
    """Re-read authoritative tenant state at every broker checkpoint."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def authorize(
        self,
        request: VerificationFetchRequest,
        checkpoint: BrokerCheckpoint,
        destination: VerificationDestination,
    ) -> PolicyDecision:
        del checkpoint, destination
        challenge_current = self._connection.execute(
            text(
                """
                SELECT 1 FROM domain_challenges
                WHERE id = :challenge_id AND organization_id = :organization_id
                  AND domain_id = :domain_id AND method = 'https_file'
                  AND state = 'pending' AND expires_at > now()
                """
            ),
            {
                "challenge_id": request.challenge_id,
                "organization_id": request.organization_id,
                "domain_id": request.domain_id,
            },
        ).scalar_one_or_none()
        if challenge_current is None:
            return PolicyDecision(False, "authorization_revoked")
        emergency = self._connection.execute(
            text(
                """
                SELECT 1 FROM emergency_controls
                WHERE deactivated_at IS NULL
                  AND (expires_at IS NULL OR expires_at > now())
                  AND (
                    scope = 'global'
                    OR (scope = 'organization' AND organization_id = :organization_id)
                    OR (scope = 'domain' AND organization_id = :organization_id
                        AND domain_id = :domain_id)
                    OR (scope = 'operation_class' AND organization_id = :organization_id
                        AND operation_class = 'https_verification')
                  )
                LIMIT 1
                """
            ),
            {
                "organization_id": request.organization_id,
                "domain_id": request.domain_id,
            },
        ).scalar_one_or_none()
        if emergency is not None:
            return PolicyDecision(False, "emergency_control_active")
        return PolicyDecision(True, "allowed")


@dataclass(frozen=True)
class HTTPSVerificationOutcome:
    matched: bool
    reason_code: str


class HTTPSVerificationService:
    def __init__(self, broker_factory: NetworkBrokerFactory) -> None:
        self._broker_factory = broker_factory

    def verify(
        self,
        connection: Connection,
        *,
        organization_id: UUID,
        domain_id: UUID,
        challenge_id: UUID,
        canonical_host: str,
        expected_digest: bytes,
    ) -> HTTPSVerificationOutcome:
        operation_id = uuid4()
        connection.execute(
            text(
                """
                INSERT INTO network_operations (
                    id, organization_id, domain_id, operation_class, status, started_at
                ) VALUES (
                    :id, :organization_id, :domain_id, 'https_verification', 'running', now()
                )
                """
            ),
            {
                "id": operation_id,
                "organization_id": organization_id,
                "domain_id": domain_id,
            },
        )
        decisions: list[dict[str, object]] = []
        broker = self._broker_factory(DatabaseNetworkPolicy(connection), decisions.append)
        result: BrokerResult = broker.fetch_https_verification(
            VerificationFetchRequest(
                organization_id=organization_id,
                domain_id=domain_id,
                challenge_id=challenge_id,
                canonical_host=canonical_host,
                authorized_redirect_hosts=(canonical_host,),
            )
        )
        matched = False
        reason = result.reason_code
        if result.allowed and result.status_code == 200:
            try:
                candidate = result.body.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                reason = "invalid_response"
            else:
                matched = token_matches_digest(candidate, expected_digest)
                reason = "token_matched" if matched else "token_not_found"
        elif result.allowed:
            reason = "http_status"
        status = "succeeded" if matched else "rejected"
        connection.execute(
            text(
                """
                UPDATE network_operations
                SET status = :status, reason_code = :reason, completed_at = now()
                WHERE id = :id
                """
            ),
            {"status": status, "reason": reason, "id": operation_id},
        )
        return HTTPSVerificationOutcome(matched, reason)
