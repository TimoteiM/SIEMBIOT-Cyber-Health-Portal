from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, text


def append_audit_event(
    connection: Connection,
    *,
    organization_id: UUID | None,
    actor_type: str,
    actor_id: str,
    action: str,
    resource_type: str,
    resource_id: str,
    request_id: str,
    correlation_id: str,
    outcome: str,
    context: dict[str, Any] | None = None,
) -> None:
    connection.execute(
        text(
            """
            INSERT INTO audit_events (
                organization_id, actor_type, actor_id, action, resource_type, resource_id,
                request_id, correlation_id, outcome, context
            ) VALUES (
                :organization_id, :actor_type, :actor_id, :action, :resource_type, :resource_id,
                :request_id, :correlation_id, :outcome, CAST(:context AS jsonb)
            )
            """
        ),
        {
            "organization_id": organization_id,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "request_id": request_id,
            "correlation_id": correlation_id,
            "outcome": outcome,
            "context": json.dumps(context or {}, separators=(",", ":"), sort_keys=True),
        },
    )
