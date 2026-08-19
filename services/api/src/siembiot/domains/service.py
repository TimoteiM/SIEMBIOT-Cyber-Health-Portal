from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sqlalchemy.engine import RowMapping

from siembiot.contracts import DomainChallengeResponse, DomainResponse
from siembiot.domains.challenges import challenge_location


def domain_response(row: RowMapping | Mapping[str, Any]) -> DomainResponse:
    return DomainResponse(
        id=row["id"],
        organization_id=row["organization_id"],
        canonical_name=row["canonical_name"],
        unicode_display=row["unicode_display"],
        registrable_domain=row["registrable_domain"],
        warnings=row["warnings"],
        ownership_state=row["ownership_state"],
        declared_dkim_selectors=list(row["declared_dkim_selectors"] or ()),
        created_at=row["created_at"],
    )


def challenge_response(row: RowMapping | Mapping[str, Any]) -> DomainChallengeResponse:
    return DomainChallengeResponse(
        id=row["id"],
        domain_id=row["domain_id"],
        method=row["method"],
        state=row["state"],
        expires_at=row["expires_at"],
        attempts_remaining=max(0, row["max_attempts"] - row["attempts"]),
        verification_location=challenge_location(row["canonical_name"], row["method"]),
    )
