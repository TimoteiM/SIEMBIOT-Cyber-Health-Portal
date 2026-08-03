from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from siembiot_worker.evidence.canonical import canonical_hash
from siembiot_worker.evidence.models import EvidenceMode


class FingerprintCollisionError(ValueError):
    pass


def finding_identity(
    *,
    organization_id: str,
    asset_id: str,
    check_id: str,
    policy_hash: str,
    mode: EvidenceMode,
    material_evidence_key: str,
    attribution_state: str,
) -> dict[str, str]:
    if re.fullmatch(r"[a-z0-9][a-z0-9._:-]{0,127}", material_evidence_key) is None:
        raise ValueError("unsafe_material_evidence_key")
    return {
        "fingerprint_version": "fingerprint-v1",
        "organization_id": organization_id,
        "asset_id": asset_id,
        "check_id": check_id,
        "policy_hash": policy_hash,
        "mode": mode.value,
        "material_evidence_key": material_evidence_key,
        "attribution_state": attribution_state,
    }


def finding_fingerprint(**values: Any) -> str:
    return canonical_hash(finding_identity(**values))


class FingerprintRegistry:
    def __init__(self) -> None:
        self._identities: dict[str, bytes] = {}

    def register(
        self, identity: Mapping[str, Any], *, asserted_fingerprint: str | None = None
    ) -> str:
        normalized = finding_identity(**dict(identity))
        fingerprint = asserted_fingerprint or canonical_hash(normalized)
        representation = repr(sorted(normalized.items())).encode()
        previous = self._identities.get(fingerprint)
        if previous is not None and previous != representation:
            raise FingerprintCollisionError("finding_fingerprint_collision")
        if asserted_fingerprint is not None and asserted_fingerprint != canonical_hash(normalized):
            if previous is not None:
                raise FingerprintCollisionError("finding_fingerprint_collision")
            raise FingerprintCollisionError("invalid_asserted_fingerprint")
        self._identities[fingerprint] = representation
        return fingerprint
