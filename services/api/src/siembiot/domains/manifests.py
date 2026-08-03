from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("manifest timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _validate_json(value: object) -> None:
    if value is None or isinstance(value, str | bool | int):
        return
    if isinstance(value, float):
        raise ValueError("canonical JSON does not allow floating-point values")
    if isinstance(value, list):
        for item in value:
            _validate_json(item)
        return
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("canonical JSON requires string object keys")
        for item in value.values():
            _validate_json(item)
        return
    raise ValueError("canonical JSON contains an unsupported value")


def canonical_manifest_bytes(value: dict[str, Any]) -> bytes:
    _validate_json(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def scope_manifest_payload(
    *,
    authorization_id: UUID,
    organization_id: UUID,
    actor_id: UUID,
    targets: list[dict[str, str]],
    policy_version: str,
    consent_version: str,
    consent_text: str,
    valid_from: datetime,
    valid_until: datetime,
    issued_at: datetime,
) -> dict[str, object]:
    ordered_targets = sorted(
        targets,
        key=lambda target: (
            target["canonical_host"],
            target["operation_class"],
            target["domain_id"],
        ),
    )
    return {
        "actor": {"type": "user", "id": str(actor_id)},
        "authorization_id": str(authorization_id),
        "consent": {
            "version": consent_version,
            "text": consent_text,
            "sha256": hashlib.sha256(consent_text.encode("utf-8")).hexdigest(),
        },
        "issued_at": _timestamp(issued_at),
        "manifest_version": "v1",
        "organization_id": str(organization_id),
        "policy_version": policy_version,
        "targets": ordered_targets,
        "valid_from": _timestamp(valid_from),
        "valid_until": _timestamp(valid_until),
    }


def manifest_allows_target(
    manifest: dict[str, object], canonical_host: str, operation_class: str
) -> bool:
    targets = manifest.get("targets")
    if not isinstance(targets, list):
        return False
    return any(
        isinstance(target, dict)
        and target.get("canonical_host") == canonical_host
        and target.get("operation_class") == operation_class
        for target in targets
    )


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def manifest_is_current(
    manifest: dict[str, object], *, now: datetime, authorization_state: str
) -> bool:
    if authorization_state != "active" or now.tzinfo is None:
        return False
    valid_from = _parse_timestamp(manifest.get("valid_from"))
    valid_until = _parse_timestamp(manifest.get("valid_until"))
    return (
        valid_from is not None
        and valid_until is not None
        and valid_from <= now.astimezone(UTC) < valid_until
    )
