from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class CanonicalizationError(ValueError):
    pass


class CanonicalProjection(StrEnum):
    CONTENT_IDENTITY_V1 = "content-identity-v1"


_PROJECTION_FIELDS: dict[CanonicalProjection, tuple[str, ...]] = {
    CanonicalProjection.CONTENT_IDENTITY_V1: ("tenant", "payload"),
}


def _normalize(value: Any) -> Any:
    if value is None or isinstance(value, str | bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError("non_finite_number")
        return int(value) if value.is_integer() else value
    if isinstance(value, datetime):
        if value.utcoffset() is None:
            raise CanonicalizationError("naive_timestamp")
        normalized = value.astimezone(UTC)
        return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise CanonicalizationError("non_string_key")
        return {key: _normalize(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_normalize(item) for item in value]
    raise CanonicalizationError("unsupported_canonical_value")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        _normalize(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def parse_json(value: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise CanonicalizationError("duplicate_json_key")
            result[key] = item
        return result

    try:
        return json.loads(value, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as exc:
        raise CanonicalizationError("invalid_json") from exc


def canonical_hash(
    value: Mapping[str, Any], *, projection: CanonicalProjection | None = None
) -> str:
    identity: Mapping[str, Any] = value
    if projection is not None:
        fields = _PROJECTION_FIELDS[projection]
        missing = set(fields) - value.keys()
        if missing:
            raise CanonicalizationError("unknown_projection_field")
        identity = {field: value[field] for field in fields}
    return "sha256-v1:" + hashlib.sha256(canonical_json(identity)).hexdigest()
