from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class NormalizationError(ValueError):
    pass


def bounded_payload(value: Any, *, depth: int = 0) -> Any:
    if depth > 4:
        raise NormalizationError("payload_depth_exceeded")
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        if not 0 <= value <= 1_000_000:
            raise NormalizationError("invalid_number")
        return value
    if isinstance(value, str):
        if len(value) > 1024:
            raise NormalizationError("string_limit_exceeded")
        return value
    if isinstance(value, Mapping):
        if len(value) > 64:
            raise NormalizationError("object_limit_exceeded")
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key).lower()
            if any(marker in name for marker in ("secret", "password", "token", "credential")):
                raise NormalizationError("sensitive_field_rejected")
            normalized[str(key)] = bounded_payload(item, depth=depth + 1)
        return normalized
    if isinstance(value, list | tuple):
        if len(value) > 128:
            raise NormalizationError("array_limit_exceeded")
        return [bounded_payload(item, depth=depth + 1) for item in value]
    raise NormalizationError("unsupported_payload_value")
