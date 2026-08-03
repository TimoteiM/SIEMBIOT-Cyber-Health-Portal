from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from siembiot_worker.normalization.common import NormalizationError


def observation_type(payload: Mapping[str, Any]) -> str:
    check = str(payload.get("check", "")).lower()
    if not check:
        raise NormalizationError("missing_email_check")
    return f"email.{check}"
