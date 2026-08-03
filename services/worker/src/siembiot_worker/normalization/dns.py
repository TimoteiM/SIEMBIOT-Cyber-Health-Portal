from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from siembiot_worker.normalization.common import NormalizationError


def observation_type(payload: Mapping[str, Any]) -> str:
    record_type = str(payload.get("record_type", "")).lower()
    if not record_type:
        raise NormalizationError("missing_dns_record_type")
    return f"dns.{record_type}"
