from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def observation_type(payload: Mapping[str, Any]) -> str:
    return (
        "http.security_txt" if payload.get("check") == "security_text" else "http.security_headers"
    )
