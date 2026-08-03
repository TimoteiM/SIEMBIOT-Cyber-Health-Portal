from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def observation_type(_: Mapping[str, Any]) -> str:
    return "http.security_headers"
