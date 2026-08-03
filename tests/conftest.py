from __future__ import annotations

import sys
from pathlib import Path

API_SRC = Path(__file__).resolve().parents[1] / "services" / "api" / "src"
sys.path.insert(0, str(API_SRC))
