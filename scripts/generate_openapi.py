from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "services" / "api" / "src"))

from siembiot.config import Settings  # noqa: E402  # type: ignore[reportMissingImports]
from siembiot.main import create_app  # noqa: E402  # type: ignore[reportMissingImports]

#: Never connected to. The observatory routes are mounted only where a public role is
#: configured, which would otherwise make the published contract depend on how a
#: particular deployment is set up -- so a client generated against staging would be
#: missing endpoints that production serves. The contract describes the whole surface;
#: whether a given deployment mounts all of it is a deployment question.
CONTRACT_ONLY_PUBLIC_URL = "postgresql+psycopg://siembiot_public@127.0.0.1:1/contract"


def main() -> int:
    destination = ROOT / "packages" / "contracts" / "openapi" / "private-api.v1.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    app = create_app(
        settings=Settings(
            _env_file=None,  # type: ignore[call-arg]
            public_database_url=CONTRACT_ONLY_PUBLIC_URL,
        )
    )
    destination.write_text(
        json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
