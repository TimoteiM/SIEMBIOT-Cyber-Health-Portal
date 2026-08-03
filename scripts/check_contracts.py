from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRACKED = (
    ROOT / "packages" / "contracts" / "openapi" / "private-api.v1.json",
    ROOT / "packages" / "contracts" / "src" / "private-api.v1.ts",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    before = {path: digest(path) for path in TRACKED}
    subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        [sys.executable, "scripts/generate_openapi.py"], cwd=ROOT, check=True
    )
    corepack = "corepack.cmd" if os.name == "nt" else "corepack"
    subprocess.run(  # noqa: S603 - fixed package-manager command and arguments
        [corepack, "pnpm", "--filter", "@siembiot/contracts", "generate"],
        cwd=ROOT,
        check=True,
    )
    after = {path: digest(path) for path in TRACKED}
    if before != after:
        print("Generated API contracts drifted; run `pnpm contracts:generate` and commit them.")
        return 1
    print("API contract drift check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
