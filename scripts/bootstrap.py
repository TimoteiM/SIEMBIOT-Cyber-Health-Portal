"""Milestone 0 local bootstrap entry point."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from shutil import which

UV_VERSION = "0.12.1"
PNPM_VERSION = "10.34.5"


@dataclass(frozen=True)
class Command:
    name: str
    argv: tuple[str, ...]


def node_version_error(actual: str, expected: str) -> str | None:
    normalized = actual.strip().removeprefix("v")
    if normalized == expected:
        return None
    return f"Node.js {expected} is required; found {normalized}"


def build_commands(root: Path | None = None) -> tuple[Command, ...]:
    del root
    python = sys.executable
    corepack = which("corepack") or "corepack"
    return (
        Command("install-uv", (python, "-m", "pip", "install", "--user", f"uv=={UV_VERSION}")),
        Command("sync-python", (python, "-m", "uv", "sync", "--locked")),
        Command("activate-pnpm", (corepack, "prepare", f"pnpm@{PNPM_VERSION}", "--activate")),
        Command("sync-node", (corepack, "pnpm", "install", "--frozen-lockfile")),
    )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    expected_node = (root / ".nvmrc").read_text(encoding="utf-8").strip()
    node = which("node")
    if node is None:
        print(f"Node.js {expected_node} is required; node was not found", file=sys.stderr)
        return 1
    actual_node = subprocess.run(  # noqa: S603
        (node, "--version"), capture_output=True, check=False, text=True
    )
    runtime_error = node_version_error(actual_node.stdout, expected_node)
    if actual_node.returncode != 0 or runtime_error:
        print(runtime_error or "Unable to determine Node.js version", file=sys.stderr)
        return 1
    for command in build_commands(root):
        print(f"[bootstrap] {command.name}", flush=True)
        completed = subprocess.run(command.argv, cwd=root, check=False)  # noqa: S603
        if completed.returncode != 0:
            print(f"[bootstrap] failed: {command.name}", file=sys.stderr)
            return completed.returncode
    print("Bootstrap complete. Run `python scripts/verify_repo.py`.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
