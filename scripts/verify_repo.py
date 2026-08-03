"""Milestone 0 repository verification entry point."""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from shutil import which

TEXT_SUFFIXES = {"", ".json", ".md", ".py", ".toml", ".yaml", ".yml"}
PLACEHOLDERS = {"", "changeme", "changeme_local_only", "disabled", "example", "placeholder"}
ASSIGNMENT = re.compile(
    r"(?im)^\s*['\"]?[a-z0-9_.-]*(?:password|passwd|secret|api[_-]?key|access[_-]?token)"
    r"[a-z0-9_.-]*['\"]?\s*[:=]\s*['\"]?([^\s'\"]+)"
)
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")


@dataclass(frozen=True)
class Check:
    name: str
    commands: tuple[tuple[str, ...], ...] = ()


def build_checks(root: Path | None = None) -> tuple[Check, ...]:
    del root
    python = sys.executable
    uv = (python, "-m", "uv")
    corepack = which("corepack") or "corepack"
    return (
        Check("phase0", ((python, "scripts/verify_phase0.py"),)),
        Check("repository", ((python, "tests/repository/test_repository_invariants.py", "-v"),)),
        Check(
            "locks", (uv + ("lock", "--check"), (corepack, "pnpm", "install", "--frozen-lockfile"))
        ),
        Check(
            "format", (uv + ("run", "--frozen", "ruff", "format", "--check", "scripts", "tests"),)
        ),
        Check("lint", (uv + ("run", "--frozen", "ruff", "check", "scripts", "tests"),)),
        Check("types", (uv + ("run", "--frozen", "mypy", "scripts", "tests"),)),
        Check("unit", (uv + ("run", "--frozen", "pytest", "-q"),)),
        Check("contracts"),
        Check("migrations"),
        Check("secrets"),
        Check("images"),
        Check("sbom"),
        Check("docs"),
        Check("diff", (("git", "diff", "--check"),)),
    )


def find_secret_candidates(files: list[Path]) -> list[Path]:
    candidates: list[Path] = []
    for path in files:
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        unsafe = PRIVATE_KEY.search(text) is not None
        for match in ASSIGNMENT.finditer(text):
            value = match.group(1).strip("<>{}[]()\"'").lower()
            if value not in PLACEHOLDERS and not value.startswith(
                ("changeme", "example", "placeholder")
            ):
                unsafe = True
        if unsafe:
            candidates.append(path)
    return candidates


def tracked_files(root: Path) -> list[Path]:
    completed = subprocess.run(  # noqa: S603, S607
        ("git", "ls-files", "-z"),
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [root / item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]


def verify_internal_gate(name: str, root: Path) -> list[str]:
    if name == "secrets":
        return [
            f"possible secret: {path.relative_to(root)}"
            for path in find_secret_candidates(tracked_files(root))
        ]
    if name == "docs":
        required = (
            root / "docs" / "product" / "phase0-review.md",
            root / "docs" / "development" / "setup.md",
        )
        return [
            f"missing documentation: {path.relative_to(root)}"
            for path in required
            if not path.is_file()
        ]
    if name == "contracts" and (root / "packages" / "contracts").exists():
        return ["contracts were introduced before Milestone 1"]
    if name == "migrations" and any(root.glob("services/**/migrations/*")):
        return ["migrations were introduced before Milestone 1"]
    if name == "images" and any(root.glob("**/Dockerfile*")):
        return ["container images were introduced before Milestone 10"]
    if name == "sbom":
        manifests = (root / "uv.lock", root / "pnpm-lock.yaml")
        return [f"SBOM input missing: {path.name}" for path in manifests if not path.is_file()]
    return []


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    for check in build_checks(root):
        print(f"[check] {check.name}", flush=True)
        errors = verify_internal_gate(check.name, root)
        if errors:
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        for command in check.commands:
            completed = subprocess.run(command, cwd=root, check=False)  # noqa: S603
            if completed.returncode != 0:
                print(f"[check] failed: {check.name}", file=sys.stderr)
                return completed.returncode
    print("Repository verification passed: 14/14 gates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
