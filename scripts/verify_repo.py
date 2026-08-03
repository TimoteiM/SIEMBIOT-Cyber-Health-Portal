"""Milestone 0 repository verification entry point."""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from shutil import which

TEXT_SUFFIXES = {"", ".json", ".md", ".py", ".toml", ".yaml", ".yml"}
PLACEHOLDERS = {
    "",
    "changeme",
    "changeme_local_only",
    "disabled",
    "example",
    "none",
    "null",
    "placeholder",
}
ASSIGNMENT = re.compile(
    r"(?im)^\s*['\"]?[a-z0-9_.-]*(?:password|passwd|secret|api[_-]?key|access[_-]?token)"
    r"[a-z0-9_.-]*['\"]?\s*([:=])\s*['\"]?([^\s'\"]+)"
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
            "format",
            (
                uv
                + (
                    "run",
                    "--frozen",
                    "ruff",
                    "format",
                    "--check",
                    "scripts",
                    "tests",
                    "services/api/src",
                    "services/worker/src",
                    "services/api/migrations",
                ),
            ),
        ),
        Check(
            "lint",
            (
                uv
                + (
                    "run",
                    "--frozen",
                    "ruff",
                    "check",
                    "scripts",
                    "tests",
                    "services/api/src",
                    "services/worker/src",
                    "services/api/migrations",
                ),
            ),
        ),
        Check(
            "types",
            (
                uv
                + (
                    "run",
                    "--frozen",
                    "mypy",
                    "scripts",
                    "tests",
                    "services/api/src",
                    "services/worker/src",
                    "services/api/migrations",
                ),
                (corepack, "pnpm", "--filter", "@siembiot/contracts", "typecheck"),
                (corepack, "pnpm", "--filter", "@siembiot/web", "typecheck"),
            ),
        ),
        Check(
            "unit",
            (
                uv + ("run", "--frozen", "pytest", "-q"),
                (corepack, "pnpm", "--filter", "@siembiot/web", "test"),
                (corepack, "pnpm", "--filter", "@siembiot/web", "build"),
            ),
        ),
        Check(
            "fixture-boundary",
            (
                uv + ("run", "--frozen", "python", "scripts/validate_fixture_pack.py"),
                uv
                + (
                    "run",
                    "--frozen",
                    "pytest",
                    "tests/security/test_collector_network_architecture.py",
                    "tests/security/test_no_external_fixture_network.py",
                    "-q",
                ),
            ),
        ),
        Check("policy", (uv + ("run", "--frozen", "python", "scripts/validate_policy.py"),)),
        Check(
            "methodology",
            (
                uv + ("run", "--frozen", "python", "scripts/reproduce_methodology.py"),
                uv
                + (
                    "run",
                    "--frozen",
                    "pytest",
                    "tests/security/test_fixture_evidence_boundary.py",
                    "-q",
                ),
            ),
        ),
        Check("contracts", (uv + ("run", "--frozen", "python", "scripts/check_contracts.py"),)),
        Check(
            "migrations",
            (uv + ("run", "--frozen", "alembic", "-c", "services/api/alembic.ini", "heads"),),
        ),
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
            separator, raw_value = match.group(1), match.group(2)
            assignment_name = match.group(0).split(separator, maxsplit=1)[0].lower()
            if "hash" in assignment_name:
                continue
            if raw_value.startswith(("${", "$env:", "%")):
                continue
            if path.suffix.lower() == ".py" and separator == ":":
                line_end = text.find("\n", match.end())
                remainder = text[match.end() : line_end if line_end >= 0 else len(text)]
                annotated_value = re.search(r"=\s*['\"]?([^\s'\"]+)", remainder)
                if annotated_value is None:
                    continue
                raw_value = annotated_value.group(1)
            if path.suffix.lower() == ".py" and "(" in raw_value:
                continue
            value = raw_value.strip("<>{}[]()\"',").lower()
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
    gate_count = len(build_checks(root))
    print(f"Repository verification passed: {gate_count}/{gate_count} gates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
