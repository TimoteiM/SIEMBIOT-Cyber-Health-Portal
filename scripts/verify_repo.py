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
            "contracts",
            (
                uv + ("run", "--frozen", "python", "scripts/check_contracts.py"),
                uv
                + ("run", "--frozen", "python", "scripts/generate_provider_matrix.py", "--check"),
                uv + ("run", "--frozen", "python", "scripts/reproduce_methodology.py", "--check"),
            ),
        ),
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


def check_images(root: Path) -> list[str]:
    """Container images must be reproducible and must not run as root.

    This gate used to refuse any Dockerfile at all, because images were Milestone 10
    work and an image appearing early would have been unreviewed. Now that they exist,
    refusing them would only teach people to delete the check, so it states the
    invariants instead:

    *Bases pinned by digest.* A tag is a moving target. Pinning by tag makes a build
    reproducible right up until somebody republishes the tag, which is also how an
    unnoticed base change reaches production.

    *A non-root user, declared last.* A `USER` line above a later `COPY --chown` or
    `RUN` still ends up running as root, so the position matters as much as the
    presence. Checked by requiring it in the final stage.

    An image without a Dockerfile here is not a failure -- the repository may
    legitimately have none -- but one that exists must meet both.
    """
    problems: list[str] = []
    dockerfiles = sorted(root.glob("infra/images/*.Dockerfile"))
    stray = [
        path
        for path in root.glob("**/Dockerfile*")
        if "node_modules" not in path.parts and ".git" not in path.parts
    ]
    for path in stray:
        problems.append(
            f"{path.relative_to(root)}: container images belong in infra/images/*.Dockerfile "
            "so they are reviewed together"
        )

    for path in dockerfiles:
        name = path.relative_to(root)
        lines = path.read_text(encoding="utf-8").splitlines()
        directives = [line.strip() for line in lines if line.strip()]

        for line in directives:
            if line.upper().startswith("FROM ") and "@sha256:" not in line:
                problems.append(f"{name}: base image is not pinned by digest: {line}")
            if line.upper().startswith("COPY --FROM=") and "@sha256:" not in line:
                # A COPY --from that names an image rather than a build stage brings in
                # an unpinned artefact by the back door.
                source = line.split("=", 1)[1].split()[0]
                if not any(
                    directive.upper().startswith("FROM ")
                    and f" AS {source}".upper() in directive.upper()
                    for directive in directives
                ):
                    problems.append(f"{name}: unpinned image in COPY --from: {source}")

        # The final stage is what actually runs, so that is where USER has to appear.
        starts = [
            index for index, line in enumerate(directives) if line.upper().startswith("FROM ")
        ]
        final = directives[starts[-1] :] if starts else directives
        users = [line for line in final if line.upper().startswith("USER ")]
        if not users:
            problems.append(f"{name}: final stage has no USER, so it runs as root")
        elif users[-1].split()[1].split(":")[0] in {"root", "0"}:
            problems.append(f"{name}: final stage runs as root")

    return problems


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
            root / "docs" / "providers" / "matrix.md",
        )
        return [
            f"missing documentation: {path.relative_to(root)}"
            for path in required
            if not path.is_file()
        ]
    if name == "images":
        return check_images(root)
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
