"""Milestone 0 repository verification entry point."""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from shutil import which

TEXT_SUFFIXES = {"", ".json", ".md", ".py", ".toml", ".yaml", ".yml"}

#: The process each image must actually start, matched against its ENTRYPOINT. The
#: quotes are part of the token so `"worker"` does not match `siembiot_worker.celery_app`
#: -- which is exactly the substring that would make this check pass on the bug it
#: exists to catch.
ENTRYPOINT_COMMANDS = {
    "api": '"uvicorn"',
    "worker": '"worker"',
    "beat": '"beat"',
    "web": '"node"',
}
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
        Check("infrastructure"),
        Check("i18n"),
        Check("sbom"),
        Check("docs"),
        Check("diff", (("git", "diff", "--check"),)),
    )


#: Letters that appear in Romanian and in no language this codebase writes code in.
#: Their presence in a component is a user-visible string that never reached the
#: catalogue -- which renders as Romanian on an English page.
ROMANIAN_LETTERS = set("șțăîâȘȚĂÎÂ")

#: Where Romanian legitimately lives outside a component.
#:
#: `consent.ts` holds both languages on purpose: its exact wording is digested and stored
#: against each authorization, so it is versioned rather than translated freely, and it
#: says so at length in its own docstring.
I18N_EXEMPT = ("src/lib/i18n/", "src/lib/consent.ts", ".test.ts", ".test.tsx")


def check_i18n(root: Path) -> list[str]:
    """User-visible Romanian must come from the catalogue, not from a component.

    Found by running the product in English and reading the page: the domains screen
    rendered "AUTHORIZED SURFACE" above "Domenii verificate", because four strings were
    written straight into the component while everything around them was translated.
    Nothing failed, and the English catalogue was complete -- the keys simply were not
    being used, which no test of the catalogue can detect.

    **This catches some of the problem, not all of it.** It keys on letters that exist in
    Romanian and not in English, so "Acceptat" and "Respins" pass straight through. Six
    such strings were sitting in the same file as the two this found; the value of the
    check is that it points at the file, and a person reads the rest. A gate that claimed
    to prove the absence of hardcoded text would be worse than this one, because it would
    be believed.
    """
    problems: list[str] = []
    web = root / "apps" / "web" / "src"
    for path in sorted(web.rglob("*.ts*")):
        relative = path.relative_to(root).as_posix()
        if any(part in relative for part in I18N_EXEMPT):
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if ROMANIAN_LETTERS & set(line):
                problems.append(
                    f"{relative}:{number}: Romanian text outside the message catalogue: "
                    f"{line.strip()[:70]}"
                )
    return problems


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

        # An image that starts the wrong process. Found the hard way: beat.Dockerfile
        # carried a copy of the worker's ENTRYPOINT, so the stack ran two workers and no
        # scheduler. Nothing failed -- schedules simply never fired, and a domain that
        # quietly stops being assessed looks exactly like a domain with nothing wrong.
        # The file's own comments claimed it ran the scheduler, which is why reading it
        # was never going to catch this.
        expected = ENTRYPOINT_COMMANDS.get(path.stem)
        if expected:
            entrypoints = [line for line in final if line.upper().startswith("ENTRYPOINT")]
            if not entrypoints:
                problems.append(f"{name}: no ENTRYPOINT, so the image runs the base default")
            elif expected not in entrypoints[-1]:
                problems.append(
                    f"{name}: ENTRYPOINT does not start {expected!r}; "
                    f"{path.stem}.Dockerfile must run the process it is named for"
                )

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
            # A bare name after `=` in Python passes a variable, and an unquoted value in
            # that position cannot be anything else -- a literal requires quotes.
            # Skipping it does not weaken the check: a quoted value is still caught,
            # which was verified by adding one in three spellings and watching each fail
            # the gate.
            #
            # Written without an example of the quoted form, because an example of a
            # credential assignment is indistinguishable from a credential assignment --
            # the phase 0 scanner flagged this very file when the comment carried one.
            #
            # Without this the gate fired on the line that reads the key out of the
            # environment, which is the one place it is supposed to be read.
            if (
                path.suffix.lower() == ".py"
                and separator == "="
                and not match.group(0).rstrip().endswith(("'", '"'))
                and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", raw_value.rstrip(","))
                and '"' not in match.group(0).split(separator, 1)[1]
                and "'" not in match.group(0).split(separator, 1)[1]
            ):
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
            # The page that says the scheduler is required. Listed here because the
            # failure it documents -- everything healthy, nothing running -- is one an
            # operator cannot deduce from the rest of the runbook.
            root / "docs" / "operations" / "jobs.md",
        )
        return [
            f"missing documentation: {path.relative_to(root)}"
            for path in required
            if not path.is_file()
        ]
    if name == "images":
        return check_images(root)
    if name == "infrastructure":
        # The misconfiguration half of container scanning. Kept in the always-run gate
        # precisely because it needs no scanner and no network: a rule that cannot be
        # absent cannot silently stop running. The vulnerability half needs a database
        # and runs in `.github/workflows/container-scan.yml`.
        sys.path.insert(0, str(root / "scripts"))
        from check_infrastructure import run as check_infrastructure_run

        return check_infrastructure_run()
    if name == "i18n":
        return check_i18n(root)
    if name == "sbom":
        manifests = (root / "uv.lock", root / "pnpm-lock.yaml")
        return [f"SBOM input missing: {path.name}" for path in manifests if not path.is_file()]
    return []


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    checks = build_checks(root)

    # `--only <name>` runs one gate. Added for `release_check.py`, which reports each
    # gate separately and must not carry its own copy of the commands: a second
    # definition of "lint" would keep passing after this one changed.
    if "--only" in sys.argv:
        wanted = sys.argv[sys.argv.index("--only") + 1]
        checks = tuple(check for check in checks if check.name == wanted)
        if not checks:
            print(f"no such gate: {wanted}", file=sys.stderr)
            return 2

    for check in checks:
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
    # Counted, not written down. This line said "14/14" for as long as there were
    # fourteen gates and kept saying it after a fifteenth was added, which is the exact
    # failure mode this repository keeps finding: a confident number nobody recomputed.
    if "--only" in sys.argv:
        print(f"gate passed: {checks[0].name}")
        return 0
    print(f"Repository verification passed: {len(checks)}/{len(checks)} gates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
