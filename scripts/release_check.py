"""Whether this commit could be released, and exactly what is missing if not.

Milestone 11 step 3 asks for `make release-check` covering "lock, lint, types,
unit/integration/contract/E2E/accessibility/security/load/migration/image/smoke/SBOM/
provenance gates". This runs every one of those that exists and **names every one that
does not**, rather than reporting on the subset that happens to be implemented.

That distinction is the whole design. A release check that silently covers twelve of
fifteen gates and prints a green summary is worse than no release check: it converts
"we have not built accessibility testing" into "the release gates passed". The failure
mode this repository keeps finding is a confident number nobody recomputed, and a
release readiness report is the worst possible place for one.

**So this is red today, and that is the correct answer.** Two gates are genuinely not
implemented and one needs a running stack. Red here does not block anything -- this is
not a CI gate on every push, `make check` is that. It is an on-demand readiness report,
so a permanently accurate red costs nothing and tells the truth, where a green would
have to be a lie.

**It does not tag anything.** Milestone 11 step 5 is explicit that a release candidate is
tagged "only after accountable security/privacy/legal approvals and upstream
credential-exposure disposition". Those are decisions outside this script's authority and
outside this repository, so the script measures readiness and stops there. Deciding to
release is a person's job; establishing whether the evidence exists is this one's.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from shutil import which

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


class Outcome(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    #: Named by the plan, and no implementation exists. Never counted as a pass.
    ABSENT = "not implemented"
    #: Implemented, and could not run here. Also never counted as a pass: an unrun gate
    #: and a passing gate are the same colour only to somebody not paying attention.
    NOT_RUN = "not run here"


@dataclass
class Gate:
    #: The plan's own word for it, so this report and Milestone 11 can be read together.
    name: str
    why: str
    #: Commands to run in order. Empty means nothing implements this gate.
    commands: tuple[tuple[str, ...], ...] = ()
    #: What it would take, when nothing implements it. Printed instead of a result.
    absent: str = ""
    #: Gates that talk to a running deployment rather than to the repository.
    needs_stack: bool = False
    outcome: Outcome = Outcome.ABSENT
    detail: str = field(default="")


def uv(*args: str) -> tuple[str, ...]:
    return ("python", "-m", "uv", "run", "--frozen", *args)


def corepack(*args: str) -> tuple[str, ...]:
    """Resolved through `which`, the same way `verify_repo` does it.

    On Windows the executable is `corepack.cmd`, and `subprocess.run` without a shell
    will not find the bare name -- so a release check that hardcoded it would die three
    gates in, which is exactly what it did the first time this was run.
    """
    return (which("corepack") or "corepack", *args)


def repo_gate(name: str) -> tuple[str, ...]:
    """Run one of `verify_repo`'s gates by name.

    Delegated rather than duplicated. A release check that carried its own copy of the
    lint command would keep passing after the real one changed, which is the same shape
    as a stale alert rule.
    """
    return ("python", "scripts/verify_repo.py", "--only", name)


def production_stack_is_up() -> bool:
    """Whether the *production-like compose stack* is running.

    Not "is anything answering on port 8000". The smoke test asserts things only that
    stack can demonstrate -- that the API runs as an unprivileged user on a read-only
    filesystem, as the least-privileged role -- and it does so through
    `docker compose exec`. A development API on the same port passes none of those and
    is not meant to: reading one as the other would report a laptop as a hardened
    deployment, which is the most flattering wrong answer available here.
    """
    try:
        completed = subprocess.run(  # noqa: S603
            (
                "docker",
                "compose",
                "-f",
                "infra/compose/production-like.compose.yml",
                # Required for `ps`, not only for `up`. Every credential in that file is
                # written `${VAR:?...}`, so compose refuses to interpolate -- and refuses
                # even to *describe* the stack -- without them. The infrastructure gate's
                # own fail-closed rule, met here rather than worked around.
                "--env-file",
                ".env",
                "ps",
                "--status",
                "running",
                "--format",
                "{{.Service}}",
            ),
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return False
    return "api" in completed.stdout.split()


def gates() -> list[Gate]:
    """Every gate Milestone 11 step 3 names, in its order."""
    return [
        Gate("lock", "dependency locks resolve and are unchanged", (repo_gate("locks"),)),
        Gate("lint", "style and static rules", (repo_gate("lint"),)),
        Gate("types", "type checking across Python and TypeScript", (repo_gate("types"),)),
        Gate(
            "unit",
            "the whole Python and web suite",
            (uv("pytest", "-q"), corepack("pnpm", "--filter", "@siembiot/web", "test")),
        ),
        Gate(
            "integration",
            "suites that use a real PostgreSQL with row-level security",
            (uv("pytest", "tests/api", "tests/database", "tests/operations", "-q"),),
        ),
        Gate(
            "contract", "published contracts match what the code serves", (repo_gate("contracts"),)
        ),
        Gate(
            "E2E",
            "authorization and the disabled-model fallback, end to end",
            (
                uv("pytest", "tests/security/test_identity_tenant_authorization.py", "-q"),
                uv("pytest", "tests/agent_security/test_disabled_gateway_fallback.py", "-q"),
            ),
        ),
        Gate(
            "accessibility",
            "keyboard and screen-reader behaviour of the interface",
            absent=(
                "No automated accessibility suite exists. The interface is built to be "
                "accessible and has never been measured, which are different claims. "
                "Needs axe (or equivalent) over the rendered pages, plus the manual "
                "keyboard and screen-reader pass Milestone 10 step 5 asks for."
            ),
        ),
        Gate(
            "security",
            "the adversarial suites: agent scope, tenant isolation, network safety",
            (uv("pytest", "tests/agent_security", "tests/security", "tests/network", "-q"),),
        ),
        Gate(
            "load",
            "measured throughput rather than a reasoned guess",
            (
                uv(
                    "--env-file",
                    ".env",
                    "python",
                    "scripts/load_test.py",
                    "audit",
                    "--organizations",
                    "2",
                    "--writers",
                    "4",
                ),
            ),
        ),
        Gate("migration", "one head, and every migration applies", (repo_gate("migrations"),)),
        Gate(
            "image",
            "images pinned by digest, non-root, and the compose stack hardened",
            (repo_gate("images"), repo_gate("infrastructure")),
        ),
        Gate(
            "smoke",
            "the production-like stack answers, unprivileged and read-only",
            # Through `--env-file`, like the load gate. `smoke_test.py` reads
            # SIEMBIOT_WEB_PORT and SIEMBIOT_API_PORT from the environment, so without it
            # the check probes 3000 and 8000 regardless of where the stack was actually
            # published -- reporting whatever else is listening there, or nothing. It
            # failed exactly that way the first time this gate ran.
            (uv("--env-file", ".env", "python", "scripts/smoke_test.py"),),
            needs_stack=True,
        ),
        Gate("SBOM", "the inputs a bill of materials is generated from", (repo_gate("sbom"),)),
        Gate(
            "provenance",
            "signed artifacts, so a deployment can prove what it is running",
            absent=(
                "Nothing is signed. The container-scan workflow builds the images and "
                "the SBOM inputs are gated, but no attestation is produced and no "
                "identity signs one. Needs a decision this repository cannot make: "
                "where artifacts are published and which identity signs them. Keyless "
                "signing through the CI's OIDC identity would need no stored key."
            ),
        ),
    ]


def run(gate: Gate, *, stack_up: bool) -> None:
    if not gate.commands:
        gate.outcome = Outcome.ABSENT
        gate.detail = gate.absent
        return

    if gate.needs_stack and not stack_up:
        gate.outcome = Outcome.NOT_RUN
        gate.detail = "needs the production-like stack; `make prod-up`, then run this again"
        return

    for command in gate.commands:
        completed = subprocess.run(command, cwd=ROOT, check=False)  # noqa: S603
        if completed.returncode != 0:
            gate.outcome = Outcome.FAILED
            gate.detail = f"`{' '.join(command)}` exited {completed.returncode}"
            return

    gate.outcome = Outcome.PASSED


def report(checked: list[Gate]) -> int:
    width = max(len(gate.name) for gate in checked)
    print()
    print("Release readiness")
    print("=" * (width + 22))
    for gate in checked:
        print(f"  {gate.name.ljust(width)}  {gate.outcome.value}")
    print()

    passed = [g for g in checked if g.outcome is Outcome.PASSED]
    failed = [g for g in checked if g.outcome is Outcome.FAILED]
    absent = [g for g in checked if g.outcome is Outcome.ABSENT]
    unrun = [g for g in checked if g.outcome is Outcome.NOT_RUN]

    for gate in failed:
        print(f"FAILED       {gate.name}: {gate.detail}", file=sys.stderr)
    for gate in unrun:
        print(f"NOT RUN      {gate.name}: {gate.detail}", file=sys.stderr)
    for gate in absent:
        print(f"NOT BUILT    {gate.name}: {gate.detail}", file=sys.stderr)

    print(f"\n{len(passed)}/{len(checked)} gates passed.")

    if failed or absent or unrun:
        print(
            "\nThis commit is NOT releasable. That is a statement about evidence, not a "
            "judgement about the code:\n"
            "a gate that was never built and a gate that passed are not the same thing, "
            "and this report refuses to\nprint them the same colour.",
            file=sys.stderr,
        )
        # Tagging is deliberately not this script's business, and saying so here keeps
        # the reader from reading a green run as permission.
        print(
            "\nEven with every gate green, tagging a release candidate needs the "
            "approvals Milestone 11 step 5\nnames: security, privacy and legal sign-off, "
            "and the upstream credential-exposure disposition.",
            file=sys.stderr,
        )
        return 1

    print(
        "\nEvery gate this repository can run has passed. Tagging a release candidate "
        "still needs the\napprovals Milestone 11 step 5 names -- security, privacy and "
        "legal sign-off, and the upstream\ncredential-exposure disposition. This script "
        "does not tag anything."
    )
    return 0


def main() -> int:
    stack_up = production_stack_is_up()
    if not stack_up:
        print(
            "The production-like stack is not running; gates that need it are reported "
            "unrun rather than passed.\n"
        )

    checked = gates()
    for gate in checked:
        print(f"[release] {gate.name} -- {gate.why}", flush=True)
        run(gate, stack_up=stack_up)
    return report(checked)


if __name__ == "__main__":
    raise SystemExit(main())
