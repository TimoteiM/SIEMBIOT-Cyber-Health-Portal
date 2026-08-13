"""The release readiness report, and the ways it could lie.

A release check is the single worst place in a repository for a confident wrong answer.
Everything else here is measured against it: if this prints "gates passed" while three of
them were never built, every other honest thing the project does is undone by the one
summary somebody actually forwards.

So the assertions are about what it must *refuse* to do. It must name every gate
Milestone 11 lists rather than the subset that happens to exist; it must never count an
unbuilt or unrun gate as a pass; and it must not tag anything, because Milestone 11 step 5
puts a release candidate behind approvals no script can give itself.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from release_check import Gate, Outcome, gates, report, run  # noqa: E402

PLAN = ROOT / "docs" / "plans" / "2026-08-03-production-implementation-plan.md"

#: The gates Milestone 11 step 3 names, in its own words.
#:
#: Written out rather than parsed from the plan: the plan is prose, and a parser over it
#: would be the thing that silently stopped matching. If the plan changes, this list
#: changes with it deliberately -- and the test below checks the plan still says so.
PLANNED = (
    "lock",
    "lint",
    "types",
    "unit",
    "integration",
    "contract",
    "E2E",
    "accessibility",
    "security",
    "load",
    "migration",
    "image",
    "smoke",
    "SBOM",
    "provenance",
)


def test_every_gate_the_plan_names_is_reported() -> None:
    """The property the whole script exists for.

    A release check covering twelve of fifteen gates and printing a green summary turns
    "we never built accessibility testing" into "the release gates passed".
    """
    reported = {gate.name for gate in gates()}
    missing = [name for name in PLANNED if name not in reported]

    assert not missing, f"{missing} are named by Milestone 11 and absent from the report"


def test_the_plan_still_names_these_gates() -> None:
    """Guards the list above against the plan moving underneath it.

    Without this, `PLANNED` is a copy that agrees with itself forever.
    """
    step_three = PLAN.read_text(encoding="utf-8")

    for name in ("accessibility", "provenance", "SBOM", "smoke"):
        assert name in step_three, f"the plan no longer mentions {name}; this list is stale"


def test_an_unbuilt_gate_is_never_a_pass() -> None:
    """The one that would hurt most if it were wrong."""
    gate = Gate("invented", "a gate nothing implements", absent="nothing implements this")

    run(gate, stack_up=True)

    # mypy proves the second half of this redundant once the first is asserted, which
    # is the strongest form the property can take: unbuilt and passed are not merely
    # different at runtime, they are unrelated in the type.
    assert gate.outcome is Outcome.ABSENT


def test_a_gate_that_could_not_run_is_never_a_pass() -> None:
    """An unrun gate and a passing gate are the same colour only to somebody not paying
    attention. This is the distinction the report exists to preserve."""
    gate = Gate("needs-it", "wants the stack", (("python", "--version"),), needs_stack=True)

    run(gate, stack_up=False)

    assert gate.outcome is Outcome.NOT_RUN


def test_the_report_fails_when_anything_is_unbuilt(capsys) -> None:  # type: ignore[no-untyped-def]
    """Green requires every gate, not every gate that exists."""
    checked = [
        Gate("built", "runs", (("python", "--version"),), outcome=Outcome.PASSED),
        Gate("unbuilt", "does not exist", absent="nothing implements this"),
    ]

    assert report(checked) == 1
    assert "NOT releasable" in capsys.readouterr().err


def test_the_report_fails_when_anything_was_not_run(capsys) -> None:  # type: ignore[no-untyped-def]
    checked = [
        Gate("built", "runs", (("python", "--version"),), outcome=Outcome.PASSED),
        Gate("skipped", "needs the stack", (), needs_stack=True, outcome=Outcome.NOT_RUN),
    ]

    assert report(checked) == 1
    assert "NOT RUN" in capsys.readouterr().err


def test_a_fully_green_report_still_refuses_to_authorise_a_release(capsys) -> None:  # type: ignore[no-untyped-def]
    """Even everything passing is not permission.

    Milestone 11 step 5 tags a release candidate "only after accountable
    security/privacy/legal approvals and upstream credential-exposure disposition". A
    green run that read as clearance would be this script overstepping the one boundary
    it was written to respect.
    """
    checked = [Gate("built", "runs", (("python", "--version"),), outcome=Outcome.PASSED)]

    assert report(checked) == 0
    printed = capsys.readouterr().out
    assert "does not tag anything" in printed
    assert "legal sign-off" in printed


def commands_in(path: Path) -> list[str]:
    """Every literal command in the file, as a space-joined string.

    Parsed rather than grepped, and that distinction was earned. The first version of
    this test searched the raw text for `"git tag"` -- which no real code would contain,
    because commands here are written as tuples: `("git", "tag", "rc1")`. A mutation that
    added exactly that passed all nine tests. The guard could only catch the spelling
    nobody would use.
    """
    import ast

    found: list[str] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Tuple | ast.List):
            parts = [
                element.value
                for element in node.elts
                if isinstance(element, ast.Constant) and isinstance(element.value, str)
            ]
            if parts:
                found.append(" ".join(parts))
    return found


def test_the_script_cannot_tag_or_publish_anything() -> None:
    """The separation between "measure readiness" and "declare a release" is the reason
    this script was allowed to be written before the reviews landed. If it ever grows a
    tag or a push, that separation is gone and this should stop the commit."""
    script = ROOT / "scripts" / "release_check.py"
    commands = commands_in(script)
    source = script.read_text(encoding="utf-8")

    for forbidden in ("git tag", "git push", "gh release", "docker push", "twine upload"):
        assert not any(forbidden in command for command in commands), (
            f"release_check.py runs `{forbidden}`. Measuring readiness and declaring a "
            "release are separate on purpose."
        )
        assert forbidden not in source, f"release_check.py mentions `{forbidden}`"


def test_that_guard_can_actually_see_a_tuple_command() -> None:
    """The mutation, kept rather than performed once by hand.

    Proves the parser above reads tuple-form commands, which is the form the guard failed
    to see the first time.
    """
    import ast
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as handle:
        handle.write('subprocess.run(("git", "tag", "rc1"), check=False)\n')
        written = Path(handle.name)

    try:
        assert ast.parse(written.read_text(encoding="utf-8"))
        assert any("git tag" in command for command in commands_in(written))
    finally:
        written.unlink()


def test_the_two_known_gaps_explain_what_they_need() -> None:
    """A gate reported as unbuilt with no explanation is a dead end for whoever picks it
    up. Both current gaps carry what closing them would take."""
    unbuilt = [gate for gate in gates() if not gate.commands]

    assert {gate.name for gate in unbuilt} == {"accessibility", "provenance"}
    for gate in unbuilt:
        assert len(gate.absent) > 80, f"{gate.name} says too little about what it needs"
