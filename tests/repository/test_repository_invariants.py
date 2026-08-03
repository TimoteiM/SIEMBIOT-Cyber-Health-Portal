from __future__ import annotations

import json
import re
import subprocess
import tomllib
import unittest
from pathlib import Path
from shutil import which

ROOT = Path(__file__).resolve().parents[2]
REQUIRED_FOUNDATION_FILES = {
    ".env.example",
    ".gitattributes",
    ".github/workflows/ci.yml",
    ".nvmrc",
    ".python-version",
    "Makefile",
    "CHANGELOG.md",
    "docs/development/setup.md",
    "package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "pyproject.toml",
    "scripts/verify_repo.py",
    "uv.lock",
}
FORBIDDEN_SUFFIXES = {".key", ".p12", ".pfx", ".pem", ".tsbuildinfo"}
FORBIDDEN_PARTS = {".next", ".venv", "__pycache__", "node_modules"}


def tracked_files() -> set[str]:
    git = which("git")
    if git is None:
        raise RuntimeError("git executable not found")
    result = subprocess.run(  # noqa: S603 - resolved executable with fixed arguments
        [git, "ls-files"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return {line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()}


class RepositoryInvariantTests(unittest.TestCase):
    def test_required_foundation_files_exist(self) -> None:
        missing = sorted(REQUIRED_FOUNDATION_FILES - tracked_files())
        self.assertEqual([], missing, f"missing Milestone 0 files: {missing}")

    def test_only_safe_environment_example_can_be_tracked(self) -> None:
        unsafe = sorted(
            path
            for path in tracked_files()
            if Path(path).name.startswith(".env") and path != ".env.example"
        )
        self.assertEqual([], unsafe, f"tracked environment files: {unsafe}")

    def test_generated_and_key_material_are_not_tracked(self) -> None:
        unsafe = []
        for relative in tracked_files():
            path = Path(relative)
            if path.suffix.lower() in FORBIDDEN_SUFFIXES or FORBIDDEN_PARTS.intersection(
                path.parts
            ):
                unsafe.append(relative)
        self.assertEqual([], sorted(unsafe), f"tracked generated/key files: {sorted(unsafe)}")

    def test_toolchains_are_exactly_pinned(self) -> None:
        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        python = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

        self.assertRegex(package["packageManager"], r"^pnpm@\d+\.\d+\.\d+\+sha512\.")
        self.assertRegex(package["engines"]["node"], r"^\d+\.\d+\.\d+$")
        self.assertEqual(package["engines"]["node"], (ROOT / ".nvmrc").read_text().strip())
        self.assertRegex(python["project"]["requires-python"], r"^==\d+\.\d+\.\*$")
        self.assertEqual(
            python["project"]["requires-python"].removeprefix("==").removesuffix(".*"),
            (ROOT / ".python-version").read_text().strip(),
        )

    def test_ci_actions_are_commit_pinned_and_run_bootstrap_and_verifier(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        actions = re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", workflow)
        self.assertGreaterEqual(len(actions), 4)
        self.assertTrue(all(re.search(r"@[0-9a-f]{40}$", action) for action in actions), actions)
        self.assertIn("node-version-file: .nvmrc", workflow)
        self.assertIn("python-version-file: .python-version", workflow)
        self.assertIn('version: "0.12.1"', workflow)
        self.assertIn("make bootstrap", workflow)
        self.assertIn("make check", workflow)
        self.assertIn("persist-credentials: false", workflow)

    def test_repository_uses_lf_for_reproducible_text_files(self) -> None:
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("* text=auto eol=lf", attributes)
        self.assertIn("*.cmd text eol=crlf", attributes)


if __name__ == "__main__":
    unittest.main()
