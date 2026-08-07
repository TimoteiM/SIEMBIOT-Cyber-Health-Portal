from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_script(name: str):  # type: ignore[no-untyped-def]
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class FoundationCommandContractTests(unittest.TestCase):
    def test_verifier_exposes_check_plan(self) -> None:
        verifier = load_script("verify_repo")
        self.assertTrue(callable(getattr(verifier, "build_checks", None)))

    def test_bootstrap_exposes_command_plan(self) -> None:
        bootstrap = load_script("bootstrap")
        self.assertTrue(callable(getattr(bootstrap, "build_commands", None)))

    def test_verifier_registers_every_foundation_gate(self) -> None:
        verifier = load_script("verify_repo")
        names = {check.name for check in verifier.build_checks(ROOT)}
        self.assertEqual(
            {
                "contracts",
                "diff",
                "docs",
                "i18n",
                "format",
                "images",
                "lint",
                "locks",
                "migrations",
                "phase0",
                "repository",
                "sbom",
                "secrets",
                "types",
                "unit",
            },
            names,
        )

    def test_bootstrap_uses_exact_tools_and_frozen_locks(self) -> None:
        bootstrap = load_script("bootstrap")
        commands = [" ".join(command.argv) for command in bootstrap.build_commands(ROOT)]
        rendered = "\n".join(commands)
        self.assertIn("uv==0.12.1", rendered)
        self.assertIn("pnpm@10.34.5", rendered)
        self.assertIn("uv sync --locked", rendered)
        self.assertIn("pnpm install --frozen-lockfile", rendered)

    @unittest.skipUnless(os.name == "nt", "Windows command shim behavior")
    def test_windows_commands_use_resolved_corepack_shim(self) -> None:
        bootstrap = load_script("bootstrap")
        verifier = load_script("verify_repo")
        bootstrap_corepack = [
            command.argv[0]
            for command in bootstrap.build_commands(ROOT)
            if "corepack" in command.argv[0].lower()
        ]
        verifier_corepack = [
            command[0]
            for check in verifier.build_checks(ROOT)
            for command in check.commands
            if "corepack" in command[0].lower()
        ]
        self.assertTrue(bootstrap_corepack)
        self.assertTrue(verifier_corepack)
        self.assertTrue(
            all(Path(command).suffix.lower() == ".cmd" for command in bootstrap_corepack)
        )
        self.assertTrue(
            all(Path(command).suffix.lower() == ".cmd" for command in verifier_corepack)
        )

    def test_node_runtime_mismatch_is_rejected(self) -> None:
        bootstrap = load_script("bootstrap")
        self.assertIsNone(bootstrap.node_version_error("v24.18.1", "24.18.1"))
        self.assertEqual(
            "Node.js 24.18.1 is required; found 20.20.0",
            bootstrap.node_version_error("v20.20.0", "24.18.1"),
        )

    def test_phase0_scans_only_repository_controlled_files(self) -> None:
        verifier = load_script("verify_phase0")
        files = verifier.repository_files(ROOT)
        self.assertIn("tests/repository/test_foundation_commands.py", files)
        self.assertFalse(any(path.startswith(".venv/") for path in files))
        self.assertFalse(any("node_modules/" in path for path in files))

    def test_secret_scanner_rejects_secret_and_allows_documented_placeholder(self) -> None:
        verifier = load_script("verify_repo")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            safe = root / ".env.example"
            safe.write_text("DATABASE_PASSWORD=CHANGEME_LOCAL_ONLY\n", encoding="utf-8")
            self.assertEqual([], verifier.find_secret_candidates([safe]))

            reference = root / "compose.yml"
            reference.write_text(
                "POSTGRES_PASSWORD: ${DATABASE_PASSWORD:?set in .env}\n", encoding="utf-8"
            )
            self.assertEqual([], verifier.find_secret_candidates([reference]))

            prose = root / "README.md"
            prose.write_text(
                "Report a possible secret: follow the incident runbook.\n", encoding="utf-8"
            )
            self.assertEqual([], verifier.find_secret_candidates([prose]))

            unsafe = root / "settings.py"
            unsafe.write_text("API_" + 'KEY="live-super-secret-value"\n', encoding="utf-8")
            self.assertEqual([unsafe], verifier.find_secret_candidates([unsafe]))

            annotated = root / "annotated_settings.py"
            annotated.write_text(
                "API_" + "KEY" + ': str | None = "live-super-secret-value"\n',
                encoding="utf-8",
            )
            self.assertEqual([annotated], verifier.find_secret_candidates([annotated]))

            optional = root / "optional_settings.py"
            optional.write_text("API_" + "KEY" + ": str | None = None\n", encoding="utf-8")
            self.assertEqual([], verifier.find_secret_candidates([optional]))


if __name__ == "__main__":
    unittest.main()
