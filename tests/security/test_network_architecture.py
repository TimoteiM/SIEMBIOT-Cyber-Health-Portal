from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKER = ROOT / "services" / "worker" / "src"


def test_direct_network_clients_are_confined_to_network_safety_boundary() -> None:
    forbidden = {"socket", "httpx", "requests", "urllib", "aiohttp"}
    violations: list[str] = []
    for path in WORKER.rglob("*.py"):
        if "network_safety" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                names = {str(node.module).split(".")[0]}
            else:
                continue
            if names & forbidden:
                violations.append(path.relative_to(ROOT).as_posix())
    assert violations == []
