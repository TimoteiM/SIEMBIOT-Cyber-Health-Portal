from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BOUNDARIES = (
    ROOT / "services" / "worker" / "src" / "siembiot_worker" / "adapters",
    ROOT / "services" / "worker" / "src" / "siembiot_worker" / "collectors",
    ROOT / "services" / "worker" / "src" / "siembiot_worker" / "collection",
)
FORBIDDEN_MODULES = {
    "aiohttp",
    "http",
    "httpx",
    "requests",
    "selenium",
    "socket",
    "ssl",
    "subprocess",
    "urllib",
}
FORBIDDEN_CALLS = {"create_connection", "getaddrinfo", "urlopen", "Popen", "run"}


def test_adapters_and_collectors_have_no_direct_network_or_process_capability() -> None:
    violations: list[str] = []
    for root in BOUNDARIES:
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules = {alias.name.split(".")[0] for alias in node.names}
                    if modules & FORBIDDEN_MODULES:
                        violations.append(f"{path.relative_to(ROOT)}:{node.lineno}:import")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    if node.module.split(".")[0] in FORBIDDEN_MODULES:
                        violations.append(f"{path.relative_to(ROOT)}:{node.lineno}:from")
                elif isinstance(node, ast.Call):
                    name = getattr(node.func, "attr", getattr(node.func, "id", ""))
                    if name in FORBIDDEN_CALLS:
                        violations.append(f"{path.relative_to(ROOT)}:{node.lineno}:call:{name}")
    assert violations == []


def test_collectors_depend_on_broker_protocols_not_fixture_implementation() -> None:
    collector_source = "\n".join(
        path.read_text(encoding="utf-8") for root in BOUNDARIES[:2] for path in root.rglob("*.py")
    )
    assert "FixtureInternetBroker" not in collector_source
    assert "SystemResolver" not in collector_source
    assert "SocketConnector" not in collector_source


def test_adapter_runtime_has_no_executable_callback_surface() -> None:
    runtime = (
        ROOT / "services" / "worker" / "src" / "siembiot_worker" / "adapters" / "runtime.py"
    ).read_text(encoding="utf-8")
    assert "operation()" not in runtime
    assert "Callable[[], Mapping" not in runtime
