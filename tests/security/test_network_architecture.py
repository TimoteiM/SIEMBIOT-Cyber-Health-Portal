from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKER = ROOT / "services" / "worker" / "src"


#: Files outside `network_safety` that may hold a network client, and why.
#:
#: The boundary exists for one reason: this platform must not be talked into connecting
#: somewhere by data it collected. Every collector's destination is derived from evidence
#: -- a nameserver, an MX host, a redirect target -- so every collector goes through the
#: broker, which resolves, pins and re-authorizes the address at each hop.
#:
#: The model provider is not that. Its destination comes from `OPENAI_BASE_URL`, set by
#: whoever runs the deployment, and nothing collected can influence it. That puts it in
#: the same category as the database connection rather than the same category as a
#: collector, which is why it is listed here rather than being made to satisfy a broker
#: built for a different problem.
#:
#: Kept as a list, with a companion test that the exemption cannot grow silently: an
#: exemption nobody re-reads is how a boundary stops being one.
NETWORK_CLIENT_EXEMPTIONS = {
    "services/worker/src/siembiot_worker/agent_provider.py": (
        "Calls one operator-configured endpoint. The destination comes from environment "
        "configuration and never from collected evidence, so the redirect and address "
        "revalidation the broker performs have nothing to protect against here."
    ),
}


def test_the_exemptions_are_real_files_with_reasons() -> None:
    """An exemption list is a hole in a boundary, so it is checked like one."""
    for name, reason in NETWORK_CLIENT_EXEMPTIONS.items():
        assert (ROOT / name).is_file(), f"{name} is exempted and does not exist"
        assert len(reason) > 80, f"{name} is exempted without a usable reason"

    assert len(NETWORK_CLIENT_EXEMPTIONS) <= 2, (
        "the exemption list is growing. Each entry is a file that can reach the network "
        "without the address policy; three of them is a boundary in name only."
    )


def test_an_exempted_client_cannot_take_its_destination_from_evidence() -> None:
    """The property the exemption rests on.

    It is allowed to hold a network client *because* nothing collected can steer it. If
    the base URL ever came from a payload rather than from configuration, that reasoning
    collapses and the file belongs behind the broker like everything else.
    """
    source = (ROOT / "services/worker/src/siembiot_worker/agent_provider.py").read_text(
        encoding="utf-8"
    )

    # The destination is a constructor field with a constant default, set by the caller
    # from the environment. It is never read out of the data being sent.
    assert 'base_url: str = "https://api.openai.com/v1"' in source
    assert "data[" not in source, "the provider indexes into the payload it was given"
    assert "data.get" not in source, "the provider reads the payload it was given"


def test_direct_network_clients_are_confined_to_network_safety_boundary() -> None:
    forbidden = {
        "socket",
        "httpx",
        "requests",
        "urllib",
        "aiohttp",
        "dns",
        "ssl",
        "http",
        "smtplib",
        "ftplib",
        "telnetlib",
        "asyncio",
    }
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
                relative = path.relative_to(ROOT).as_posix()
                if relative not in NETWORK_CLIENT_EXEMPTIONS:
                    violations.append(relative)
    assert violations == []
