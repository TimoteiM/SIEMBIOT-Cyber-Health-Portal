"""What the compose files may and may not declare.

The production-like stack is already hardened -- read-only root filesystems, dropped
capabilities, `no-new-privileges`, non-root users, no published database port. All of
that is currently prose in a comment and YAML that nothing enforces, which means it holds
until the first person who needs a container to write somewhere and reaches for the
quickest fix.

**This is the misconfiguration half of container scanning.** The other half -- known
vulnerabilities in image layers -- needs a vulnerability database and a network, so it
runs in CI where the scanner is installed deterministically (see `.github/workflows/
container-scan.yml`). Splitting them this way is deliberate: the rules that *can* run
everywhere, always, with no external tool, are the ones that must never be able to
silently not run.

Which is the danger this file was written against. A checker that parses a compose file,
finds nothing because the parse failed, and reports no problems is indistinguishable from
a checker that found nothing wrong. The alert-rules parser made exactly that mistake with
a folded scalar, and these compose files apply their hardening through a YAML anchor
(`<<: *hardening`) that a naive parser would not resolve -- so every service would look
unhardened, or the file would look empty and pass.

So every check here is preceded by an assertion that there was something to check:
`EXPECTED_SERVICES` names what must be found, and a file that yields fewer services than
that is a failure of this script rather than a clean bill of health.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "infra" / "compose"

#: The stack whose hardening is a claim worth enforcing. `local-stack.compose.yml` runs
#: the application on the host and containerises only infrastructure, so most of these
#: rules do not apply to it and pretending otherwise would produce noise.
PRODUCTION_LIKE = COMPOSE / "production-like.compose.yml"

#: What must be in that file for this script to believe it read it.
#:
#: The point of the list is not documentation. If a parser change, a rename or a
#: restructure means these are not found, the gate fails loudly instead of reporting a
#: hardened stack it never actually looked at.
EXPECTED_SERVICES = frozenset({"postgres", "redis", "api", "worker", "beat", "web"})

#: Services that run this project's own code, and must therefore be hardened. The
#: datastores are excluded: PostgreSQL needs to write to its data directory, and a
#: read-only root filesystem there is a container that does not start.
APPLICATION_SERVICES = frozenset({"api", "worker", "beat", "web"})

#: Never, in any compose file in this repository.
#:
#: Each of these hands a container the host. `privileged` needs no explanation; the
#: docker socket is root on the host with extra steps; host networking removes the
#: network boundary the address policy is enforced against, which would let a collector
#: reach services this platform has spent a milestone refusing to reach.
FORBIDDEN_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")


def load(path: Path) -> dict[str, Any]:
    """Parse with a real YAML implementation, so anchors and merge keys resolve.

    `yaml.safe_load` rather than `load`: a compose file is data, and the full loader can
    construct arbitrary Python objects from it.
    """
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} did not parse as a mapping")
    return document


def services(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    found = document.get("services")
    if not isinstance(found, dict):
        return {}
    return {name: value for name, value in found.items() if isinstance(value, dict)}


def check_the_parse_found_something(document: dict[str, Any], name: str) -> list[str]:
    """The check that makes every other check in this file mean anything.

    Run first and reported first. Without it, the honest answer to "what would this
    script report if it could not read the file at all?" is "a clean pass".
    """
    found = set(services(document))
    missing = EXPECTED_SERVICES - found
    if missing:
        return [
            f"{name}: expected services {sorted(missing)} were not found. Either they "
            "were removed -- in which case update EXPECTED_SERVICES deliberately -- or "
            "this script is not reading the file it thinks it is, and every check below "
            "is passing on nothing."
        ]
    return []


def check_hardening(document: dict[str, Any], name: str) -> list[str]:
    """Each service that runs our code must be unable to modify itself or escalate."""
    problems: list[str] = []
    for service, spec in sorted(services(document).items()):
        if service not in APPLICATION_SERVICES:
            continue
        where = f"{name}: {service}"

        if spec.get("read_only") is not True:
            problems.append(
                f"{where}: no read_only root filesystem. A container that cannot write to "
                "itself cannot be persistently modified by anything that gets into it."
            )

        options = [str(item) for item in spec.get("security_opt") or []]
        if "no-new-privileges:true" not in options:
            problems.append(
                f"{where}: no-new-privileges is not set. Without it a process can escalate "
                "through a setuid binary that happened to survive into the base image."
            )

        dropped = {str(item).upper() for item in spec.get("cap_drop") or []}
        if "ALL" not in dropped:
            problems.append(
                f"{where}: capabilities are not dropped. `cap_drop: [ALL]` and add back "
                "what is genuinely needed, rather than the other way round."
            )

        if spec.get("cap_add"):
            problems.append(
                f"{where}: adds capabilities {spec['cap_add']}. Nothing in this platform "
                "has needed one; if something now does, it needs a comment saying why."
            )

    return problems


def check_nothing_reaches_the_host(document: dict[str, Any], name: str) -> list[str]:
    """Applies to every compose file, including the development one.

    A developer stack that mounts the docker socket is still a developer machine one
    container escape away from being owned, and it is the file people copy from.
    """
    problems: list[str] = []
    for service, spec in sorted(services(document).items()):
        where = f"{name}: {service}"

        if spec.get("privileged"):
            problems.append(f"{where}: runs privileged, which is the whole host.")

        if str(spec.get("network_mode", "")).startswith("host"):
            problems.append(
                f"{where}: uses host networking, which removes the network boundary the "
                "address policy is enforced against."
            )

        if spec.get("pid") == "host":
            problems.append(f"{where}: shares the host PID namespace.")

        for volume in spec.get("volumes") or []:
            text = volume if isinstance(volume, str) else str(volume.get("source", ""))
            if any(socket in text for socket in FORBIDDEN_SOCKETS):
                problems.append(
                    f"{where}: mounts the docker socket, which is root on the host with "
                    "extra steps."
                )

    return problems


def check_the_database_is_not_published(document: dict[str, Any], name: str) -> list[str]:
    """The one port mapping that turns a private datastore into an exposed one.

    Deliberately checked rather than trusted to the comment already in the file: a port
    mapping is a one-line change that looks like a debugging convenience.
    """
    problems: list[str] = []
    for service in ("postgres", "redis"):
        spec = services(document).get(service)
        if spec and spec.get("ports"):
            problems.append(
                f"{name}: {service} publishes {spec['ports']}. Nothing outside the compose "
                "network has any business reaching it directly."
            )
    return problems


def check_images_are_pinned(document: dict[str, Any], name: str) -> list[str]:
    """A tag is a moving target, and the same rule the Dockerfiles are already held to.

    Services built from `infra/images` are exempt here because the Dockerfile gate pins
    their bases -- checking the same thing twice in two vocabularies would mean one of
    them going stale unnoticed.
    """
    problems: list[str] = []
    for service, spec in sorted(services(document).items()):
        image = spec.get("image")
        if image and "@sha256:" not in str(image) and not spec.get("build"):
            problems.append(
                f"{name}: {service} uses `{image}`, which is not pinned by digest. A tag "
                "is reproducible until somebody republishes it."
            )
    return problems


def run() -> list[str]:
    problems: list[str] = []

    if not PRODUCTION_LIKE.is_file():
        return [f"missing {PRODUCTION_LIKE.relative_to(ROOT)}: nothing to check"]

    document = load(PRODUCTION_LIKE)
    name = PRODUCTION_LIKE.name

    # First, and short-circuiting: every check below is meaningless if this one fails.
    found_nothing = check_the_parse_found_something(document, name)
    if found_nothing:
        return found_nothing

    problems += check_hardening(document, name)
    problems += check_the_database_is_not_published(document, name)
    problems += check_images_are_pinned(document, name)

    # The host-reaching rules apply to every compose file, not just the hardened one.
    for path in sorted(COMPOSE.glob("*.compose.yml")):
        problems += check_nothing_reaches_the_host(load(path), path.name)

    return problems


def main() -> int:
    problems = run()
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    if problems:
        print(f"infrastructure check failed: {len(problems)} problems", file=sys.stderr)
        return 1
    print("Infrastructure check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
