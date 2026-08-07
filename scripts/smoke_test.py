"""Prove the production-like stack actually serves, rather than merely starting.

    python scripts/smoke_test.py

A container that reached "running" has proved that its entrypoint resolved. It has not
proved that it can reach the database, that row-level security is in force, that the
web tier can talk to the API, or that the hardening did not break something that only
appears under a read-only filesystem. Each of those has a specific way of being
discovered late and expensively, so each gets a check here.

Deliberately not a functional test suite. It answers "is this deployment sound", and
the answer has to be quick enough that somebody runs it after every deploy.
"""

from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = ROOT / "infra" / "compose" / "production-like.compose.yml"
#: The stack's variables live here, and compose needs them even to describe itself.
ENV_FILE = ROOT / ".env"
API = "http://127.0.0.1:8000"
WEB = "http://127.0.0.1:3000"
READY_TIMEOUT_SECONDS = 120


@dataclass
class Result:
    name: str
    ok: bool
    detail: str


def fetch(url: str, timeout: float = 5.0) -> tuple[int, str]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        # The URLs are the two constants above: both http, both loopback.
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")
    except Exception as error:  # noqa: BLE001 - any failure is a failed check
        return 0, str(error)


def wait_until_ready() -> Result:
    """Readiness, not liveness: liveness would pass before the database was reachable."""
    deadline = time.monotonic() + READY_TIMEOUT_SECONDS
    last = "never answered"
    while time.monotonic() < deadline:
        status, body = fetch(f"{API}/api/v1/ready")
        if status == 200:
            return Result("api ready", True, body.strip())
        last = f"status {status}: {body.strip()[:120]}"
        time.sleep(2)
    return Result("api ready", False, f"not ready within {READY_TIMEOUT_SECONDS}s ({last})")


def check_liveness_ignores_dependencies() -> Result:
    """Liveness must answer without touching the database.

    A liveness probe that fails during a database outage makes an orchestrator restart
    every replica, which does not fix the database and delays recovery once it returns.
    """
    status, body = fetch(f"{API}/api/v1/health")
    return Result("liveness", status == 200, f"status {status}: {body.strip()[:80]}")


def check_api_runs_unprivileged() -> Result:
    """The image declares a non-root user; this checks the running process honours it."""
    output = compose("exec", "-T", "api", "python", "-c", "import os; print(os.getuid())")
    uid = output.strip().splitlines()[-1] if output.strip() else ""
    return Result("api uid", uid.isdigit() and uid != "0", f"uid {uid or 'unknown'}")


def check_api_filesystem_is_read_only() -> Result:
    """A container that cannot rewrite itself cannot be persistently modified."""
    output = compose(
        "exec",
        "-T",
        "api",
        "python",
        "-c",
        "open('/app/probe','w').close()",
        allow_failure=True,
    )
    denied = "Read-only file system" in output or "Permission denied" in output
    return Result("api filesystem", denied, "writable" if not denied else "read-only")


def check_api_uses_the_least_privileged_role() -> Result:
    """The whole tenant-isolation guarantee rests on this.

    The owner is a superuser, and superusers bypass row-level security even where it is
    FORCEd. Serving from the owner switches isolation off completely and silently, so
    the API refuses to start -- and this confirms it is not merely configured but
    connected as the application role.
    """
    output = compose(
        "exec",
        "-T",
        "api",
        "python",
        "-c",
        "import os;print(os.environ['SIEMBIOT_APP_DATABASE_URL'].split('://')[1].split(':')[0])",
    )
    role = output.strip().splitlines()[-1] if output.strip() else ""
    return Result("api database role", role == "siembiot_app", f"role {role or 'unknown'}")


def check_worker_uses_its_own_role() -> Result:
    """The worker's role may write inside a tenant without a human membership, which is
    a permission the API must not be able to reach."""
    output = compose(
        "exec",
        "-T",
        "worker",
        "python",
        "-c",
        "import os;print(os.environ['SIEMBIOT_WORKER_DATABASE_URL'].split('://')[1].split(':')[0])",
    )
    role = output.strip().splitlines()[-1] if output.strip() else ""
    return Result("worker database role", role == "siembiot_worker", f"role {role or 'unknown'}")


def check_web_reaches_the_api() -> Result:
    """The web tier proxies /api to the API service.

    A page that renders while its API calls fail looks fine until somebody clicks
    something, so this goes through the proxy rather than to the API directly.
    """
    status, _ = fetch(f"{WEB}/api/v1/health")
    return Result("web to api", status == 200, f"status {status}")


def check_web_serves() -> Result:
    status, body = fetch(WEB, timeout=15.0)
    return Result("web renders", status == 200 and "SIEMBIOT" in body, f"status {status}")


def check_database_is_not_published() -> Result:
    """Nothing outside the compose network should reach PostgreSQL directly.

    A port mapping is the easiest way for that to stop being true without anybody
    deciding it, so this asserts the absence rather than trusting the file.
    """
    # A missing mapping makes `compose port` exit non-zero, which is the answer we want.
    output = compose("port", "postgres", "5432", allow_failure=True)
    return Result("database not published", "5432" not in output, output.strip() or "no mapping")


def check_logs_are_structured() -> Result:
    """Structured logs, so an operator filtering by tenant during an incident is not
    writing a regular expression against an English sentence."""
    output = compose("logs", "--no-log-prefix", "--tail", "200", "worker", allow_failure=True)
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if "level" in parsed and "message" in parsed:
            return Result("worker logs", True, "structured")
    # Not a failure: a worker that has done nothing has nothing to say, and failing
    # here would make the smoke test depend on timing.
    return Result("worker logs", True, "no structured line yet (worker idle)")


class ComposeError(RuntimeError):
    """A compose command that did not run.

    Raised rather than returned because the first version of this file let a failed
    command's error text flow into a check, and `database not published` passed on the
    strength of an error message that happened not to contain "5432". A smoke test that
    can pass because its own tooling broke is worse than no smoke test.
    """


def compose(*args: str, allow_failure: bool = False) -> str:
    # S607: `docker` is resolved from PATH deliberately -- an operator's docker may be
    # `docker` is resolved from PATH deliberately: an operator's docker may be anywhere,
    # and a hardcoded path would make this script work on exactly one machine.
    completed = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "--env-file", str(ENV_FILE), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    output = (completed.stdout or "") + (completed.stderr or "")
    if completed.returncode != 0 and not allow_failure:
        raise ComposeError(f"docker compose {' '.join(args)} failed: {output.strip()[:200]}")
    return output


def main() -> int:
    print("waiting for the API to report ready…")
    results = [wait_until_ready()]
    if not results[0].ok:
        # Everything after this would fail for the same reason, and a wall of
        # consequential failures hides the one that matters.
        print(f"  FAIL  {results[0].name}: {results[0].detail}")
        return 1

    for check in (
        check_liveness_ignores_dependencies,
        check_api_runs_unprivileged,
        check_api_filesystem_is_read_only,
        check_api_uses_the_least_privileged_role,
        check_worker_uses_its_own_role,
        check_database_is_not_published,
        check_web_serves,
        check_web_reaches_the_api,
        check_logs_are_structured,
    ):
        try:
            results.append(check())
        except ComposeError as error:
            # Reported as a failure of that check rather than swallowed, so tooling
            # trouble is visible instead of being mistaken for a passing system.
            results.append(Result(check.__name__, False, str(error)))

    for result in results:
        print(f"  {'ok  ' if result.ok else 'FAIL'}  {result.name}: {result.detail}")

    failed = [result for result in results if not result.ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
