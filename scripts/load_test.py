"""Measure what this platform actually does under concurrency.

    python scripts/load_test.py audit --organizations 4 --writers 16
    python scripts/load_test.py reads --url http://127.0.0.1:8000/metrics --clients 32

Milestone 10 asks for measured targets, and there were none: every performance claim in
this repository so far has been a reasoned guess. This produces numbers instead.

Two things are measured, because two things in the design deliberately trade throughput
for a guarantee and neither had been quantified:

**Audit writes take a per-organization lock.** Every event is chained to the one before
it, and the chain is built under `pg_advisory_xact_lock` so two concurrent writers cannot
read the same predecessor and fork it. That serializes writes within one organization by
construction. The question is not whether it serializes -- it must -- but whether the
resulting rate is anywhere near what a real institution generates, and whether writes for
*different* organizations still proceed in parallel as the design claims.

**Every tenant read passes through row-level security**, with policies that call
functions on each row. That cost is invisible in a single-user test.

Latency is reported at p50, p95 and p99. A mean would hide exactly the tail that a lock
produces, which is the thing worth seeing.
"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from uuid import UUID, uuid4

#: The audit table constrains both of these to 26 characters.
IDENTIFIER = "01JQ0000000000000000000001"


@dataclass(frozen=True)
class Sample:
    durations: list[float]
    failures: int
    elapsed: float

    def report(self, label: str, unit: str = "op") -> str:
        if not self.durations:
            return f"{label}: no successful {unit}s ({self.failures} failures)"
        ordered = sorted(self.durations)
        return "\n".join(
            [
                f"{label}",
                f"  {len(ordered)} {unit}s in {self.elapsed:.2f}s "
                f"= {len(ordered) / self.elapsed:.1f}/s",
                f"  p50 {_ms(ordered, 0.50)}  p95 {_ms(ordered, 0.95)}  p99 {_ms(ordered, 0.99)}"
                f"  max {ordered[-1] * 1000:.1f}ms",
                f"  failures: {self.failures}",
            ]
        )


def _ms(ordered: list[float], quantile: float) -> str:
    index = min(len(ordered) - 1, int(len(ordered) * quantile))
    return f"{ordered[index] * 1000:.1f}ms"


def database_url() -> str:
    url = os.environ.get("SIEMBIOT_DATABASE_URL")
    if not url:
        raise SystemExit("SIEMBIOT_DATABASE_URL is required (the owner role)")
    return url.replace("postgresql+psycopg://", "postgresql://")


# -- audit writes ---------------------------------------------------------------------


def seed_organizations(count: int) -> list[UUID]:
    import psycopg

    created: list[UUID] = []
    with psycopg.connect(database_url(), autocommit=True) as connection:
        for _ in range(count):
            organization_id, user_id = uuid4(), uuid4()
            connection.execute(
                "INSERT INTO users (id, identity_issuer, identity_subject, email, "
                "display_name) VALUES (%s, 'https://idp.local.test', %s, %s, 'Load test')",
                (str(user_id), str(user_id), f"{user_id}@load.test"),
            )
            connection.execute(
                "INSERT INTO organizations (id, name, slug, created_by_user_id) "
                "VALUES (%s, 'Load test', %s, %s)",
                (str(organization_id), f"lt-{organization_id.hex[:12]}", str(user_id)),
            )
            created.append(organization_id)
    return created


def write_events(organization_id: UUID, count: int) -> tuple[list[float], int]:
    """One connection, `count` audit inserts, timed individually."""
    import psycopg

    durations: list[float] = []
    failures = 0
    with psycopg.connect(database_url(), autocommit=True) as connection:
        for _ in range(count):
            started = time.perf_counter()
            try:
                connection.execute(
                    "INSERT INTO audit_events (organization_id, actor_type, actor_id, "
                    "action, resource_type, resource_id, request_id, correlation_id, "
                    "outcome, context) VALUES (%s, 'system', 'load', 'load.write', "
                    "'organization', %s, %s, %s, 'success', '{}')",
                    (str(organization_id), str(organization_id), IDENTIFIER, IDENTIFIER),
                )
                durations.append(time.perf_counter() - started)
            except Exception:  # noqa: BLE001 - counted, not diagnosed, under load
                failures += 1
    return durations, failures


def measure_audit(organizations: list[UUID], writers: int, per_writer: int) -> Sample:
    """`writers` threads writing at once, spread over the organizations given.

    One organization measures the lock; several measure whether the lock is per
    organization as intended, which is the difference between a bounded cost and a
    platform-wide bottleneck.
    """
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=writers) as pool:
        results = list(
            pool.map(
                lambda index: write_events(organizations[index % len(organizations)], per_writer),
                range(writers),
            )
        )
    elapsed = time.perf_counter() - started
    return Sample(
        [duration for durations, _ in results for duration in durations],
        sum(failures for _, failures in results),
        elapsed,
    )


def cleanup(organizations: list[UUID]) -> None:
    import psycopg

    with psycopg.connect(database_url(), autocommit=True) as connection:
        connection.execute("SELECT set_config('app.tenant_erasure', 'on', false)")
        for organization_id in organizations:
            connection.execute(
                "DELETE FROM audit_events WHERE organization_id = %s", (str(organization_id),)
            )
            connection.execute(
                "DELETE FROM memberships WHERE organization_id = %s", (str(organization_id),)
            )
            connection.execute(
                "DELETE FROM organizations WHERE id = %s", (str(organization_id),)
            )


# -- reads ----------------------------------------------------------------------------


def fetch(url: str, count: int) -> tuple[list[float], int]:
    durations: list[float] = []
    failures = 0
    for _ in range(count):
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310
                response.read()
            durations.append(time.perf_counter() - started)
        except (urllib.error.URLError, TimeoutError, OSError):
            failures += 1
    return durations, failures


def measure_reads(url: str, clients: int, per_client: int) -> Sample:
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=clients) as pool:
        results = list(pool.map(lambda _: fetch(url, per_client), range(clients)))
    elapsed = time.perf_counter() - started
    return Sample(
        [duration for durations, _ in results for duration in durations],
        sum(failures for _, failures in results),
        elapsed,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="audit write throughput and the chain's lock")
    audit.add_argument("--organizations", type=int, default=4)
    audit.add_argument("--writers", type=int, default=16)
    audit.add_argument("--per-writer", type=int, default=25)
    audit.add_argument("--keep", action="store_true", help="do not remove the test rows")

    reads = sub.add_parser("reads", help="read latency under concurrency")
    reads.add_argument("--url", required=True)
    reads.add_argument("--clients", type=int, default=16)
    reads.add_argument("--per-client", type=int, default=20)

    arguments = parser.parse_args()

    if arguments.command == "reads":
        print(measure_reads(arguments.url, arguments.clients, arguments.per_client).report("reads"))
        return 0

    organizations = seed_organizations(arguments.organizations)
    try:
        # The same total work, concentrated and spread. Reporting only one of these would
        # say nothing about whether the lock is per organization or global.
        concentrated = measure_audit(organizations[:1], arguments.writers, arguments.per_writer)
        print(concentrated.report(f"audit writes, {arguments.writers} writers, ONE organization"))
        print()
        spread = measure_audit(organizations, arguments.writers, arguments.per_writer)
        print(
            spread.report(
                f"audit writes, {arguments.writers} writers, "
                f"{len(organizations)} organizations"
            )
        )

        if concentrated.durations and spread.durations:
            gain = (len(spread.durations) / spread.elapsed) / (
                len(concentrated.durations) / concentrated.elapsed
            )
            print(f"\nspreading across {len(organizations)} organizations: {gain:.2f}x throughput")
            print(
                "A ratio near 1 would mean the lock is effectively global and the "
                "per-organization design is not delivering what it claims."
            )
    finally:
        if not arguments.keep:
            cleanup(organizations)
            print("\ntest rows removed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
