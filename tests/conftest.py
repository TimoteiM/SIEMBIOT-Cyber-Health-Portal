from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

API_SRC = Path(__file__).resolve().parents[1] / "services" / "api" / "src"
WORKER_SRC = Path(__file__).resolve().parents[1] / "services" / "worker" / "src"
sys.path.insert(0, str(API_SRC))
sys.path.insert(0, str(WORKER_SRC))

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = ROOT / "infra" / "compose" / "postgres.compose.yml"
PROJECT = "siembiot-m1-test"
OWNER_URL = "postgresql://siembiot_owner:placeholder@127.0.0.1:55432/siembiot_test"
OWNER_ALEMBIC_URL = "postgresql+psycopg://siembiot_owner:placeholder@127.0.0.1:55432/siembiot_test"
APP_URL = "postgresql://siembiot_app:placeholder@127.0.0.1:55432/siembiot_test"
WORKER_URL = "postgresql://siembiot_worker:placeholder@127.0.0.1:55432/siembiot_test"


def run(command: list[str], env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=ROOT, env=env, check=True)  # noqa: S603


@pytest.fixture(scope="session")
def postgres_database() -> Iterator[dict[str, str]]:
    compose = ["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE_FILE)]
    test_env = os.environ.copy()
    test_env.update(
        {
            "SIEMBIOT_POSTGRES_PORT": "55432",
            "SIEMBIOT_POSTGRES_DB": "siembiot_test",
            "SIEMBIOT_POSTGRES_OWNER_PASSWORD": "placeholder",
            "SIEMBIOT_POSTGRES_APP_PASSWORD": "placeholder",
            "SIEMBIOT_POSTGRES_WORKER_PASSWORD": "placeholder",
            "SIEMBIOT_DATABASE_URL": OWNER_ALEMBIC_URL,
            "SIEMBIOT_APP_DATABASE_URL": APP_URL,
        }
    )
    run([*compose, "up", "-d", "--wait"], test_env)
    try:
        run(
            [
                sys.executable,
                "-m",
                "alembic",
                "-c",
                "services/api/alembic.ini",
                "upgrade",
                "head",
            ],
            test_env,
        )
        # Migration 0009 creates siembiot_worker without a password, because a password
        # must never live in a migration. Deployments set one out of band; the tests
        # do it here so the worker role can actually be connected as and its isolation
        # asserted rather than assumed.
        import psycopg  # noqa: PLC0415

        with psycopg.connect(OWNER_URL, autocommit=True) as owner:
            owner.execute("ALTER ROLE siembiot_worker PASSWORD 'placeholder'")

        yield {"owner_url": OWNER_URL, "app_url": APP_URL, "worker_url": WORKER_URL}
    finally:
        run([*compose, "down", "--volumes", "--remove-orphans"], test_env)
