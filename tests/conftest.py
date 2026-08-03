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
        yield {"owner_url": OWNER_URL, "app_url": APP_URL}
    finally:
        run([*compose, "down", "--volumes", "--remove-orphans"], test_env)
