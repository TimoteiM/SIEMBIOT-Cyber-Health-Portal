"""The API must run as a role that row-level security actually applies to.

Every other tenant-isolation test in this suite passes the application role explicitly,
which is why none of them noticed that the running service resolved a *different* URL
from the environment and connected as the owner instead. The owner is a superuser, and
superusers bypass row-level security even where it is declared `FORCE`. Nothing fails
when that happens: every query succeeds and every organization can read every other
one's rows.

These tests cover the two halves of that gap -- which variable is read, and which role
is actually connected -- because a check on either alone can be satisfied while the
service is still wrong.
"""

from __future__ import annotations

import os
from unittest import mock

import psycopg
import pytest
from fastapi.testclient import TestClient
from siembiot.config import Settings
from siembiot.db import Database, LeastPrivilegeError
from siembiot.main import create_app


def test_settings_read_the_application_role_not_the_owner() -> None:
    """SIEMBIOT_DATABASE_URL is the migration credential and must not be served from."""
    with mock.patch.dict(
        os.environ,
        {
            "SIEMBIOT_DATABASE_URL": "postgresql+psycopg://siembiot_owner:x@db/siembiot",
            "SIEMBIOT_APP_DATABASE_URL": "postgresql+psycopg://siembiot_app:x@db/siembiot",
        },
        clear=True,
    ):
        settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert "siembiot_app" in settings.app_database_url
    assert "siembiot_owner" not in settings.app_database_url


def test_a_superuser_connection_is_refused(postgres_database: dict[str, str]) -> None:
    """The owner is a superuser, so no policy constrains it. Serving is not an option."""
    database = Database(
        postgres_database["owner_url"].replace("postgresql://", "postgresql+psycopg://")
    )
    try:
        with pytest.raises(LeastPrivilegeError) as raised:
            database.verify_least_privilege()
        assert "siembiot_owner" in str(raised.value)
    finally:
        database.close()


def test_the_application_role_is_accepted(postgres_database: dict[str, str]) -> None:
    database = Database(
        postgres_database["app_url"].replace("postgresql://", "postgresql+psycopg://")
    )
    try:
        database.verify_least_privilege()  # does not raise
    finally:
        database.close()


def test_the_service_refuses_to_start_as_the_owner(postgres_database: dict[str, str]) -> None:
    """A configuration mistake must stop the service, not quietly disable isolation."""
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        environment="development",
        app_database_url=postgres_database["owner_url"].replace(
            "postgresql://", "postgresql+psycopg://"
        ),
    )
    app = create_app(settings)
    with pytest.raises(LeastPrivilegeError), TestClient(app):
        pass


def test_row_level_security_is_forced_on_every_tenant_table(
    postgres_database: dict[str, str],
) -> None:
    """Enabled is not sufficient: without FORCE, the table's owner still bypasses it.

    Checked over every table carrying an organization_id so a table added later cannot
    join the schema without its isolation.
    """
    with psycopg.connect(postgres_database["owner_url"]) as owner:
        unprotected = owner.execute(
            """
            SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN information_schema.columns col
                 ON col.table_name = c.relname AND col.table_schema = n.nspname
            WHERE n.nspname = 'public'
              AND c.relkind = 'r'
              AND col.column_name = 'organization_id'
              AND NOT (c.relrowsecurity AND c.relforcerowsecurity)
            """
        ).fetchall()
    assert unprotected == [], f"tenant tables without forced row-level security: {unprotected}"


# -- liveness and readiness --------------------------------------------------


def test_liveness_answers_without_touching_the_database(
    postgres_database: dict[str, str],
) -> None:
    """The distinction that stops a dependency outage becoming a restart loop.

    Not alive restarts a replica; not ready removes it from rotation. A liveness probe
    that checks the database makes an orchestrator restart every replica during an
    outage, which does not fix the database and delays recovery once it returns.
    """
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        environment="development",
        app_database_url=postgres_database["app_url"].replace(
            "postgresql://", "postgresql+psycopg://"
        ),
    )
    app = create_app(settings)
    with TestClient(app) as client:
        # The engine is swapped on the existing Database rather than the object being
        # replaced: the endpoints close over that instance, so assigning a new one to
        # app.state would leave them talking to the original and the test would pass
        # without proving anything.
        from sqlalchemy import create_engine

        app.state.database.engine.dispose()
        # A short connect timeout: without one the unreachable host is retried until
        # the operating system gives up, and a two-minute test is a test people skip.
        app.state.database.engine = create_engine(
            "postgresql+psycopg://nobody:nothing@127.0.0.1:1/none?connect_timeout=1"
        )

        assert client.get("/api/v1/health").status_code == 200

        ready = client.get("/api/v1/ready")
        assert ready.status_code == 503
        assert ready.json()["ready"] is False
        # Named so an operator reading a failed probe knows which dependency to look
        # at, without correlating against logs.
        assert ready.json()["checks"]["database"] is False


def test_readiness_reports_the_database_when_it_is_reachable(
    postgres_database: dict[str, str],
) -> None:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        environment="development",
        app_database_url=postgres_database["app_url"].replace(
            "postgresql://", "postgresql+psycopg://"
        ),
    )
    with TestClient(create_app(settings)) as client:
        response = client.get("/api/v1/ready")
    assert response.status_code == 200
    assert response.json()["ready"] is True
