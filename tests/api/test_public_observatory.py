"""The unauthenticated read side, and the connection it is served by.

The interesting property is not that these routes return data. It is that they are served
by a connection which cannot reach tenant tables, that the service refuses to start if
that stops being true, and that they are not served at all unless somebody configured
them deliberately.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "api" / "src"))

from siembiot.config import Settings  # noqa: E402
from siembiot.db import LeastPrivilegeError  # noqa: E402
from siembiot.main import create_app  # noqa: E402

DIGEST = "a" * 64


def alchemy(url: str) -> str:
    return url.replace("postgresql://", "postgresql+psycopg://")


def client_for(
    postgres_database: dict[str, str], *, public_url: str | None = "public"
) -> TestClient:
    """`public_url=None` leaves the observatory unconfigured, which is the default."""
    resolved = (
        None
        if public_url is None
        else alchemy(postgres_database["public_url" if public_url == "public" else public_url])
    )

    class NullResolver:
        def resolve(self, request: object) -> None:
            return None

    return TestClient(
        create_app(
            settings=Settings(
                environment="test",
                app_database_url=alchemy(postgres_database["app_url"]),
                public_database_url=resolved,
            ),
            identity_resolver=NullResolver(),
        )
    )


def publish(owner_url: str, host: str, *, band: str | None = "managed") -> None:
    with psycopg.connect(owner_url, autocommit=True) as owner:
        profile_id = owner.execute(
            "INSERT INTO observatory.profiles (registrable_domain, band, "
            "coverage_percentage, methodology_version, policy_digest, observed_at) "
            "VALUES (%s, %s, 88.0, '1.0.0', %s, now()) RETURNING id",
            (host, band, DIGEST),
        ).fetchone()
        assert profile_id is not None
        owner.execute(
            "INSERT INTO observatory.profile_checks (profile_id, check_id, result) "
            "VALUES (%s, 'B.dmarc_enforced', 'pass')",
            (profile_id[0],),
        )


# -- the connection these routes are served by -------------------------------


def test_the_service_refuses_to_start_if_public_routes_could_reach_tenant_data(
    postgres_database: dict[str, str],
) -> None:
    """The failure this check exists for is silent.

    Serving public pages from the application connection breaks nothing, returns the
    same bytes, and leaves the schema separation meaningful only on paper.
    """
    with pytest.raises(LeastPrivilegeError, match="USAGE on the schema"):
        # Pointed at the application role, which has USAGE on the tenant schema.
        with client_for(postgres_database, public_url="app_url"):
            pass


def test_the_observatory_is_not_served_when_it_is_not_configured(
    postgres_database: dict[str, str],
) -> None:
    """Failing closed is the right default for the one part that speaks in public."""
    with client_for(postgres_database, public_url=None) as client:
        assert client.get("/api/v1/public/observatory").status_code == 404
        document = client.get("/openapi.json").json()
    assert not [path for path in document["paths"] if path.startswith("/api/v1/public")]


def test_the_public_connection_really_cannot_read_tenant_tables(
    postgres_database: dict[str, str],
) -> None:
    """Asserted through the app's own engine, not a separate connection.

    A test that opens its own psycopg connection proves something about the role; this
    proves something about the object the routes actually use.
    """
    with client_for(postgres_database) as client:
        engine = client.app.state.public_database.engine  # type: ignore[attr-defined]
        with engine.connect() as connection:
            from sqlalchemy import text  # noqa: PLC0415

            with pytest.raises(Exception, match="permission denied|does not exist"):
                connection.execute(text("SELECT count(*) FROM public.organizations"))


# -- what the routes return --------------------------------------------------


def test_a_published_profile_is_readable_with_no_session(
    postgres_database: dict[str, str],
) -> None:
    host = f"obs-{uuid4().hex[:10]}.example.ro"
    publish(postgres_database["owner_url"], host)

    with client_for(postgres_database) as client:
        body = client.get(f"/api/v1/public/observatory/{host}").json()

    assert body["registrable_domain"] == host
    assert body["band"] == "managed"
    # The title comes from the versioned catalogue rather than being stored beside the
    # result, so a public page needs no copy of the catalogue to render a sentence.
    # Compared against the catalogue rather than against a literal: a copy of the wording
    # here would be a second place it lives, and the two would drift.
    from siembiot.check_metadata import load_check_metadata  # noqa: PLC0415

    expected = load_check_metadata()["B.dmarc_enforced"]
    assert body["checks"] == [
        {
            "check_id": "B.dmarc_enforced",
            "result": "pass",
            "title_ro": expected.title_ro,
            "title_en": expected.title_en,
        }
    ]
    # Traceable to the rules that produced it, so a dispute has something to point at.
    assert body["methodology_version"] == "1.0.0"
    assert body["policy_digest"] == DIGEST


def test_a_public_response_carries_no_score_and_no_identifier(
    postgres_database: dict[str, str],
) -> None:
    """A score invites a league table of public institutions; an identifier invites a
    join back to private records."""
    host = f"obs-{uuid4().hex[:10]}.example.ro"
    publish(postgres_database["owner_url"], host)

    with client_for(postgres_database) as client:
        raw = client.get(f"/api/v1/public/observatory/{host}").text
        body = client.get(f"/api/v1/public/observatory/{host}").json()

    assert "score" not in body
    assert not [key for key in body if key.endswith("_id") and key != "policy_digest"]
    import re  # noqa: PLC0415

    assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}", raw)


def test_a_withdrawn_profile_is_indistinguishable_from_one_that_never_existed(
    postgres_database: dict[str, str],
) -> None:
    """Otherwise anybody can enumerate which institutions agreed and then changed their
    mind, which is a fact about them that they withdrew."""
    host = f"obs-{uuid4().hex[:10]}.example.ro"
    publish(postgres_database["owner_url"], host)
    with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
        owner.execute("DELETE FROM observatory.profiles WHERE registrable_domain = %s", (host,))

    with client_for(postgres_database) as client:
        withdrawn = client.get(f"/api/v1/public/observatory/{host}")
        never = client.get("/api/v1/public/observatory/never-existed.example.ro")

    def without_request_id(response: object) -> dict[str, Any]:
        body: dict[str, Any] = dict(response)  # type: ignore[call-overload]
        error = dict(body["error"])
        error.pop("request_id")
        return {**body, "error": error}

    assert withdrawn.status_code == never.status_code == 404
    assert without_request_id(withdrawn.json()) == without_request_id(never.json())


def test_a_profile_without_a_band_publishes_none_rather_than_a_label(
    postgres_database: dict[str, str],
) -> None:
    host = f"obs-{uuid4().hex[:10]}.example.ro"
    publish(postgres_database["owner_url"], host, band=None)

    with client_for(postgres_database) as client:
        body = client.get(f"/api/v1/public/observatory/{host}").json()

    assert body["band"] is None
    assert body["coverage_percentage"] == 88.0


def test_published_pages_are_not_cached_so_a_withdrawal_is_immediate(
    postgres_database: dict[str, str],
) -> None:
    """The cache header *is* the suppression latency.

    An earlier draft of this router set `max-age=60`, which would have made a minute the
    real answer to "how quickly does a withdrawal take effect" -- the row is deleted
    synchronously, but a response already handed to a cache is beyond recall until it
    expires. `no-store` makes the synchronous delete mean what it says.
    """
    host = f"obs-{uuid4().hex[:10]}.example.ro"
    publish(postgres_database["owner_url"], host)

    with client_for(postgres_database) as client:
        response = client.get(f"/api/v1/public/observatory/{host}")
        assert response.headers["cache-control"] == "no-store"

        with psycopg.connect(postgres_database["owner_url"], autocommit=True) as owner:
            owner.execute("DELETE FROM observatory.profiles WHERE registrable_domain = %s", (host,))
        # Gone on the very next read, with nothing in between.
        assert client.get(f"/api/v1/public/observatory/{host}").status_code == 404


def test_aggregates_are_not_read_as_a_domain_name(
    postgres_database: dict[str, str],
) -> None:
    """Route ordering, which is the kind of thing that works until somebody adds a
    domain called 'aggregates'."""
    with client_for(postgres_database) as client:
        response = client.get("/api/v1/public/aggregates")
    assert response.status_code == 200
    assert "aggregates" in response.json()


def test_the_listing_is_bounded(postgres_database: dict[str, str]) -> None:
    with client_for(postgres_database) as client:
        assert client.get("/api/v1/public/observatory?limit=1000").status_code == 422
        assert client.get("/api/v1/public/observatory?limit=10").status_code == 200
