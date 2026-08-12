"""What the metrics endpoint may and may not say.

Two failure modes matter here and neither is an error. The first is a label that names a
tenant or a target, which turns a scraped-and-stored endpoint into an export of the
customer list. The second is a confident wrong number -- the first version of this
endpoint queried the tables directly as the application role and got zero for
everything, because row-level security hides rows rather than refusing, and a monitoring
system would have recorded a healthy idle platform indefinitely.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "api" / "src"))

from siembiot.config import Settings  # noqa: E402
from siembiot.main import create_app  # noqa: E402
from siembiot.metrics import HELP, PREFIX, Metric, render  # noqa: E402

#: Every label the endpoint may use. Anything else is either an identifier or unbounded,
#: and both are reasons this list is checked rather than trusted.
PERMITTED_LABELS = {"state", "ownership_state", "reason_code", "schema_version"}

#: Tenant data that must not appear in a scrape. Named for what it is rather than
#: as a "secret", which it is not -- a domain under assessment is confidential
#: because of whose it is, not because it is unguessable.
TENANT_DOMAIN = "private-target.test"
TENANT_NAME = "Confidential Institution"


def client_for(postgres_database: dict[str, str]) -> TestClient:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        environment="development",
        app_database_url=postgres_database["app_url"].replace(
            "postgresql://", "postgresql+psycopg://"
        ),
    )
    return TestClient(create_app(settings))


def seed(owner_url: str) -> dict[str, str]:
    organization_id, user_id, domain_id = uuid4(), uuid4(), uuid4()
    slug = f"me-{organization_id.hex[:12]}"
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO users (id, identity_issuer, identity_subject, email, display_name) "
            "VALUES (%s, 'https://idp.example.test', %s, %s, 'Metrics user')",
            (str(user_id), str(user_id), f"{user_id}@example.test"),
        )
        owner.execute(
            "INSERT INTO organizations (id, name, slug, created_by_user_id) "
            "VALUES (%s, %s, %s, %s)",
            (str(organization_id), TENANT_NAME, slug, str(user_id)),
        )
        owner.execute(
            "INSERT INTO domains (id, organization_id, canonical_name, unicode_display, "
            "registrable_domain, ownership_state, created_by_user_id) "
            "VALUES (%s, %s, %s, %s, %s, 'verified', %s)",
            (
                str(domain_id),
                str(organization_id),
                TENANT_DOMAIN,
                TENANT_DOMAIN,
                TENANT_DOMAIN,
                str(user_id),
            ),
        )
    return {
        "organization_id": str(organization_id),
        "domain_id": str(domain_id),
        "slug": slug,
    }


# -- what must never appear --------------------------------------------------


def test_no_tenant_or_target_appears_anywhere_in_a_scrape(
    postgres_database: dict[str, str],
) -> None:
    """The endpoint is scraped on a timer and stored somewhere with looser access rules.

    A label carrying an organization id would export the customer list; one carrying a
    hostname would export the list of domains under assessment.
    """
    fixture = seed(postgres_database["owner_url"])
    with client_for(postgres_database) as client:
        body = client.get("/metrics").text

    assert fixture["organization_id"] not in body
    assert fixture["domain_id"] not in body
    assert TENANT_DOMAIN not in body
    assert TENANT_NAME not in body
    assert fixture["slug"] not in body
    # And no bare identifier of any kind.
    assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}", body)


def test_only_permitted_labels_are_used(postgres_database: dict[str, str]) -> None:
    """Checked against an allowlist rather than trusted.

    An added label is how an identifier gets in, and it would look like a small,
    obviously useful change at the time.
    """
    seed(postgres_database["owner_url"])
    with client_for(postgres_database) as client:
        body = client.get("/metrics").text

    used = set(re.findall(r'[{,]([a-z_]+)="', body))
    assert used <= PERMITTED_LABELS, f"unexpected labels: {sorted(used - PERMITTED_LABELS)}"


def test_label_cardinality_stays_bounded(postgres_database: dict[str, str]) -> None:
    """Every label value comes from a set the schema constrains.

    Bounded cardinality is a side effect; the reason for the constraint is
    confidentiality, and a check on the count catches a leak of either kind.
    """
    seed(postgres_database["owner_url"])
    with client_for(postgres_database) as client:
        body = client.get("/metrics").text

    values = set(re.findall(r'[{,][a-z_]+="([^"]*)"', body))
    assert len(values) < 60, f"cardinality is growing with data: {len(values)} label values"


# -- what it must report -----------------------------------------------------


def test_a_scrape_reports_real_counts_not_zero(postgres_database: dict[str, str]) -> None:
    """The bug this endpoint was rebuilt around.

    Querying the tables directly as the application role returned zero for everything,
    because row-level security hides rows rather than refusing the query. A failed
    scrape is visible; a confident wrong number is not.
    """
    seed(postgres_database["owner_url"])
    with client_for(postgres_database) as client:
        body = client.get("/metrics").text

    assert f"{PREFIX}metrics_scrape_ok 1.0" in body
    assert re.search(rf'{PREFIX}domains\{{ownership_state="verified"\}} [1-9]', body)


def test_a_failed_scrape_says_so_rather_than_going_quiet() -> None:
    """Silence looks identical to a healthy, quiet platform."""
    body = render([], scrape_ok=False)
    assert f"{PREFIX}metrics_scrape_ok 0.0" in body


def test_every_metric_carries_a_description() -> None:
    """Whoever meets one of these in an alert at an unsociable hour did not write it."""
    for name, text in HELP.items():
        assert text.strip(), name
        assert text.strip().endswith("."), f"{name}: help text should read as a sentence"


def test_the_exposition_format_is_well_formed(postgres_database: dict[str, str]) -> None:
    seed(postgres_database["owner_url"])
    with client_for(postgres_database) as client:
        response = client.get("/metrics")

    assert response.headers["content-type"].startswith("text/plain")
    for line in response.text.splitlines():
        if line.startswith("#"):
            assert line.startswith(("# HELP ", "# TYPE ")), line
        elif line:
            assert re.fullmatch(r"[a-z_]+(\{[^}]*\})? -?[0-9.e+]+", line), line


def test_the_metrics_endpoint_is_not_in_the_public_contract(
    postgres_database: dict[str, str],
) -> None:
    """Not part of the product's API, and nothing should generate a client for it."""
    with client_for(postgres_database) as client:
        document = client.get("/openapi.json").json()
    assert "/metrics" not in document["paths"]


@pytest.mark.parametrize("value", ['a"b', "a\\b", "a\nb"])
def test_hostile_label_values_cannot_break_the_format(value: str) -> None:
    """Every value comes from a closed set today.

    A label added later from somewhere less constrained must not be able to inject a
    line into the exposition, which is why values are escaped rather than trusted.
    """
    rendered = Metric("assessments", [({"state": value}, 1.0)]).render()
    body_lines = [line for line in rendered.splitlines() if not line.startswith("#")]
    assert len(body_lines) == 1, "a label value split the sample across lines"


# -- the one metric that must not default to zero -----------------------------------------


def test_an_unreadable_database_does_not_report_a_fresh_backup() -> None:
    """The dangerous default.

    Every other metric fills in at zero when the scrape produces nothing, and zero is the
    honest reading of an absent count: none happened. For an *age* it is the opposite. Nil
    seconds since the last backup reads as "backed up moments ago", so a database the
    exporter cannot reach would hold `BackupStale` quiet for exactly as long as the outage
    lasted -- silencing the alert in the one situation where somebody needs it.

    Ten years is the same sentinel the SQL function returns for a platform that has never
    taken a backup, and no threshold survives it.
    """
    body = render([], scrape_ok=False)

    line = next(
        text
        for text in body.splitlines()
        if text.startswith(f"{PREFIX}last_successful_backup_seconds ")
    )

    assert float(line.split()[-1]) > 86_400 * 365, line


def test_a_missing_count_still_defaults_to_zero() -> None:
    """The other side of the rule above, so the sentinel is not applied to everything.

    "No schedules are due" is genuinely zero, and reporting a decade there would page
    somebody about a healthy platform.
    """
    body = render([], scrape_ok=False)

    line = next(text for text in body.splitlines() if text.startswith(f"{PREFIX}schedules_due "))

    assert float(line.split()[-1]) == 0.0, line
