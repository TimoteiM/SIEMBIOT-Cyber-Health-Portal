"""Logging that cannot leak credentials or evidence.

Logs are shipped to aggregators, retained for months, and read by people who were never
granted access to the tenant a line came from. A secret or somebody's findings landing
there is worse than in almost any other place, and it happens by accident rather than
by decision -- so the tests are about what escapes, not about formatting.
"""

from __future__ import annotations

import json
import logging

import pytest
from siembiot_worker.telemetry import (
    REDACTED,
    SECRET_FIELD_NAMES,
    JsonFormatter,
    configure_logging,
    log_event,
    redact,
    redact_field,
)


def rendered(record: logging.LogRecord) -> dict[str, object]:
    parsed: dict[str, object] = json.loads(JsonFormatter().format(record))
    return parsed


def record(message: str, **fields: object) -> logging.LogRecord:
    made = logging.LogRecord("siembiot.test", logging.INFO, __file__, 1, message, None, None)
    made.fields = fields
    return made


# -- what must never appear --------------------------------------------------


@pytest.mark.parametrize("field", sorted(SECRET_FIELD_NAMES))
def test_a_secret_field_is_never_emitted(field: str) -> None:
    """Matched on the field name, because a secret has no recognisable shape and
    waiting to recognise one is how they get logged."""
    assert redact_field(field, "hunter2") == REDACTED


def test_the_field_name_check_ignores_case() -> None:
    assert redact_field("Authorization", "Bearer abc") == REDACTED
    assert redact_field("GATEWAY_SECRET", "abc") == REDACTED


def test_a_credential_inside_a_connection_string_is_scrubbed() -> None:
    """These reach logs through exception messages more often than through logging.

    A database error's text routinely contains the whole connection string, so the
    value is scrubbed as well as the field name being checked.
    """
    scrubbed = redact("could not connect: postgresql+psycopg://siembiot_worker:s3cr3t@db:5432/x")
    assert "s3cr3t" not in scrubbed
    assert "siembiot_worker" in scrubbed  # the role is useful; the password is not


def test_credentials_are_scrubbed_inside_nested_structures() -> None:
    payload = {"outer": {"database_url": "postgresql://u:p@h/d"}, "list": ["postgres://a:b@h/d"]}
    scrubbed = redact(payload)
    assert scrubbed["outer"]["database_url"] == REDACTED
    assert "b@h" not in json.dumps(scrubbed)


def test_an_exception_contributes_its_type_not_its_message() -> None:
    """A message can carry the connection string that caused it."""
    try:
        raise ValueError("postgresql://user:leaked@host/db is unreachable")
    except ValueError:
        import sys

        made = logging.LogRecord(
            "siembiot.test", logging.ERROR, __file__, 1, "run failed", None, sys.exc_info()
        )
        payload = rendered(made)

    assert payload["error_type"] == "ValueError"
    assert "leaked" not in json.dumps(payload)


# -- what the line looks like ------------------------------------------------


def test_a_line_is_one_json_object() -> None:
    """Read by machines first: filtering by tenant during an incident should not mean
    writing a regular expression against an English sentence."""
    payload = rendered(record("run finished", assessment_id="abc", state="completed"))
    assert payload["message"] == "run finished"
    assert payload["level"] == "info"
    assert payload["assessment_id"] == "abc"
    assert payload["state"] == "completed"


def test_a_timestamp_is_present_and_timezone_aware() -> None:
    payload = rendered(record("anything"))
    assert isinstance(payload["timestamp"], str)
    assert payload["timestamp"].endswith("+00:00")


def test_values_that_are_not_json_survive_serialisation() -> None:
    """A UUID or a datetime in a field must not turn the whole line into an exception,
    because the line is often the only record that something happened."""
    from datetime import UTC, datetime
    from uuid import uuid4

    payload = rendered(record("run", assessment_id=uuid4(), at=datetime.now(UTC)))
    assert isinstance(payload["assessment_id"], str)
    assert isinstance(payload["at"], str)


def test_log_event_puts_fields_on_the_record(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("siembiot.test.event")
    with caplog.at_level(logging.INFO, logger="siembiot.test.event"):
        log_event(logger, "verification expired", domains=3)
    assert caplog.records[-1].fields == {"domains": 3}  # type: ignore[attr-defined]


def test_configuring_logging_replaces_handlers_rather_than_adding(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Called twice -- as an import and again by a runner -- it must not double every
    line, which is how a log volume bill and an unreadable stream both start."""
    configure_logging("INFO")
    configure_logging("INFO")
    logging.getLogger("siembiot.test.dup").info("once")
    assert capsys.readouterr().out.count('"message": "once"') == 1


# -- credentials carried inside a DNS name -------------------------------------------------


def test_a_key_in_a_dns_query_name_is_redacted() -> None:
    """The shape the existing redactor was blind to.

    Reputation blocklists are queried as `<key>.<list>.dq.spamhaus.net`, so the API key
    is not in a header or a URL -- it is the question. Every layer that touches a DNS
    query touches the secret: the resolver, the timeout message, the exception text, the
    record of what was asked. A redactor written for `scheme://user:pass@host` sees
    nothing wrong, because nothing is wrong with the shape; it is an ordinary hostname.

    Caught before the collector was written rather than after it had been logging for a
    month, which is the only reason this is a test and not an incident.
    """
    line = "resolving abc123SECRETKEY.dbl.dq.spamhaus.net timed out"

    assert "SECRETKEY" not in redact(line)


def test_the_whole_prefix_is_redacted_not_just_one_label() -> None:
    """The trap in the obvious implementation.

    The key is the leftmost label and the list name sits between it and the zone. A
    pattern anchored one label out redacts `dbl` and publishes the key -- and the line
    then *looks* handled, which is worse than no redaction, because nobody re-reads a
    log line that already says [redacted].
    """
    for listing in ("dbl", "zen", "sbl", "xbl"):
        line = f"query k3yMATERIAL.{listing}.dq.spamhaus.net"

        assert "k3yMATERIAL" not in redact(line), f"the key survived a {listing} query"


def test_an_ordinary_spamhaus_hostname_is_left_alone() -> None:
    """Redacting `www.spamhaus.org` would be noise, and noise is how a redactor teaches
    people to stop reading its output."""
    assert redact("see www.spamhaus.org for details") == "see www.spamhaus.org for details"


def test_the_dns_redaction_survives_being_nested_in_a_structure() -> None:
    """Logs carry dictionaries, not sentences. A rule that only fires on a bare string
    misses the case the logger actually produces."""
    event = {"detail": {"query": "topsecret.zen.dq.spamhaus.net", "attempt": 2}}

    assert "topsecret" not in str(redact(event))
