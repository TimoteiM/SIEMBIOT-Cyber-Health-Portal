"""Structured logging, with the things that must never be logged left out by design.

A security assessment platform holds two kinds of dangerous string: credentials, and
other people's evidence. Both end up in logs by accident, and both are worse there than
almost anywhere else -- logs get shipped to aggregators, retained for months, and read
by people who were never granted access to the tenant the line came from.

So this module makes the safe thing the easy thing. Events carry named fields rather
than interpolated sentences, the field names are what get emitted, and values are
passed through a redactor that recognises the shapes this system actually produces:
connection URLs with passwords, gateway secrets, verification tokens.

What is deliberately *not* here: a general-purpose PII scrubber. Pattern-matching for
personal data gives false confidence -- it catches the examples somebody thought of and
silently misses the rest. The discipline is to log identifiers and let anyone who needs
the content go and read it from the database, with an audit trail.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

#: Field names whose values are never emitted, whatever they contain. Matched on the
#: name rather than the value, because a secret does not have a recognisable shape and
#: waiting to recognise one is how they get logged.
SECRET_FIELD_NAMES = frozenset(
    {
        "password",
        "secret",
        "token",
        "verification_token",
        "gateway_secret",
        "authorization",
        "cookie",
        "database_url",
        "broker_url",
        "url",
    }
)

REDACTED = "[redacted]"

#: A connection string with credentials in it. These reach logs through exception
#: messages more often than through deliberate logging, which is why the value is
#: scrubbed as well as the field name being checked.
_CREDENTIAL_URL = re.compile(r"(?P<scheme>[a-z+]+://)(?P<user>[^:@/\s]+):(?P<secret>[^@/\s]+)@")

#: A credential carried as the first label of a DNS name.
#:
#: Reputation blocklists are queried this way -- `<key>.dbl.dq.spamhaus.net` -- so the
#: API key is not in a header or a URL but *in the question itself*. Every layer that
#: handles a DNS query handles the secret: the resolver, the timeout message, the
#: exception text, the record of which name was asked. A redactor written for
#: `scheme://user:password@host` sees nothing wrong with any of it, because nothing is
#: wrong with the shape -- it is a perfectly ordinary hostname.
#:
#: Matched on the *zone* rather than on what a key looks like. Keys have no recognisable
#: shape, and waiting to recognise one is how they get logged; the zones that use this
#: scheme are a short, known list.
_CREDENTIALLED_DNS_ZONES = (
    "dq.spamhaus.net",
    "dq.spamhaus.org",
)
#: Everything left of the zone is redacted, not merely the first label. The key is
#: the leftmost label and the list name -- `dbl`, `zen`, `sbl` -- sits between it and
#: the zone, so a pattern anchored one label out would redact `dbl` and publish the
#: key. That is worse than no redaction at all, because the line then looks handled.
_CREDENTIALLED_DNS_NAME = re.compile(
    r"(?:[A-Za-z0-9_-]+\.)+(?P<zone>"
    + "|".join(re.escape(zone) for zone in _CREDENTIALLED_DNS_ZONES)
    + r")"
)


def redact(value: Any) -> Any:
    """Scrub credentials out of a value that is about to be logged."""
    if isinstance(value, str):
        value = _CREDENTIALLED_DNS_NAME.sub(REDACTED + r".\g<zone>", value)
        return _CREDENTIAL_URL.sub(r"\g<scheme>\g<user>:" + REDACTED + "@", value)
    if isinstance(value, dict):
        return {key: redact_field(key, item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [redact(item) for item in value]
    return value


def redact_field(name: str, value: Any) -> Any:
    if name.lower() in SECRET_FIELD_NAMES:
        return REDACTED
    return redact(value)


class JsonFormatter(logging.Formatter):
    """One JSON object per line.

    Structured rather than formatted prose because these lines are read by machines
    first: an operator filtering for one organization's runs during an incident should
    not be writing a regular expression against an English sentence.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            payload.update({key: redact_field(key, value) for key, value in extra.items()})
        if record.exc_info:
            # The type and the traceback, not the exception's own message: a database
            # error's message routinely contains the connection string.
            payload["error_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
            payload["traceback"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, default=_encode, ensure_ascii=False)


def _encode(value: Any) -> str:
    if isinstance(value, UUID | datetime):
        return str(value)
    return repr(value)


def configure_logging(level: str | None = None) -> None:
    """Send structured logs to stdout.

    stdout rather than a file because a container has no useful filesystem to keep logs
    on, and whatever collects them expects a stream.
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    resolved = level or os.environ.get("SIEMBIOT_LOG_LEVEL") or "INFO"
    root.setLevel(resolved.upper())


def log_event(logger: logging.Logger, message: str, **fields: Any) -> None:
    """Record an event with named fields.

    Fields rather than an interpolated sentence: `log_event(log, "run finished",
    assessment_id=..., state=...)` stays queryable, and nothing is tempted to
    interpolate a value that turns out to be evidence.
    """
    logger.info(message, extra={"fields": fields})
