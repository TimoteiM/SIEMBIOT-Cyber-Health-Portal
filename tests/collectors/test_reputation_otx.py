"""The OTX reputation provider.

No network. The provider talks to the broker, so a fake broker is the whole seam — which
is the point of routing provider traffic through it rather than letting each provider own
a socket.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from siembiot_worker.collectors.reputation import Listing
from siembiot_worker.collectors.reputation_otx import (
    OTX_KEY_HEADER,
    OTXReputationProvider,
)
from siembiot_worker.network_safety.collection_broker import (
    CollectionRequest,
    HTTPCollectionResult,
)
from siembiot_worker.network_safety.collection_policy import (
    CollectionDestination,
    OperationClass,
)

KEY = "otx-key-not-a-real-one"


class FakeBroker:
    def __init__(self, result: HTTPCollectionResult) -> None:
        self.result = result
        self.calls: list[tuple[CollectionRequest, CollectionDestination, dict[str, str]]] = []

    def fetch(
        self,
        request: CollectionRequest,
        destination: CollectionDestination,
        **kwargs: Any,
    ) -> HTTPCollectionResult:
        self.calls.append((request, destination, dict(kwargs.get("credentials") or {})))
        return self.result


def answered(payload: dict[str, Any], status: int = 200) -> HTTPCollectionResult:
    return HTTPCollectionResult(True, "allowed", status, {}, (), json.dumps(payload).encode())


def provider(result: HTTPCollectionResult) -> tuple[OTXReputationProvider, FakeBroker]:
    broker = FakeBroker(result)
    return (
        OTXReputationProvider(broker, KEY, uuid4(), uuid4(), uuid4()),  # type: ignore[arg-type]
        broker,
    )


def test_a_domain_in_no_threat_report_is_not_listed() -> None:
    otx, _ = provider(answered({"pulse_info": {"count": 0}, "validation": [{"source": "alexa"}]}))
    verdict = otx.lookup("example.test")
    assert verdict.listing is Listing.NOT_LISTED
    assert verdict.detail == "pulses:0 whitelisted:1"


def test_a_domain_named_in_threat_reports_is_listed() -> None:
    otx, _ = provider(answered({"pulse_info": {"count": 2}, "validation": []}))
    verdict = otx.lookup("example.test")
    assert verdict.listing is Listing.LISTED
    assert verdict.detail == "pulses:2 whitelisted:0"


def test_a_missing_count_is_unavailable_rather_than_clean() -> None:
    """The failure that would matter most.

    Reading an absent count as zero would turn every change to somebody else's response
    shape into a clean bill of health for every domain we assess, and nothing downstream
    could tell the difference.
    """
    payloads: list[dict[str, Any]] = [
        {},
        {"pulse_info": {}},
        {"pulse_info": {"count": "many"}},
        {"pulse_info": []},
    ]
    for payload in payloads:
        otx, _ = provider(answered(payload))
        assert otx.lookup("example.test").listing is Listing.UNAVAILABLE


def test_a_rejected_key_says_nothing_about_the_domain() -> None:
    """403 and 429 are facts about us, not about the institution."""
    for status in (401, 403, 429, 500):
        otx, _ = provider(answered({"pulse_info": {"count": 0}}, status=status))
        verdict = otx.lookup("example.test")
        assert verdict.listing is Listing.UNAVAILABLE
        assert verdict.detail == f"status:{status}"


def test_a_refused_request_says_nothing_about_the_domain() -> None:
    otx, _ = provider(HTTPCollectionResult(False, "no_addresses"))
    verdict = otx.lookup("example.test")
    assert verdict.listing is Listing.UNAVAILABLE
    assert verdict.detail == "no_addresses"


def test_an_unreadable_answer_is_unavailable() -> None:
    otx, _ = provider(HTTPCollectionResult(True, "allowed", 200, {}, (), b"<html>not json"))
    assert otx.lookup("example.test").listing is Listing.UNAVAILABLE


def test_without_a_key_nothing_is_asked_and_nothing_is_claimed() -> None:
    broker = FakeBroker(answered({"pulse_info": {"count": 0}}))
    otx = OTXReputationProvider(broker, "  ", uuid4(), uuid4(), uuid4())  # type: ignore[arg-type]
    verdict = otx.lookup("example.test")
    assert verdict.listing is Listing.UNAVAILABLE
    assert verdict.detail == "no_api_key"
    assert broker.calls == [], "a provider with no key must not reach the network"


def test_the_key_travels_in_a_header_and_never_in_the_url() -> None:
    """A URL is written to logs, proxy records and error messages by everything it passes
    through. A credential in one is a credential published."""
    otx, broker = provider(answered({"pulse_info": {"count": 0}}))
    otx.lookup("example.test")
    _, destination, credentials = broker.calls[0]
    assert credentials == {OTX_KEY_HEADER: KEY}
    assert KEY not in destination.path
    assert KEY not in destination.query
    assert KEY not in destination.url


def test_the_request_is_aimed_at_the_provider_not_the_institution() -> None:
    """Getting this the wrong way round would apply the institution's rate limit and
    address policy to a third party, and file the audit row against the wrong host."""
    otx, broker = provider(answered({"pulse_info": {"count": 0}}))
    otx.lookup("primaria-exemplu.ro")
    request, destination, _ = broker.calls[0]
    assert request.operation_class is OperationClass.REPUTATION_QUERY
    assert request.canonical_host == "otx.alienvault.com"
    assert destination.host == "otx.alienvault.com"
    # The domain being asked about is in the path, and escaped.
    assert "primaria-exemplu.ro" in destination.path


def test_a_hostile_domain_name_cannot_escape_the_path() -> None:
    """The host reaches here from the database, but the encoding is what stops a name
    from becoming a different request."""
    otx, broker = provider(answered({"pulse_info": {"count": 0}}))
    verdict = otx.lookup("evil.test/../../admin?x=1")
    assert verdict.listing is Listing.UNAVAILABLE
    assert verdict.detail is not None and verdict.detail.startswith("unusable_host:")
    assert broker.calls == [], "a name that cannot be encoded safely must not be sent"
