"""The Certificate Transparency source, and the contract it has to meet.

Asset discovery was complete, wired, and connected to `EmptyCTSource` in every deployed
run, so `collect.ct` reported "no entries" for every domain on earth. These tests exist
so the replacement cannot fail the same way quietly: once by never being asked, and once
by answering in a shape the collector does not read.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent))

from siembiot_worker.collectors.ct_log import extract_candidates  # noqa: E402
from siembiot_worker.collectors.ct_source import BrokeredCTSource, _names  # noqa: E402
from siembiot_worker.network_safety.collection_broker import (  # noqa: E402
    CollectionRequest,
    HTTPCollectionResult,
)
from siembiot_worker.network_safety.collection_policy import (  # noqa: E402
    CollectionDestination,
)

DOMAIN = "apavil.ro"

#: The shape certspotter answers with, copied from a real response for this domain.
CERTSPOTTER_ROW = {
    "id": "14929805852",
    "dns_names": ["apavil.ro", "www.apavil.ro"],
    "issuer": {"friendly_name": "Let's Encrypt", "name": "C=US, O=Let's Encrypt, CN=R13"},
    "not_before": "2026-05-16T05:51:28Z",
    "not_after": "2026-08-14T05:51:27Z",
    "revoked": False,
}

#: And the shape crt.sh answers with, because the index is configurable and an operator
#: may point this at either. Names arrive as one newline-separated string there.
CRT_SH_ROW = {
    "issuer_ca_id": 183267,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R11",
    "common_name": "apavil.ro",
    "name_value": "apavil.ro\nwww.apavil.ro",
    "id": 123456789,
    "entry_timestamp": "2026-01-01T00:00:00",
    "not_before": "2026-01-01T00:00:00",
    "not_after": "2026-04-01T00:00:00",
}


class StubBroker:
    def __init__(self, body: bytes, status: int = 200, allowed: bool = True) -> None:
        self.body = body
        self.status = status
        self.allowed = allowed
        self.requests: list[tuple[str, str]] = []

    def fetch(
        self,
        request: CollectionRequest,
        destination: CollectionDestination,
        **kwargs: object,
    ) -> HTTPCollectionResult:
        del kwargs
        self.requests.append((request.canonical_host, destination.query))
        return HTTPCollectionResult(
            self.allowed, "allowed", status_code=self.status, body=self.body
        )


def source(broker: StubBroker) -> BrokeredCTSource:
    return BrokeredCTSource(broker, uuid4(), uuid4(), uuid4())  # type: ignore[arg-type]


def test_entries_are_shaped_the_way_the_collector_reads_them() -> None:
    """The contract between the source and the collector, pinned.

    The first draft emitted `names`; `extract_candidates` reads `dns_names`. Every
    domain would have come back with zero candidates -- the same silent nothing this
    module was written to fix, reached a different way.
    """
    for row in (CERTSPOTTER_ROW, CRT_SH_ROW):
        broker = StubBroker(json.dumps([row]).encode())
        candidates, rejected = extract_candidates(source(broker).entries(DOMAIN), DOMAIN)

        assert {item["name"] for item in candidates} == {"apavil.ro", "www.apavil.ro"}
        assert rejected == []


def test_the_index_is_the_host_that_is_connected_to() -> None:
    """Not the domain being asked about.

    The wrong way round would apply the target's rate limit and address policy to a third
    party, and record the audit row against a host we never touched.
    """
    from siembiot_worker.collectors.ct_source import DEFAULT_CT_INDEX

    broker = StubBroker(json.dumps([CERTSPOTTER_ROW]).encode())
    list(source(broker).entries(DOMAIN))

    host, query = broker.requests[0]
    assert host == DEFAULT_CT_INDEX
    assert DOMAIN in query


def test_a_wildcard_is_not_expanded_into_a_host_nobody_has_seen() -> None:
    """`*.example.ro` is a statement about a zone. Inventing `www` from it would put a
    name in the review list that has never been observed answering."""
    names = _names({"name_value": "*.apavil.ro\napavil.ro"})
    assert names == ["*.apavil.ro", "apavil.ro"]


def test_a_refused_or_broken_answer_yields_nothing_rather_than_failing_the_run() -> None:
    """A third party having a bad day must not fail somebody's assessment."""
    assert tuple(source(StubBroker(b"not json")).entries(DOMAIN)) == ()
    assert tuple(source(StubBroker(b"[]", status=503)).entries(DOMAIN)) == ()
    assert tuple(source(StubBroker(b"[]", allowed=False)).entries(DOMAIN)) == ()
    assert tuple(source(StubBroker(b'{"not": "a list"}')).entries(DOMAIN)) == ()


def test_a_configured_source_does_not_claim_to_be_unconfigured() -> None:
    """The flag that separates "the logs hold nothing" from "nobody was asked"."""
    from siembiot_worker.observation.pipeline import EmptyCTSource

    assert source(StubBroker(b"[]")).is_unconfigured is False
    assert EmptyCTSource().is_unconfigured is True


def test_the_answer_is_bounded() -> None:
    """A wildcard search against a large organisation can answer with tens of thousands
    of rows, and a candidate list that long is not a review anybody performs."""
    from siembiot_worker.collectors.ct_source import MAX_ENTRIES

    rows = json.dumps([CERTSPOTTER_ROW] * (MAX_ENTRIES + 50)).encode()
    assert len(tuple(source(StubBroker(rows)).entries(DOMAIN))) == MAX_ENTRIES
