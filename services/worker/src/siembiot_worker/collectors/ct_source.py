"""A real Certificate Transparency source.

Until now the only sources were a local fixture and `EmptyCTSource`, and the empty one
was the default in every deployed run. So asset discovery has never returned a single
candidate: `collect.ct` reported `no_ct_entries` for every domain, which reads as "this
organisation has no certificates" and is false for anything with working HTTPS. The
subsystem was complete, wired, and connected to nothing.

CT logs are public append-only records (RFC 6962) and every publicly trusted certificate
is in them, which is what makes them the one keyless way to find an organisation's
hostnames. This reads them through an index rather than from the logs directly: the raw
logs are enormous and querying them by name is not something they support.

Two things the index is *not* trusted with. It answers over the same broker as everything
else, so the address policy, budgets and kill switch apply to it exactly as to a target.
And what it returns is treated as hostile input -- names are re-validated against the host
policy before they become candidates, because a name in somebody else's certificate is a
string from the internet, not a fact about this organisation.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any
from uuid import UUID

from siembiot_worker.network_safety.collection_broker import (
    CollectionNetworkBroker,
    CollectionRequest,
)
from siembiot_worker.network_safety.collection_policy import (
    OperationClass,
    encode_path_segment,
    provider_destination,
)

#: The index this reads the logs through. Configurable because an operator may prefer
#: their own, and named here rather than buried in a call so the one third-party
#: dependency of asset discovery is visible in a single place.
#:
#: certspotter rather than crt.sh, which is the better-known index and was the first
#: choice: crt.sh timed out entirely on one attempt and answered 502 on the next, while
#: certspotter answered in about a second. An index that is down produces an empty
#: candidate list, and an empty candidate list is indistinguishable from an organisation
#: with no subdomains -- which is the exact failure this module was written to end.
DEFAULT_CT_INDEX = "api.certspotter.com"
CT_INDEX_PATH = "/v1/issuances"

#: A bound on what one query may return. A wildcard search against a large organisation
#: can answer with tens of thousands of rows, and the candidate list is reviewed by a
#: person -- ten thousand names is not a review, it is a refusal to look.
MAX_ENTRIES = 2_000


class BrokeredCTSource:
    """Reads CT entries for a domain through the collection broker."""

    def __init__(
        self,
        broker: CollectionNetworkBroker,
        organization_id: UUID,
        domain_id: UUID,
        assessment_id: UUID | None = None,
        index_host: str = DEFAULT_CT_INDEX,
    ) -> None:
        self._broker = broker
        self._organization_id = organization_id
        self._domain_id = domain_id
        self._assessment_id = assessment_id
        self._index_host = index_host

    @property
    def is_unconfigured(self) -> bool:
        return False

    def entries(self, canonical_domain: str) -> Iterable[dict[str, Any]]:
        request = CollectionRequest(
            self._organization_id,
            self._domain_id,
            self._assessment_id,
            OperationClass.CT_QUERY,
            # The *index* is the host being connected to, not the domain being asked
            # about. Getting this the wrong way round would have the broker apply the
            # target's rate limit and address policy to a third party, and record the
            # audit row against the wrong host.
            self._index_host,
            (self._index_host,),
        )
        destination = provider_destination(
            OperationClass.CT_QUERY,
            self._index_host,
            CT_INDEX_PATH,
            f"domain={encode_path_segment(canonical_domain)}"
            "&include_subdomains=true&expand=dns_names&expand=issuer",
        )
        response = self._broker.fetch(request, destination)
        if not response.allowed or response.status_code != 200:
            return ()

        try:
            payload = json.loads(response.body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # A malformed answer from the index is the index's problem, and returning
            # nothing is the honest outcome. Raising would fail the whole assessment over
            # a third party having a bad day.
            return ()
        if not isinstance(payload, list):
            return ()

        # `dns_names`, not `names`: this is the key `extract_candidates` reads, and the
        # first draft used the wrong one. It would have produced zero candidates for every
        # domain -- the same silent nothing this whole module exists to fix, arrived at a
        # different way. A test now pins the two together.
        return tuple(
            {
                "dns_names": _names(item),
                "issuer": _issuer(item),
                "not_before": item.get("not_before"),
                "not_after": item.get("not_after"),
            }
            for item in payload[:MAX_ENTRIES]
            if isinstance(item, dict)
        )


def _names(entry: dict[str, Any]) -> list[str]:
    """Every name a certificate covers, as the index reports them.

    Two shapes are read because two indexes are plausible and an operator may point this
    at either: certspotter returns `dns_names` as a list, crt.sh returns `name_value` as
    a newline-separated string. Supporting both costs four lines and means changing index
    is configuration rather than a code change.

    A wildcard is kept as written rather than expanded. `*.example.ro` is a statement
    about a zone, and inventing `www.example.ro` from it would put a host in the review
    list that nobody has ever seen answer.
    """
    listed = entry.get("dns_names")
    if isinstance(listed, list):
        return [str(name).strip().lower() for name in listed if str(name).strip()]
    raw = entry.get("name_value") or entry.get("common_name") or ""
    if not isinstance(raw, str):
        return []
    return [line.strip().lower() for line in raw.splitlines() if line.strip()]


def _issuer(entry: dict[str, Any]) -> str | None:
    """Who signed it, in whichever way the index says so."""
    issuer = entry.get("issuer")
    if isinstance(issuer, dict):
        name = issuer.get("friendly_name") or issuer.get("name")
        return str(name) if name else None
    return str(entry["issuer_name"]) if entry.get("issuer_name") else None
