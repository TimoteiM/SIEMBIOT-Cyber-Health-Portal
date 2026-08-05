"""Certificate Transparency collection (pillar D).

CT is the primary keyless source of asset candidates. Every candidate carries its
attribution confidence and stays a candidate until a human accepts it — discovery is
never ownership. The local fixture source keeps the whole pipeline testable offline.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from siembiot_worker.adapters.contract import (
    AdapterDescriptor,
    AdapterGroup,
    CachePolicy,
    CollectionResult,
    CostUnit,
    DataClassification,
    RateLimitPolicy,
)
from siembiot_worker.collectors.base import Clock, Collector, utc_now
from siembiot_worker.network_safety.collection_broker import (
    CollectionNetworkBroker,
    CollectionRequest,
)
from siembiot_worker.network_safety.host_policy import HostPolicyError, canonical_host

MAX_CANDIDATES = 500

CT_DESCRIPTOR = AdapterDescriptor(
    adapter_id="certificate_transparency",
    version="1.0.0",
    group=AdapterGroup.CERTIFICATE_TRANSPARENCY,
    title="Certificate Transparency asset candidate collector",
    capabilities=frozenset({"ct.entries", "ct.asset_candidates"}),
    data_classification=DataClassification.PUBLIC_OBSERVATION,
    terms_notes=(
        "Certificate Transparency logs are public append-only records (RFC 6962). "
        "Names observed here are candidates, not confirmed organizational assets."
    ),
    terms_url="https://datatracker.ietf.org/doc/html/rfc6962",
    required_secrets=frozenset(),
    timeout_seconds=10.0,
    rate_limit=RateLimitPolicy(2, 1.0, burst=1, minimum_interval_seconds=0.5),
    cost_unit=CostUnit.NONE,
    cache=CachePolicy(3_600),
    supports_fixtures=True,
)


class CTEntrySource(Protocol):
    def entries(self, canonical_domain: str) -> Iterable[dict[str, Any]]: ...


class FixtureCTSource:
    """Reads CT entries from a local fixture directory; makes no network connection."""

    def __init__(self, root: Path) -> None:
        self._root = root

    def entries(self, canonical_domain: str) -> Iterable[dict[str, Any]]:
        path = self._root / f"{canonical_domain}.json"
        if not path.is_file():
            return ()
        document = json.loads(path.read_text(encoding="utf-8"))
        entries = document.get("entries")
        return entries if isinstance(entries, list) else ()


def attribution_confidence(candidate: str, canonical_domain: str) -> tuple[float, str]:
    """Confidence is a function of the name's relationship to the authorized domain."""
    if candidate == canonical_domain:
        return 1.0, "authorized_domain"
    if candidate.endswith(f".{canonical_domain}"):
        return 0.9, "subdomain_of_authorized_domain"
    return 0.2, "unrelated_name"


def extract_candidates(
    entries: Iterable[dict[str, Any]], canonical_domain: str
) -> tuple[list[dict[str, Any]], list[str]]:
    """Flatten CT entries into deduplicated, confidence-labelled asset candidates."""
    seen: dict[str, dict[str, Any]] = {}
    rejected: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        names = entry.get("dns_names")
        if not isinstance(names, list):
            continue
        issuer = entry.get("issuer")
        not_before = entry.get("not_before")
        not_after = entry.get("not_after")
        for raw_name in names:
            if not isinstance(raw_name, str):
                continue
            name = raw_name.strip().lower().lstrip("*.")
            try:
                candidate = canonical_host(name)
            except HostPolicyError:
                rejected.append(raw_name[:255])
                continue
            confidence, basis = attribution_confidence(candidate, canonical_domain)
            existing = seen.get(candidate)
            if existing is None:
                seen[candidate] = {
                    "name": candidate,
                    "confidence": confidence,
                    "attribution_basis": basis,
                    "wildcard_observed": raw_name.strip().startswith("*."),
                    "first_seen": not_before,
                    "last_seen": not_after,
                    "issuers": [issuer] if isinstance(issuer, str) else [],
                    "observation_count": 1,
                }
                continue
            existing["observation_count"] += 1
            existing["wildcard_observed"] = existing[
                "wildcard_observed"
            ] or raw_name.strip().startswith("*.")
            if isinstance(issuer, str) and issuer not in existing["issuers"]:
                existing["issuers"].append(issuer)
            existing["first_seen"] = _earliest(existing["first_seen"], not_before)
            existing["last_seen"] = _latest(existing["last_seen"], not_after)
    candidates = sorted(seen.values(), key=lambda item: (-item["confidence"], str(item["name"])))
    return candidates[:MAX_CANDIDATES], sorted(set(rejected))


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _earliest(current: Any, candidate: Any) -> Any:
    left, right = _parse(current), _parse(candidate)
    if left is None:
        return candidate if right is not None else current
    if right is None:
        return current
    return current if left <= right else candidate


def _latest(current: Any, candidate: Any) -> Any:
    left, right = _parse(current), _parse(candidate)
    if left is None:
        return candidate if right is not None else current
    if right is None:
        return current
    return current if left >= right else candidate


class CertificateTransparencyCollector(Collector):
    descriptor = CT_DESCRIPTOR

    def __init__(
        self,
        broker: CollectionNetworkBroker,
        source: CTEntrySource,
        clock: Clock = utc_now,
    ) -> None:
        super().__init__(broker, clock)
        self._source = source

    def collect(self, request: CollectionRequest) -> CollectionResult:
        host = request.canonical_host
        try:
            entries = list(self._source.entries(host))
        except (OSError, json.JSONDecodeError):
            return self.unavailable("ct_source_unavailable", {"host": host})
        if not entries:
            return self.not_applicable("no_ct_entries", {"host": host, "candidates": []})
        candidates, rejected = extract_candidates(entries, host)
        payload: dict[str, Any] = {
            "host": host,
            "entry_count": len(entries),
            "candidates": candidates,
            "candidate_count": len(candidates),
            "rejected_names": rejected,
            "truncated": len(candidates) == MAX_CANDIDATES,
        }
        if rejected or payload["truncated"]:
            reasons = tuple(
                filter(
                    None,
                    (
                        "malformed_names_rejected" if rejected else None,
                        "candidate_list_truncated" if payload["truncated"] else None,
                    ),
                )
            )
            return self.partial(payload, reasons, source="certificate_transparency")
        return self.ok(payload, source="certificate_transparency")
