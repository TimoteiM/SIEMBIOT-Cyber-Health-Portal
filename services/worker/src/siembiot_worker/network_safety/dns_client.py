"""Bounded DNS querying.

DNS is the one collection channel that reaches names rather than addresses, so the
guard rails here are the record-type allowlist, the per-run query budget, and hard
caps on record count and record size.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from siembiot_worker.network_safety.host_policy import HostPolicyError, canonical_dns_name

DNSStatus = Literal[
    "answered",
    "no_records",
    "nxdomain",
    "timeout",
    "refused",
    "error",
    "too_large",
    "budget_exhausted",
    "forbidden_record_type",
    "invalid_name",
]

ALLOWED_RECORD_TYPES = frozenset(
    {
        "A",
        "AAAA",
        "CAA",
        "CNAME",
        "DNSKEY",
        "DS",
        "MX",
        "NS",
        "SOA",
        "TLSA",
        "TXT",
    }
)

MAX_RECORDS_PER_QUERY = 50
MAX_RECORD_BYTES = 4_096


class DNSClientError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class DNSQuery:
    name: str
    record_type: str


@dataclass(frozen=True)
class DNSRecordSet:
    query: DNSQuery
    status: DNSStatus
    records: tuple[str, ...] = ()
    authenticated: bool = False
    ttl_seconds: int | None = None

    @property
    def is_answered(self) -> bool:
        return self.status == "answered"

    @property
    def is_conclusive(self) -> bool:
        """A conclusive answer proves presence or absence; anything else is unknown."""
        return self.status in {"answered", "no_records", "nxdomain"}


@dataclass(frozen=True)
class DNSBudget:
    lifetime_seconds: float = 3.0
    max_queries: int = 64
    max_records: int = MAX_RECORDS_PER_QUERY
    max_record_bytes: int = MAX_RECORD_BYTES


class DNSTransport(Protocol):
    def query(
        self, name: str, record_type: str, *, lifetime: float, want_dnssec: bool
    ) -> DNSRecordSet: ...


class BoundedDNSClient:
    """The only DNS query path available to collectors."""

    def __init__(self, transport: DNSTransport, budget: DNSBudget | None = None) -> None:
        self._transport = transport
        self._budget = budget or DNSBudget()
        self._queries_used = 0

    @property
    def queries_used(self) -> int:
        return self._queries_used

    @property
    def remaining_queries(self) -> int:
        return max(0, self._budget.max_queries - self._queries_used)

    def query(self, name: str, record_type: str, *, want_dnssec: bool = False) -> DNSRecordSet:
        record_type = record_type.upper()
        query = DNSQuery(name, record_type)
        if record_type not in ALLOWED_RECORD_TYPES:
            return DNSRecordSet(query, "forbidden_record_type")
        try:
            canonical = canonical_dns_name(name)
        except HostPolicyError:
            return DNSRecordSet(query, "invalid_name")
        if self._queries_used >= self._budget.max_queries:
            return DNSRecordSet(query, "budget_exhausted")
        self._queries_used += 1
        answer = self._transport.query(
            canonical,
            record_type,
            lifetime=self._budget.lifetime_seconds,
            want_dnssec=want_dnssec,
        )
        return self._bound(query, answer)

    def _bound(self, query: DNSQuery, answer: DNSRecordSet) -> DNSRecordSet:
        if not answer.is_answered:
            return DNSRecordSet(query, answer.status, (), answer.authenticated, answer.ttl_seconds)
        if len(answer.records) > self._budget.max_records:
            return DNSRecordSet(query, "too_large")
        if any(
            len(record.encode("utf-8")) > self._budget.max_record_bytes for record in answer.records
        ):
            return DNSRecordSet(query, "too_large")
        return DNSRecordSet(
            query,
            "answered",
            tuple(answer.records),
            answer.authenticated,
            answer.ttl_seconds,
        )


class DnspythonTransport:
    """Live resolver transport. Constructed only by the worker runtime, never by a collector."""

    def query(
        self, name: str, record_type: str, *, lifetime: float, want_dnssec: bool
    ) -> DNSRecordSet:
        import dns.exception  # noqa: PLC0415
        import dns.flags  # noqa: PLC0415
        import dns.rdatatype  # noqa: PLC0415
        import dns.resolver  # noqa: PLC0415

        query = DNSQuery(name, record_type)
        resolver = dns.resolver.Resolver()
        resolver.lifetime = lifetime
        resolver.timeout = lifetime
        if want_dnssec:
            resolver.use_edns(0, dns.flags.DO, 4096)
        try:
            answer = resolver.resolve(name, record_type, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return DNSRecordSet(query, "nxdomain")
        except dns.resolver.NoNameservers:
            return DNSRecordSet(query, "refused")
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout, TimeoutError):
            return DNSRecordSet(query, "timeout")
        except dns.exception.DNSException:
            return DNSRecordSet(query, "error")
        if answer.rrset is None or len(answer.rrset) == 0:
            return DNSRecordSet(query, "no_records")
        authenticated = bool(answer.response is not None and answer.response.flags & dns.flags.AD)
        records = tuple(item.to_text() for item in answer.rrset)
        ttl = int(answer.rrset.ttl)
        return DNSRecordSet(query, "answered", records, authenticated, ttl)
