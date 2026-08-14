from __future__ import annotations

from typing import Protocol

import dns.exception
import dns.resolver

from siembiot.domains.challenges import token_matches_digest


class TXTResolver(Protocol):
    def resolve_txt(self, name: str) -> tuple[str, ...]: ...


class BoundedTXTResolver:
    def __init__(self, *, lifetime_seconds: float = 3.0, max_records: int = 20) -> None:
        self.lifetime_seconds = lifetime_seconds
        self.max_records = max_records

    def resolve_txt(self, name: str) -> tuple[str, ...]:
        try:
            answer = dns.resolver.resolve(name, "TXT", lifetime=self.lifetime_seconds)
        except (dns.exception.DNSException, TimeoutError):
            return ()
        records: list[str] = []
        for item in answer:
            if len(records) >= self.max_records:
                return ()
            value = b"".join(item.strings).decode("utf-8", errors="strict")
            if len(value) > 512:
                return ()
            records.append(value)
        return tuple(records)


class DNSVerificationService:
    def __init__(self, resolver: TXTResolver) -> None:
        self.resolver = resolver

    def verify(self, canonical_name: str, expected_digest: bytes) -> bool:
        records = self.resolver.resolve_txt(f"_siembiot-verify.{canonical_name}")
        return any(token_matches_digest(record, expected_digest) for record in records)
