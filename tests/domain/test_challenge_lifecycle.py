from __future__ import annotations

import hashlib

from siembiot.domains.challenges import (
    challenge_location,
    new_challenge_token,
    token_matches_digest,
)
from siembiot.domains.dns_verification import DNSVerificationService


class FakeTXTResolver:
    def __init__(self, records: tuple[str, ...]) -> None:
        self.records = records
        self.queries: list[str] = []

    def resolve_txt(self, name: str) -> tuple[str, ...]:
        self.queries.append(name)
        return self.records


def test_challenge_plaintext_has_single_purpose_prefix_and_digest() -> None:
    token, digest = new_challenge_token()
    assert token.startswith("siembiot-v1=")
    assert len(digest) == 32
    assert digest == hashlib.sha256(token.encode("utf-8")).digest()
    assert token_matches_digest(token, digest)
    assert not token_matches_digest(token + "altered", digest)


def test_dns_verification_queries_only_the_fixed_name() -> None:
    token, digest = new_challenge_token()
    resolver = FakeTXTResolver(("unrelated", token))
    service = DNSVerificationService(resolver)
    assert service.verify("example.com", digest)
    assert resolver.queries == ["_siembiot-verify.example.com"]
    assert challenge_location("example.com", "dns_txt") == "_siembiot-verify.example.com"
    assert (
        challenge_location("example.com", "https_file")
        == "https://example.com/.well-known/siembiot-verification.txt"
    )


def test_dns_verification_does_not_accept_partial_or_combined_tokens() -> None:
    token, digest = new_challenge_token()
    resolver = FakeTXTResolver((f"prefix-{token}", f"{token} suffix"))
    assert not DNSVerificationService(resolver).verify("example.com", digest)
