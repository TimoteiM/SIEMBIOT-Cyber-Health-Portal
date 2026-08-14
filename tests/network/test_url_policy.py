from __future__ import annotations

import pytest
from siembiot_worker.network_safety.url_policy import (
    DestinationPolicyError,
    VerificationDestination,
    authorize_redirect,
)


def test_verification_destination_is_fixed_and_structured() -> None:
    destination = VerificationDestination.https("example.com")
    assert destination.scheme == "https"
    assert destination.host == "example.com"
    assert destination.port == 443
    assert destination.path == "/.well-known/siembiot-verification.txt"
    assert destination.host_header == "example.com"
    with pytest.raises(DestinationPolicyError):
        VerificationDestination("https", "127.0.0.1", 443)
    with pytest.raises(DestinationPolicyError):
        VerificationDestination("https", "example.com", 8443)
    with pytest.raises(DestinationPolicyError):
        VerificationDestination("https", "example.com", 443, "/arbitrary")


@pytest.mark.parametrize(
    ("location", "reason"),
    [
        ("http://example.com/.well-known/siembiot-verification.txt", "tls_downgrade"),
        ("https://user:pass@example.com/.well-known/siembiot-verification.txt", "credentials"),
        ("https://example.com/.well-known/siembiot-verification.txt#fragment", "fragment"),
        ("ftp://example.com/.well-known/siembiot-verification.txt", "unsupported_scheme"),
        ("https://example.com:8443/.well-known/siembiot-verification.txt", "forbidden_port"),
        ("https://example.com/other", "forbidden_path"),
        ("https://example.com/.well-known/siembiot-verification.txt?token=x", "query"),
        ("https://EXAMPLE.com/.well-known/siembiot-verification.txt", "noncanonical_host"),
        ("https://example.com./.well-known/siembiot-verification.txt", "noncanonical_host"),
        ("https://127.0.0.1/.well-known/siembiot-verification.txt", "ip_literal"),
    ],
)
def test_redirect_parser_rejects_bypass_forms(location: str, reason: str) -> None:
    current = VerificationDestination.https("example.com")
    with pytest.raises(DestinationPolicyError) as caught:
        authorize_redirect(current, location, authorized_hosts={"example.com"})
    assert caught.value.reason == reason


def test_redirect_is_rebuilt_and_requires_exact_authorized_host() -> None:
    current = VerificationDestination.https("example.com")
    same = authorize_redirect(
        current,
        "https://example.com/.well-known/siembiot-verification.txt",
        authorized_hosts={"example.com"},
    )
    assert same == current
    delegated = authorize_redirect(
        current,
        "https://verify.example.net/.well-known/siembiot-verification.txt",
        authorized_hosts={"example.com", "verify.example.net"},
    )
    assert delegated.host == "verify.example.net"
    with pytest.raises(DestinationPolicyError, match="redirect_not_authorized"):
        authorize_redirect(
            current,
            "https://child.example.com/.well-known/siembiot-verification.txt",
            authorized_hosts={"example.com"},
        )


def test_http_destination_may_upgrade_to_https_but_never_downgrade() -> None:
    current = VerificationDestination.http_upgrade("example.com")
    upgraded = authorize_redirect(
        current,
        "https://example.com/.well-known/siembiot-verification.txt",
        authorized_hosts={"example.com"},
    )
    assert upgraded.scheme == "https"
    assert upgraded.port == 443
