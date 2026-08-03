from __future__ import annotations

from pathlib import Path

import pytest
from siembiot_worker.collection.broker import (
    BrokerBudget,
    BrokerRequestError,
    FixtureInternetBroker,
    HTTPFixtureRequest,
)
from siembiot_worker.collection.fixtures import FixtureScenarioPack

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "fake_internet" / "v1"


@pytest.fixture
def broker() -> FixtureInternetBroker:
    return FixtureInternetBroker(FixtureScenarioPack.load(FIXTURE_ROOT))


def test_broker_has_only_purpose_specific_fixture_operations(
    broker: FixtureInternetBroker,
) -> None:
    assert not hasattr(broker, "fetch")
    assert not hasattr(broker, "request")
    assert broker.resolve_dns("healthy", "portal.example.test", "MX").allowed
    assert broker.handshake_tls("healthy", "portal.example.test").allowed
    assert broker.query_rdap("healthy", "example.test").allowed
    assert broker.query_ct("healthy", "example.test").allowed


def test_http_result_is_deterministic_and_uses_fixture_timestamp(
    broker: FixtureInternetBroker,
) -> None:
    request = HTTPFixtureRequest.https("portal.example.test", method="HEAD")
    first = broker.fetch_http("healthy", request)
    second = broker.fetch_http("healthy", request)
    assert first == second
    assert first.allowed
    assert first.fixture_timestamp.isoformat() == "2026-08-03T12:00:00+00:00"


@pytest.mark.parametrize(
    ("scenario", "host", "reason"),
    [
        ("adversarial", "private.example.test", "forbidden_address"),
        ("adversarial", "mixed.example.test", "mixed_dns_answers"),
    ],
)
def test_ssrf_destinations_are_denied(
    broker: FixtureInternetBroker, scenario: str, host: str, reason: str
) -> None:
    result = broker.fetch_http(scenario, HTTPFixtureRequest.https(host))
    assert not result.allowed
    assert result.reason_code == reason
    assert result.data == {}


def test_redirect_is_revalidated_and_dns_rebinding_is_denied(
    broker: FixtureInternetBroker,
) -> None:
    safe = broker.fetch_http(
        "adversarial",
        HTTPFixtureRequest.https(
            "redirect.example.test",
            authorized_redirect_hosts=("target.example.test",),
        ),
    )
    assert safe.allowed
    assert safe.redirect_count == 1

    rebound = broker.fetch_http("adversarial", HTTPFixtureRequest.https("rebind.example.test"))
    assert not rebound.allowed
    assert rebound.reason_code == "forbidden_address"


def test_cross_host_redirect_requires_explicit_authorization(
    broker: FixtureInternetBroker,
) -> None:
    result = broker.fetch_http("adversarial", HTTPFixtureRequest.https("redirect.example.test"))
    assert not result.allowed
    assert result.reason_code == "redirect_not_authorized"


def test_timeout_cancellation_size_and_malformed_fail_safely(
    broker: FixtureInternetBroker,
) -> None:
    assert (
        broker.fetch_http(
            "adversarial", HTTPFixtureRequest.https("timeout.example.test")
        ).reason_code
        == "timeout"
    )
    assert (
        broker.fetch_http(
            "adversarial", HTTPFixtureRequest.https("malformed.example.test")
        ).reason_code
        == "malformed_response"
    )

    bounded = FixtureInternetBroker(
        FixtureScenarioPack.load(FIXTURE_ROOT), BrokerBudget(max_body_bytes=4)
    )
    assert (
        bounded.fetch_http(
            "adversarial", HTTPFixtureRequest.https("large.example.test")
        ).reason_code
        == "response_too_large"
    )

    checkpoints = 0

    def cancelled() -> bool:
        nonlocal checkpoints
        checkpoints += 1
        return checkpoints >= 2

    result = broker.fetch_http(
        "healthy", HTTPFixtureRequest.https("portal.example.test"), cancelled=cancelled
    )
    assert result.reason_code == "cancelled"
    assert result.data == {}


def test_inputs_are_canonical_and_scenario_failures_are_structured(
    broker: FixtureInternetBroker,
) -> None:
    with pytest.raises(BrokerRequestError, match="noncanonical_host"):
        HTTPFixtureRequest.https("Portal.Example.Test")
    with pytest.raises(BrokerRequestError, match="method_not_allowed"):
        HTTPFixtureRequest.https("portal.example.test", method="POST")  # type: ignore[arg-type]

    result = broker.fetch_http("missing", HTTPFixtureRequest.https("portal.example.test"))
    assert not result.allowed
    assert result.reason_code == "scenario_not_found"


def test_partial_failure_keeps_independent_fixture_operations(
    broker: FixtureInternetBroker,
) -> None:
    dns = broker.resolve_dns("partial-failure", "portal.example.test", "A")
    http = broker.fetch_http("partial-failure", HTTPFixtureRequest.https("portal.example.test"))
    tls = broker.handshake_tls("partial-failure", "portal.example.test")
    assert dns.allowed
    assert not http.allowed and http.reason_code == "timeout"
    assert tls.allowed


def test_cancellation_callback_is_cooperative_not_transport_capable(
    broker: FixtureInternetBroker,
) -> None:
    def callback() -> bool:
        return True

    assert broker.query_ct("healthy", "example.test", cancelled=callback).reason_code == (
        "cancelled"
    )
