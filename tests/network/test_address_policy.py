from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from siembiot_worker.network_safety.address_policy import (
    AddressPolicyError,
    authorize_resolved_addresses,
    parse_canonical_ip,
)

FIXTURES = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "network" / "destinations.json").read_text(
        encoding="utf-8"
    )
)


@pytest.mark.parametrize("address", FIXTURES["public"])
def test_public_unicast_addresses_are_allowed(address: str) -> None:
    decision = authorize_resolved_addresses([address])
    assert decision.allowed
    assert decision.reason_code == "allowed"
    assert decision.addresses == (address,)


@pytest.mark.parametrize("address", FIXTURES["forbidden"])
def test_special_or_non_public_addresses_are_blocked(address: str) -> None:
    decision = authorize_resolved_addresses([address])
    assert not decision.allowed
    assert decision.reason_code == "forbidden_address"
    assert decision.addresses == ()


@pytest.mark.parametrize("address", FIXTURES["noncanonical"])
def test_alternate_numeric_and_zone_id_forms_are_rejected(address: str) -> None:
    with pytest.raises(AddressPolicyError, match="noncanonical_address"):
        parse_canonical_ip(address)


def test_mixed_public_and_forbidden_dns_answer_fails_closed() -> None:
    decision = authorize_resolved_addresses(["8.8.8.8", "127.0.0.1"])
    assert not decision.allowed
    assert decision.reason_code == "mixed_dns_answers"
    assert decision.addresses == ()


def test_empty_or_malformed_dns_answer_fails_closed() -> None:
    assert authorize_resolved_addresses([]).reason_code == "no_addresses"
    assert authorize_resolved_addresses(["not-an-address"]).reason_code == "invalid_address"


@given(last_octet=st.integers(min_value=0, max_value=255))
def test_entire_loopback_block_is_forbidden(last_octet: int) -> None:
    decision = authorize_resolved_addresses([f"127.0.0.{last_octet}"])
    assert not decision.allowed
