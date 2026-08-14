from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError
from siembiot.contracts import DomainCreate, DomainResponse

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "packages" / "contracts" / "jsonschema" / "v1"
SCOPE_SCHEMA = (
    ROOT / "packages" / "contracts" / "jsonschema" / "scope" / "v1" / "scope-manifest.json"
)


def validate(name: str, payload: dict[str, Any]) -> None:
    schema = cast(
        dict[str, Any],
        json.loads((SCHEMA_ROOT / f"{name}.json").read_text(encoding="utf-8")),
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(payload)


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        (
            "domain",
            {
                "contract_version": "v1",
                "id": "018f5f80-8a4b-7c1b-b55e-ea65c9126201",
                "organization_id": "018f5f80-8a4b-7c1b-b55e-ea65c9126202",
                "canonical_name": "xn--coal-3sa77n.ro",
                "unicode_display": "școală.ro",
                "registrable_domain": "xn--coal-3sa77n.ro",
                "warnings": ["idn_present"],
                "ownership_state": "pending",
                "created_at": "2026-08-03T12:00:00Z",
            },
        ),
        (
            "domain-challenge",
            {
                "contract_version": "v1",
                "id": "018f5f80-8a4b-7c1b-b55e-ea65c9126203",
                "domain_id": "018f5f80-8a4b-7c1b-b55e-ea65c9126201",
                "method": "dns_txt",
                "state": "pending",
                "expires_at": "2026-08-03T12:15:00Z",
                "attempts_remaining": 5,
                "verification_location": "_siembiot-verify.xn--coal-3sa77n.ro",
            },
        ),
        (
            "assessment-authorization",
            {
                "contract_version": "v1",
                "id": "018f5f80-8a4b-7c1b-b55e-ea65c9126204",
                "organization_id": "018f5f80-8a4b-7c1b-b55e-ea65c9126202",
                "state": "active",
                "policy_version": "policy-v1",
                "consent_version": "consent-ro-v1",
                "valid_from": "2026-08-03T12:00:00Z",
                "valid_until": "2026-09-03T12:00:00Z",
                "operation_classes": ["https_verification"],
            },
        ),
        (
            "scope-manifest",
            {
                "contract_version": "v1",
                "id": "018f5f80-8a4b-7c1b-b55e-ea65c9126205",
                "authorization_id": "018f5f80-8a4b-7c1b-b55e-ea65c9126204",
                "manifest_version": "v1",
                "payload_sha256": "a" * 64,
                "key_id": "dev-ed25519-2026-08",
                "algorithm": "EdDSA",
                "created_at": "2026-08-03T12:00:00Z",
            },
        ),
        (
            "emergency-control",
            {
                "contract_version": "v1",
                "id": "018f5f80-8a4b-7c1b-b55e-ea65c9126206",
                "scope": "domain",
                "organization_id": "018f5f80-8a4b-7c1b-b55e-ea65c9126202",
                "domain_id": "018f5f80-8a4b-7c1b-b55e-ea65c9126201",
                "reason": "Incident response containment",
                "active": True,
                "created_at": "2026-08-03T12:00:00Z",
            },
        ),
        (
            "network-decision",
            {
                "contract_version": "v1",
                "allowed": False,
                "reason_code": "forbidden_address",
                "operation_class": "https_verification",
                "policy_version": "network-v1",
            },
        ),
    ],
)
def test_domain_scope_contracts_are_strict_and_versioned(
    name: str, payload: dict[str, Any]
) -> None:
    validate(name, payload)
    with pytest.raises(Exception):
        validate(name, {**payload, "unexpected_private_field": "challenge plaintext"})


def test_challenge_contract_never_exposes_digest_or_stored_token() -> None:
    schema = json.loads((SCHEMA_ROOT / "domain-challenge.json").read_text(encoding="utf-8"))
    properties = schema["properties"]
    assert "token_digest" not in properties
    assert "stored_token" not in properties


def test_domain_api_models_are_typed_and_reject_unknown_fields() -> None:
    assert DomainCreate(domain="Example.COM").domain == "Example.COM"
    with pytest.raises(ValidationError):
        DomainResponse.model_validate(
            {
                "contract_version": "v1",
                "id": "018f5f80-8a4b-7c1b-b55e-ea65c9126201",
                "organization_id": "018f5f80-8a4b-7c1b-b55e-ea65c9126202",
                "canonical_name": "example.com",
                "unicode_display": "example.com",
                "registrable_domain": "example.com",
                "warnings": [],
                "ownership_state": "pending",
                "created_at": "2026-08-03T12:00:00Z",
                "token_digest": "not-public",
            }
        )


def test_canonical_scope_payload_has_a_separate_versioned_schema() -> None:
    schema = json.loads(SCOPE_SCHEMA.read_text(encoding="utf-8"))
    payload = {
        "manifest_version": "v1",
        "authorization_id": "018f5f80-8a4b-7c1b-b55e-ea65c9126204",
        "organization_id": "018f5f80-8a4b-7c1b-b55e-ea65c9126202",
        "actor": {
            "type": "user",
            "id": "018f5f80-8a4b-7c1b-b55e-ea65c9126207",
        },
        "targets": [
            {
                "domain_id": "018f5f80-8a4b-7c1b-b55e-ea65c9126201",
                "canonical_host": "example.com",
                "operation_class": "https_verification",
            }
        ],
        "policy_version": "policy-v1",
        "consent": {
            "version": "consent-ro-v1",
            "text": "Autorizez explicit operațiunile declarate pentru acest domeniu.",
            "sha256": "a" * 64,
        },
        "valid_from": "2026-08-03T12:00:00Z",
        "valid_until": "2026-09-03T12:00:00Z",
        "issued_at": "2026-08-03T12:00:00Z",
    }
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(payload)
    with pytest.raises(Exception):
        Draft202012Validator(schema).validate({**payload, "wildcard": "*.example.com"})
