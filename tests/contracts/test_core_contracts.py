from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "packages" / "contracts" / "jsonschema" / "v1"


def load_schema(name: str) -> dict[str, Any]:
    return json.loads((SCHEMA_ROOT / f"{name}.json").read_text(encoding="utf-8"))


def validate(name: str, value: dict[str, Any]) -> None:
    Draft202012Validator(load_schema(name), format_checker=FormatChecker()).validate(value)


def test_error_envelope_is_versioned_and_rejects_details() -> None:
    validate(
        "error-envelope",
        {
            "contract_version": "v1",
            "error": {
                "code": "forbidden",
                "message": "The requested operation is not permitted.",
                "request_id": "01K1X6HBFM6W2Y0M76K5G5HT3C",
            },
        },
    )
    with pytest.raises(Exception):
        validate(
            "error-envelope",
            {
                "contract_version": "v1",
                "error": {
                    "code": "internal_error",
                    "message": "database password was exposed",
                    "request_id": "01K1X6HBFM6W2Y0M76K5G5HT3C",
                    "stack_trace": "secret internals",
                },
            },
        )


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        (
            "session",
            {
                "contract_version": "v1",
                "authenticated": True,
                "user": {
                    "id": "018f5f80-8a4b-7c1b-b55e-ea65c91262c0",
                    "email": "owner@example.test",
                    "display_name": "Owner",
                },
                "expires_at": "2026-08-03T13:45:00Z",
                "csrf_token": "opaque-memory-only-token",
            },
        ),
        (
            "organization",
            {
                "contract_version": "v1",
                "id": "018f5f80-8a4b-7c1b-b55e-ea65c91262c1",
                "name": "Exemplu SRL",
                "slug": "exemplu-srl",
                "created_at": "2026-08-03T13:45:00Z",
            },
        ),
        (
            "membership",
            {
                "contract_version": "v1",
                "id": "018f5f80-8a4b-7c1b-b55e-ea65c91262c2",
                "organization_id": "018f5f80-8a4b-7c1b-b55e-ea65c91262c1",
                "user_id": "018f5f80-8a4b-7c1b-b55e-ea65c91262c0",
                "role": "organization_owner",
                "status": "active",
                "created_at": "2026-08-03T13:45:00Z",
            },
        ),
        (
            "invitation",
            {
                "contract_version": "v1",
                "id": "018f5f80-8a4b-7c1b-b55e-ea65c91262c3",
                "organization_id": "018f5f80-8a4b-7c1b-b55e-ea65c91262c1",
                "email": "analyst@example.test",
                "role": "analyst",
                "status": "pending",
                "expires_at": "2026-08-10T13:45:00Z",
                "created_at": "2026-08-03T13:45:00Z",
            },
        ),
        (
            "audit-event",
            {
                "contract_version": "v1",
                "id": "018f5f80-8a4b-7c1b-b55e-ea65c91262c4",
                "organization_id": "018f5f80-8a4b-7c1b-b55e-ea65c91262c1",
                "actor": {"type": "user", "id": "018f5f80-8a4b-7c1b-b55e-ea65c91262c0"},
                "action": "membership.invited",
                "resource": {"type": "invitation", "id": "018f5f80-8a4b-7c1b-b55e-ea65c91262c3"},
                "request_id": "01K1X6HBFM6W2Y0M76K5G5HT3C",
                "correlation_id": "01K1X6HBFM6W2Y0M76K5G5HT3C",
                "occurred_at": "2026-08-03T13:45:00Z",
                "outcome": "success",
                "context": {"role": "analyst"},
            },
        ),
    ],
)
def test_core_contract_accepts_valid_payload(name: str, payload: dict[str, Any]) -> None:
    validate(name, payload)


def test_contracts_reject_unknown_fields_and_non_utc_timestamps() -> None:
    organization = {
        "contract_version": "v1",
        "id": "018f5f80-8a4b-7c1b-b55e-ea65c91262c1",
        "name": "Exemplu SRL",
        "slug": "exemplu-srl",
        "created_at": "2026-08-03T16:45:00+03:00",
        "tenant_secret": "must-not-exist",
    }
    with pytest.raises(Exception):
        validate("organization", organization)


def test_paginated_contract_requires_bounded_page_size() -> None:
    validate(
        "page",
        {
            "contract_version": "v1",
            "items": [],
            "page": {"limit": 50, "next_cursor": None},
        },
    )
    with pytest.raises(Exception):
        validate(
            "page",
            {
                "contract_version": "v1",
                "items": [],
                "page": {"limit": 1000, "next_cursor": None},
            },
        )
