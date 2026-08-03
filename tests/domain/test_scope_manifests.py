from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from siembiot.domains.manifests import (
    canonical_manifest_bytes,
    manifest_allows_target,
    manifest_is_current,
    scope_manifest_payload,
)
from siembiot.domains.signing import (
    Ed25519ManifestSigner,
    ManifestKeySet,
    ensure_signer_allowed,
)


def payload() -> dict[str, object]:
    now = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)
    return scope_manifest_payload(
        authorization_id=uuid4(),
        organization_id=uuid4(),
        actor_id=uuid4(),
        targets=[
            {
                "domain_id": str(uuid4()),
                "canonical_host": "example.com",
                "operation_class": "https_verification",
            }
        ],
        policy_version="policy-v1",
        consent_version="consent-ro-v1",
        consent_text="Autorizez explicit operațiunile declarate pentru acest domeniu.",
        valid_from=now,
        valid_until=now + timedelta(days=30),
        issued_at=now,
    )


def test_canonical_manifest_is_stable_utf8_without_insignificant_whitespace() -> None:
    first = payload()
    reordered = dict(reversed(list(first.items())))
    encoded = canonical_manifest_bytes(first)
    assert encoded == canonical_manifest_bytes(reordered)
    assert encoded == json.dumps(
        first, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    assert b"\n" not in encoded
    assert b": " not in encoded


def test_signature_verification_rotation_and_tamper_detection() -> None:
    old = Ed25519ManifestSigner.generate("dev-old", development_only=True)
    new = Ed25519ManifestSigner.generate("kms-new", development_only=False)
    encoded = canonical_manifest_bytes(payload())
    signature = old.sign(encoded)
    rotated = ManifestKeySet([old.public_key(), new.public_key()])
    assert rotated.verify("dev-old", "EdDSA", encoded, signature)
    assert not rotated.verify("unknown", "EdDSA", encoded, signature)
    assert not rotated.verify("dev-old", "EdDSA", encoded + b"x", signature)
    assert not rotated.verify("dev-old", "RS256", encoded, signature)


def test_production_rejects_development_signing_key() -> None:
    development = Ed25519ManifestSigner.generate("dev-ephemeral", development_only=True)
    ensure_signer_allowed("development", development)
    with pytest.raises(RuntimeError, match="development-only"):
        ensure_signer_allowed("production", development)


def test_manifest_target_and_validity_are_exact_and_fail_closed() -> None:
    manifest = payload()
    now = datetime(2026, 8, 10, tzinfo=UTC)
    assert manifest_allows_target(manifest, "example.com", "https_verification")
    assert not manifest_allows_target(manifest, "child.example.com", "https_verification")
    assert not manifest_allows_target(manifest, "example.com", "active_assessment")
    assert manifest_is_current(manifest, now=now, authorization_state="active")
    assert not manifest_is_current(manifest, now=now, authorization_state="revoked")
    assert not manifest_is_current(
        manifest, now=datetime(2027, 1, 1, tzinfo=UTC), authorization_state="active"
    )


def test_canonical_manifest_rejects_floats_and_non_json_values() -> None:
    with pytest.raises(ValueError, match="canonical JSON"):
        canonical_manifest_bytes({"budget": 1.5})
    with pytest.raises(ValueError, match="canonical JSON"):
        canonical_manifest_bytes({"opaque": object()})
