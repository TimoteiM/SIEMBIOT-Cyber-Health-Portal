from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from siembiot_worker.evidence.canonical import (
    CanonicalizationError,
    CanonicalProjection,
    canonical_hash,
    canonical_json,
    parse_json,
)


def test_canonical_json_v1_is_semantic_and_stable() -> None:
    first = {"z": [1, True, None], "a": "România"}
    second = {"a": "România", "z": [1, True, None]}
    assert canonical_json(first) == canonical_json(second)
    assert canonical_hash(first) == canonical_hash(second)
    assert canonical_hash(first).startswith("sha256-v1:")


def test_timestamps_are_normalized_to_utc() -> None:
    utc = datetime(2026, 8, 3, 10, tzinfo=UTC)
    offset = datetime(2026, 8, 3, 12, tzinfo=UTC) + timedelta(0)
    assert canonical_json({"at": utc}) != canonical_json({"at": offset})
    same_instant = datetime.fromisoformat("2026-08-03T12:00:00+02:00")
    assert canonical_hash({"at": utc}) == canonical_hash({"at": same_instant})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), b"secret", datetime(2026, 8, 3)])
def test_ambiguous_or_unsafe_values_are_rejected(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json({"value": value})


def test_identity_projection_excludes_only_declared_volatile_fields() -> None:
    first = {"tenant": "org-a", "payload": {"ok": True}, "created_at": "one"}
    second = {**first, "created_at": "two"}
    assert canonical_hash(first) != canonical_hash(second)
    assert canonical_hash(
        first, projection=CanonicalProjection.CONTENT_IDENTITY_V1
    ) == canonical_hash(second, projection=CanonicalProjection.CONTENT_IDENTITY_V1)


def test_duplicate_json_keys_are_rejected_before_canonicalization() -> None:
    with pytest.raises(CanonicalizationError, match="duplicate_json_key"):
        parse_json('{"tenant":"one","tenant":"two"}')
