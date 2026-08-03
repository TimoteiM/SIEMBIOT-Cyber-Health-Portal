from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from siembiot_worker.evidence.models import EvidenceMode, Finding
from siembiot_worker.findings.events import FindingEvent, FindingEventType
from siembiot_worker.findings.fingerprint import (
    FingerprintCollisionError,
    FingerprintRegistry,
    finding_fingerprint,
)
from siembiot_worker.findings.projection import project_finding

NOW = datetime(2026, 8, 3, 12, tzinfo=UTC)


def identity(**changes: object) -> dict[str, object]:
    values: dict[str, object] = {
        "organization_id": "org-a",
        "asset_id": "asset-a",
        "check_id": "dns.dnssec",
        "policy_hash": "sha256-v1:" + "a" * 64,
        "mode": EvidenceMode.FIXTURE,
        "material_evidence_key": "dnssec-chain",
        "attribution_state": "direct",
    }
    values.update(changes)
    return values


def event(event_type: FindingEventType, **changes: object) -> FindingEvent:
    values: dict[str, object] = {
        "finding_id": finding_fingerprint(**identity()),
        "organization_id": "org-a",
        "event_type": event_type,
        "actor_id": "user-a",
        "reason": "Documented security decision",
        "scope_reference": "scope-a",
        "occurred_at": NOW,
        "request_id": "01K1X6HBFM6W2Y0M76K5G5HT3C",
        "correlation_id": "01K1X6HBFM6W2Y0M76K5G5HT3D",
        "audit_event_id": "audit-a",
        "authorized": True,
    }
    values.update(changes)
    return FindingEvent.build(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "field",
    [
        "organization_id",
        "asset_id",
        "check_id",
        "policy_hash",
        "mode",
        "material_evidence_key",
        "attribution_state",
    ],
)
def test_fingerprint_never_merges_incompatible_identity(field: str) -> None:
    first = finding_fingerprint(**identity())
    changed = {"mode": EvidenceMode.LIVE if field == "mode" else "different"}
    assert finding_fingerprint(**identity(**{field: changed.get(field, "different")})) != first


def test_fingerprint_collision_fails_closed() -> None:
    registry = FingerprintRegistry()
    fingerprint = registry.register(identity())
    with pytest.raises(FingerprintCollisionError, match="finding_fingerprint_collision"):
        registry.register(identity(asset_id="asset-b"), asserted_fingerprint=fingerprint)


@pytest.mark.parametrize("key", ["raw secret value", "x" * 129, "line\nbreak"])
def test_material_evidence_key_is_a_bounded_identifier(key: str) -> None:
    with pytest.raises(ValueError, match="unsafe_material_evidence_key"):
        finding_fingerprint(**identity(material_evidence_key=key))


def test_runtime_finding_recomputes_fingerprint() -> None:
    values = identity()
    with pytest.raises(ValueError, match="finding_id_mismatch"):
        Finding.model_validate(
            {
                **values,
                "finding_id": "sha256-v1:" + "0" * 64,
                "fingerprint_version": "fingerprint-v1",
                "scope_reference": "scope-a",
                "severity": "high",
                "first_seen_at": NOW,
                "publishable": False,
                "classification": "DEMO/FIXTURE",
            }
        )


def test_decision_events_require_authorization_reason_and_review_date() -> None:
    with pytest.raises(ValueError, match="finding_event_not_authorized"):
        event(FindingEventType.SUPPRESSED, authorized=False, review_at=NOW + timedelta(days=30))
    with pytest.raises(ValueError, match="decision_review_required"):
        event(FindingEventType.ACCEPTED_RISK)
    accepted = event(FindingEventType.ACCEPTED_RISK, review_at=NOW + timedelta(days=30))
    assert accepted.event_id.startswith("sha256-v1:")


def test_projection_preserves_history_and_surfaces_expiry() -> None:
    events = (
        event(FindingEventType.OBSERVED),
        event(FindingEventType.SUPPRESSED, review_at=NOW + timedelta(days=1)),
    )
    active = project_finding(events, as_of=NOW)
    expired = project_finding(events, as_of=NOW + timedelta(days=2))
    assert active.state == "suppressed" and not active.review_due
    assert expired.state == "suppressed" and expired.review_due
    assert expired.first_seen_at == NOW and len(expired.events) == 2


def test_reopening_and_verification_are_new_events() -> None:
    events = (
        event(FindingEventType.OBSERVED),
        event(FindingEventType.ACCEPTED_RISK, review_at=NOW + timedelta(days=30)),
        event(FindingEventType.REOPENED, occurred_at=NOW + timedelta(days=1)),
        event(FindingEventType.REMEDIATION_VERIFIED, occurred_at=NOW + timedelta(days=2)),
    )
    projection = project_finding(events, as_of=NOW + timedelta(days=2))
    assert projection.state == "verified"
    assert len(projection.events) == 4
