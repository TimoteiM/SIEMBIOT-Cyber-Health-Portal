from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from siembiot_worker.collection.models import ObservationOutcome, build_fixture_observation
from siembiot_worker.evaluation.engine import EvaluationContext, evaluate_check
from siembiot_worker.evaluation.policy import load_policy_catalog
from siembiot_worker.normalization.registry import normalize_observation
from siembiot_worker.scoring.attribution import attribute_score_change
from siembiot_worker.scoring.engine import score_evaluations

NOW = datetime(2026, 8, 3, 12, tzinfo=UTC)
SOURCES: tuple[tuple[str, dict[str, Any]], ...] = (
    ("dns", {"record_type": "DNSSEC", "secure": True}),
    ("email-dns", {"check": "DMARC", "policy": "reject"}),
    ("http", {"status": 200, "headers": {"strict-transport-security": "max-age=1"}}),
    ("rdap", {"status": ["active"]}),
    ("ct", {"asserted_names": ["portal.example.test"], "asset_authorized": False}),
)


def reproduce(root: Path | None = None) -> dict[str, Any]:
    repository = root or Path(__file__).resolve().parents[5]
    catalog = load_policy_catalog(repository / "packages/policy/checks/v1")
    observations = []
    for collector, payload in SOURCES:
        source = build_fixture_observation(
            scope_reference="fixture-scope-v1",
            collector_id=collector,
            collector_version="1.0.0",
            adapter_id=f"fixture-{collector}",
            adapter_version="1.0.0",
            collected_at=NOW,
            scenario_id="healthy",
            scenario_sha256="b" * 64,
            outcome=ObservationOutcome.PASS,
            payload=payload,
        )
        observations.append(
            normalize_observation(source, organization_id="fixture-org", asset_id="fixture-asset")
        )
    context = EvaluationContext(evaluated_at=NOW)
    evaluations = tuple(
        evaluate_check(
            check,
            tuple(observations),
            catalog,
            context,
            organization_id="fixture-org",
            asset_id="fixture-asset",
            mode="fixture",
        )
        for check in catalog.checks
    )
    snapshot = score_evaluations(evaluations, catalog, created_at=NOW)
    attributions = attribute_score_change(snapshot, None, created_at=NOW)
    return {
        "methodology_version": catalog.methodology_version,
        "policy_hash": catalog.policy_hash,
        "observations": [
            item.model_dump(mode="json")
            for item in sorted(observations, key=lambda item: item.normalized_id)
        ],
        "evaluations": [item.model_dump(mode="json") for item in evaluations],
        "snapshot": snapshot.model_dump(mode="json"),
        "attributions": [item.model_dump(mode="json") for item in attributions],
    }
