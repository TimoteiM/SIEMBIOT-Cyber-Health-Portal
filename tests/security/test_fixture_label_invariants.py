from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from siembiot_worker.collection.models import (
    CollectionObservation,
    ObservationOutcome,
    build_fixture_observation,
)


def test_fixture_output_cannot_be_relabelled_as_live_or_publishable() -> None:
    observation = build_fixture_observation(
        scope_reference="scope-example-test",
        collector_id="dns",
        collector_version="1.0.0",
        adapter_id="fixture-internet",
        adapter_version="1.0.0",
        collected_at=datetime(2026, 8, 3, 12, tzinfo=UTC),
        scenario_id="healthy",
        scenario_sha256="a" * 64,
        outcome=ObservationOutcome.PASS,
        payload={"fixture_only": True},
    )
    payload = observation.model_dump(mode="json")
    for changes in (
        {"publishable": True},
        {"real_world": True},
        {"execution_mode": "live"},
    ):
        with pytest.raises(ValidationError):
            CollectionObservation.model_validate({**payload, **changes})


def test_fixture_contract_contains_no_finding_or_score_fields() -> None:
    forbidden = {"finding", "findings", "score", "risk_score", "live_finding"}
    assert forbidden.isdisjoint(CollectionObservation.model_fields)
