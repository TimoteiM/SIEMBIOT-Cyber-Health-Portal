from __future__ import annotations

import pytest
from pydantic import ValidationError
from siembiot_worker.evidence.models import ScoreSnapshot
from siembiot_worker.scoring.reproduction import reproduce


def test_fixture_mode_propagates_through_methodology_output() -> None:
    output = reproduce()
    assert {item["mode"] for item in output["observations"]} == {"fixture"}
    assert {item["mode"] for item in output["evaluations"]} == {"fixture"}
    assert output["snapshot"]["mode"] == "fixture"


def test_fixture_snapshot_cannot_be_relabelled_or_published() -> None:
    payload = reproduce()["snapshot"]
    payload["mode"] = "live"
    payload["publishable"] = True
    payload["classification"] = "PRIVATE"
    with pytest.raises(ValidationError):
        ScoreSnapshot.model_validate(payload)
