from __future__ import annotations

from siembiot_worker.scoring.reproduction import reproduce


def test_methodology_fixture_is_byte_reproducible_and_non_publishable() -> None:
    first = reproduce()
    second = reproduce()
    assert first == second
    assert first["snapshot"]["classification"] == "DEMO/FIXTURE"
    assert first["snapshot"]["publishable"] is False
    assert first["policy_hash"].startswith("sha256-v1:")
    assert len(first["evaluations"]) == 6
