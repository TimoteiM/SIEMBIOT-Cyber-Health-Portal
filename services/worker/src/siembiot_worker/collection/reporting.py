from __future__ import annotations

from typing import Any

from siembiot_worker.collection.runner import FixtureRunResult


def render_fixture_report(result: FixtureRunResult) -> dict[str, Any]:
    """Render an explicitly non-live, non-scored fixture report."""

    return {
        "banner": result.banner,
        "fixture_only": True,
        "live_assessment": False,
        "publishable": False,
        "scoring": "not_performed",
        "run": result.contract_summary(),
        "coverage": [
            {
                "step_id": item.step_id,
                "status": item.status,
                "observation_count": item.observation_count,
                "reason_code": item.reason_code,
            }
            for item in result.coverage
        ],
        "observations": [
            observation.model_dump(mode="json") for observation in result.observations
        ],
    }
