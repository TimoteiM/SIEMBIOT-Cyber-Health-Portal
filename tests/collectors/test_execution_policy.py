from __future__ import annotations

import pytest
from siembiot_worker.collection.models import ExecutionMode
from siembiot_worker.collection.policy import (
    ExecutionDeniedError,
    FixtureOnlyExecutionPolicy,
)


def test_fixture_mode_is_the_only_executable_milestone_3_mode() -> None:
    policy = FixtureOnlyExecutionPolicy(environment="test")
    assert policy.authorize(ExecutionMode.FIXTURE).allowed
    for mode in (
        ExecutionMode.UNAVAILABLE,
        ExecutionMode.DISABLED_BY_POLICY,
        ExecutionMode.LIVE,
    ):
        with pytest.raises(ExecutionDeniedError):
            policy.authorize(mode)


def test_production_fails_closed_without_restricted_egress_boundary() -> None:
    policy = FixtureOnlyExecutionPolicy(environment="production")
    with pytest.raises(ExecutionDeniedError, match="restricted_egress_absent"):
        policy.authorize(ExecutionMode.FIXTURE)
    with pytest.raises(ExecutionDeniedError, match="live_execution_unavailable"):
        policy.authorize(ExecutionMode.LIVE)


def test_environment_text_cannot_enable_live_execution() -> None:
    for environment in ("live", "production-live", "fixture", "development"):
        with pytest.raises(ExecutionDeniedError, match="live_execution_unavailable"):
            FixtureOnlyExecutionPolicy(environment=environment).authorize(ExecutionMode.LIVE)
