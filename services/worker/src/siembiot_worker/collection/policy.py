from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from siembiot_worker.collection.models import ExecutionMode


class ExecutionDeniedError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class ExecutionAuthorization:
    allowed: bool
    execution_mode: ExecutionMode
    reason_code: str


class DeploymentEnvironment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    CI = "ci"
    PRODUCTION = "production"


class FixtureOnlyExecutionPolicy:
    def __init__(self, *, environment: DeploymentEnvironment) -> None:
        if not isinstance(environment, DeploymentEnvironment):
            raise ExecutionDeniedError("invalid_environment")
        self._environment = environment

    def authorize(self, mode: ExecutionMode) -> ExecutionAuthorization:
        if mode is ExecutionMode.LIVE:
            raise ExecutionDeniedError("live_execution_unavailable")
        if self._environment is DeploymentEnvironment.PRODUCTION:
            raise ExecutionDeniedError("restricted_egress_absent")
        if mode is not ExecutionMode.FIXTURE:
            raise ExecutionDeniedError(f"execution_mode_not_runnable:{mode.value}")
        return ExecutionAuthorization(True, mode, "fixture_only")
