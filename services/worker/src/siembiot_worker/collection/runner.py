from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from siembiot_worker.collection.broker import CollectorBroker
from siembiot_worker.collection.models import CollectionObservation, ObservationOutcome
from siembiot_worker.collectors.common import FixtureCollectorContext
from siembiot_worker.collectors.ct.collector import CTCollector
from siembiot_worker.collectors.dns.collector import DNSCollector
from siembiot_worker.collectors.email.collector import EmailDNSCollector
from siembiot_worker.collectors.http.collector import HTTPCollector
from siembiot_worker.collectors.rdap.collector import RDAPCollector
from siembiot_worker.collectors.tls.collector import TLSCollector

FIXTURE_BANNER = "FIXTURE DATA — NOT A LIVE ASSESSMENT"


@dataclass(frozen=True)
class FixtureRunInput:
    context: FixtureCollectorContext
    domain: str
    web_host: str
    dkim_selectors: tuple[str, ...] = ()


StepCallback = Callable[[FixtureRunInput], tuple[CollectionObservation, ...]]


@dataclass(frozen=True)
class CollectionStep:
    step_id: str
    callback: StepCallback


@dataclass(frozen=True)
class StepCoverage:
    step_id: str
    status: Literal["completed", "failed", "cancelled"]
    observation_count: int
    reason_code: str


@dataclass(frozen=True)
class FixtureRunResult:
    run_id: str
    status: Literal["completed", "partially_completed", "cancelled", "failed"]
    fixture_only: Literal[True]
    publishable: Literal[False]
    banner: str
    scoring: Literal["not_performed"]
    observations: tuple[CollectionObservation, ...]
    coverage: tuple[StepCoverage, ...]

    def contract_summary(self) -> dict[str, object]:
        return {
            "contract_version": "v1",
            "run_id": self.run_id,
            "execution_mode": "fixture",
            "status": self.status,
            "fixture_only": True,
            "publishable": False,
            "observation_ids": [item.evidence_id for item in self.observations],
            "banner": FIXTURE_BANNER,
        }


class FixtureSuiteRunner:
    def __init__(self, steps: tuple[CollectionStep, ...]) -> None:
        if not steps or len({step.step_id for step in steps}) != len(steps):
            raise ValueError("invalid_collection_steps")
        self.steps = steps

    @classmethod
    def for_broker(cls, broker: CollectorBroker) -> FixtureSuiteRunner:
        dns = DNSCollector(broker)
        email = EmailDNSCollector(broker)
        http = HTTPCollector(broker)
        tls = TLSCollector(broker)
        rdap = RDAPCollector(broker)
        ct = CTCollector(broker)
        return cls(
            (
                CollectionStep("dns", lambda value: dns.collect(value.context, value.domain)),
                CollectionStep(
                    "email-dns",
                    lambda value: email.collect(
                        value.context,
                        value.domain,
                        dkim_selectors=value.dkim_selectors,
                    ),
                ),
                CollectionStep("http", lambda value: http.collect(value.context, value.web_host)),
                CollectionStep("tls", lambda value: (tls.collect(value.context, value.web_host),)),
                CollectionStep("rdap", lambda value: (rdap.collect(value.context, value.domain),)),
                CollectionStep("ct", lambda value: (ct.collect(value.context, value.domain),)),
            )
        )

    @staticmethod
    def _run_id(value: FixtureRunInput) -> str:
        identity = json.dumps(
            {
                "scope_reference": value.context.scope_reference,
                "scenario_id": value.context.scenario_id,
                "scenario_sha256": value.context.scenario_sha256,
                "domain": value.domain,
                "web_host": value.web_host,
                "dkim_selectors": value.dkim_selectors,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return str(uuid.uuid5(uuid.NAMESPACE_URL, identity))

    def run(self, value: FixtureRunInput) -> FixtureRunResult:
        observations: list[CollectionObservation] = []
        coverage: list[StepCoverage] = []
        cancelled = False
        for index, step in enumerate(self.steps):
            if value.context.cancelled is not None and value.context.cancelled():
                coverage.extend(
                    StepCoverage(pending.step_id, "cancelled", 0, "cancelled")
                    for pending in self.steps[index:]
                )
                cancelled = True
                break
            try:
                produced = step.callback(value)
            except Exception:
                coverage.append(StepCoverage(step.step_id, "failed", 0, "collector_error"))
                continue
            observations.extend(produced)
            coverage.append(StepCoverage(step.step_id, "completed", len(produced), "fixture"))

        if cancelled:
            status: Literal["completed", "partially_completed", "cancelled", "failed"] = "cancelled"
        elif all(item.status == "failed" for item in coverage):
            status = "failed"
        elif any(item.status == "failed" for item in coverage) or any(
            item.outcome
            in {
                ObservationOutcome.ERROR,
                ObservationOutcome.UNKNOWN,
                ObservationOutcome.UNAVAILABLE,
                ObservationOutcome.DISABLED_BY_POLICY,
            }
            for item in observations
        ):
            status = "partially_completed"
        else:
            status = "completed"
        return FixtureRunResult(
            self._run_id(value),
            status,
            True,
            False,
            FIXTURE_BANNER,
            "not_performed",
            tuple(observations),
            tuple(coverage),
        )
