"""The concrete assessment step handlers.

Each handler is a thin adapter: it calls one already-tested component and translates the
outcome into a ``StepOutcome``. Nothing here re-implements collection, normalization or
scoring, because a second implementation could disagree with the first.

The judgement in this module is entirely about **which failures are worth retrying**:

* a provider that timed out may succeed on the next attempt, so it retries;
* a domain that is not in the registry will still not be there in thirty seconds, so it
  fails permanently rather than burning the retry budget and the provider's patience;
* a defect in our own deterministic code will reproduce exactly, so it fails permanently
  too — retrying a bug is just a slower bug.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from siembiot_worker.adapters.contract import CollectionResult, CollectionStatus
from siembiot_worker.collectors.ct_log import CertificateTransparencyCollector, CTEntrySource
from siembiot_worker.collectors.dns_records import DNSResilienceCollector
from siembiot_worker.collectors.email_records import EmailTrustCollector
from siembiot_worker.collectors.http_surface import HTTPSurfaceCollector
from siembiot_worker.collectors.rdap import RDAPCollector
from siembiot_worker.collectors.tls_certificate import TLSCertificateCollector
from siembiot_worker.network_safety.collection_broker import CollectionNetworkBroker
from siembiot_worker.network_safety.collection_policy import OperationClass
from siembiot_worker.observation.pipeline import EmptyCTSource
from siembiot_worker.observation.runtime import ObservationRuntime
from siembiot_worker.policy.catalog import PolicyCatalog
from siembiot_worker.policy.evaluation import evaluate_assessment
from siembiot_worker.policy.evidence import (
    CheckEvaluation,
    NormalizedObservation,
    Subject,
)
from siembiot_worker.policy.findings import Finding, derive_findings
from siembiot_worker.policy.normalization import (
    derive_freshness_observation,
    domain_subject,
    normalize_ct,
    normalize_dns,
    normalize_email,
    normalize_http,
    normalize_rdap,
    normalize_tls,
)
from siembiot_worker.policy.scoring import ScoreSnapshot, compute_score
from siembiot_worker.workflows.assets import AssetCandidate, candidates_from_ct
from siembiot_worker.workflows.engine import StepContext, StepHandler, StepOutcome

#: Collection outcomes that will not improve by trying again. Everything else is
#: treated as transient, because assuming a failure is permanent risks discarding
#: evidence that a second attempt would have produced.
PERMANENT_COLLECTION_REASONS = frozenset(
    {
        "domain_not_in_registry",
        "operation_class_requires_authorization",
        "operation_class_mismatch",
        "invalid_rdap_document",
        "tls_inspector_unavailable",
    }
)


@dataclass
class AssessmentContext:
    """Everything the handlers share for one run, including what they produce."""

    organization_id: UUID
    assessment_id: UUID
    host: str
    catalog: PolicyCatalog
    runtime: ObservationRuntime
    clock: Callable[[], datetime]
    declared_dkim_selectors: tuple[str, ...] = ()
    rdap_endpoint: str = "rdap.org"
    ct_source: CTEntrySource = field(default_factory=EmptyCTSource)
    probe_tls_protocols: bool = False

    collection: dict[str, CollectionResult] = field(default_factory=dict)
    observations: tuple[NormalizedObservation, ...] = ()
    evaluations: tuple[CheckEvaluation, ...] = ()
    snapshot: ScoreSnapshot | None = None
    findings: tuple[Finding, ...] = ()
    asset_candidates: tuple[AssetCandidate, ...] = ()

    @property
    def broker(self) -> CollectionNetworkBroker:
        return self.runtime.broker

    @property
    def subject(self) -> Subject:
        return domain_subject(self.host)

    @property
    def freshness_window_seconds(self) -> int:
        windows = self.catalog.methodology.freshness_windows_seconds
        return max(windows.values()) if windows else 604_800


def _collection_outcome(name: str, result: CollectionResult) -> StepOutcome:
    """Translate a collection result, distinguishing transient from permanent."""
    if result.usable:
        return StepOutcome.ok(**{f"{name}_status": str(result.status)})
    reason = result.reason_code or "collection_failed"
    if result.status is CollectionStatus.NOT_APPLICABLE or reason in PERMANENT_COLLECTION_REASONS:
        return StepOutcome.fail(reason)
    return StepOutcome.retry(reason)


def build_handlers(context: AssessmentContext) -> dict[str, StepHandler]:
    """Bind the step graph to real work over one assessment context."""

    def plan(step: StepContext) -> StepOutcome:
        """Freeze what this run will do before it does any of it."""
        step.check_cancelled()
        coverage = len(context.catalog.checks)
        return StepOutcome.ok(
            host=context.host,
            methodology_version=context.catalog.methodology.version,
            policy_digest=context.catalog.digest,
            planned_checks=coverage,
        )

    def collect(name: str, operation_class: OperationClass) -> StepHandler:
        def run(step: StepContext) -> StepOutcome:
            step.check_cancelled()
            request = context.runtime.request(operation_class, context.host)
            if name == "dns":
                result = DNSResilienceCollector(context.broker, context.clock).collect(request)
            elif name == "email":
                result = EmailTrustCollector(context.broker, context.clock).collect(
                    request, declared_dkim_selectors=context.declared_dkim_selectors
                )
            elif name == "tls":
                result = TLSCertificateCollector(context.broker, context.clock).collect(
                    request, probe_protocols=context.probe_tls_protocols
                )
            elif name == "http":
                result = HTTPSurfaceCollector(context.broker, context.clock).collect(request)
            elif name == "rdap":
                result = RDAPCollector(
                    context.broker, context.rdap_endpoint, context.clock
                ).collect(request)
            else:
                result = CertificateTransparencyCollector(
                    context.broker, context.ct_source, context.clock
                ).collect(request)
            context.collection[name] = result
            return _collection_outcome(name, result)

        return run

    def normalize(step: StepContext) -> StepOutcome:
        """Turn whatever was collected into immutable observations.

        A collector that failed simply contributes nothing. Normalization does not
        invent a substitute, so the missing evidence shows up as reduced coverage
        rather than as a result.
        """
        step.check_cancelled()
        shared: dict[str, Any] = {
            "organization_id": context.organization_id,
            "assessment_id": context.assessment_id,
            "subject": context.subject,
            "now": context.clock(),
            "window_seconds": context.freshness_window_seconds,
        }
        # Dispatched explicitly rather than through a table: the normalizers do not
        # share one signature, and a table would hide that behind an untyped call.
        observations: list[NormalizedObservation] = []
        if (dns := context.collection.get("dns")) is not None:
            observations.extend(normalize_dns(dns, **shared))
        if (email := context.collection.get("email")) is not None:
            observations.extend(normalize_email(email, **shared))
        if (tls := context.collection.get("tls")) is not None:
            observations.extend(normalize_tls(tls, **shared))
        if (http := context.collection.get("http")) is not None:
            observations.extend(normalize_http(http, **shared))
        if (rdap := context.collection.get("rdap")) is not None:
            observations.extend(normalize_rdap(rdap, **shared))
        if (ct := context.collection.get("ct")) is not None:
            observations.extend(normalize_ct(ct, **shared))

        if not observations:
            return StepOutcome.fail("no_evidence_collected")

        observations.append(
            derive_freshness_observation(
                tuple(observations),
                organization_id=context.organization_id,
                assessment_id=context.assessment_id,
                subject=context.subject,
                now=context.clock(),
                windows=context.catalog.methodology.freshness_windows_seconds,
            )
        )
        context.observations = tuple(observations)
        return StepOutcome.ok(observation_count=len(context.observations))

    def evaluate(step: StepContext) -> StepOutcome:
        step.check_cancelled()
        context.evaluations = evaluate_assessment(
            context.catalog,
            context.observations,
            organization_id=context.organization_id,
            assessment_id=context.assessment_id,
            subject=context.subject,
            evaluated_at=context.clock(),
        )
        return StepOutcome.ok(evaluation_count=len(context.evaluations))

    def score(step: StepContext) -> StepOutcome:
        step.check_cancelled()
        snapshot = compute_score(
            context.catalog,
            context.evaluations,
            context.observations,
            snapshot_id=uuid4(),
            organization_id=context.organization_id,
            assessment_id=context.assessment_id,
            computed_at=context.clock(),
        )
        context.snapshot = snapshot
        return StepOutcome.ok(
            score=snapshot.score,
            band=snapshot.band,
            coverage=snapshot.coverage.percentage,
        )

    def findings(step: StepContext) -> StepOutcome:
        step.check_cancelled()
        context.findings = derive_findings(
            context.catalog,
            context.evaluations,
            organization_id=context.organization_id,
            assessment_id=context.assessment_id,
            observed_at=context.clock(),
        )
        ct_result = context.collection.get("ct")
        if ct_result is not None and ct_result.usable:
            context.asset_candidates = candidates_from_ct(
                ct_result.payload, observed_at=context.clock()
            )
        return StepOutcome.ok(
            finding_count=len(context.findings),
            asset_candidate_count=len(context.asset_candidates),
        )

    def agent_analysis(step: StepContext) -> StepOutcome:
        """Optional by design.

        The model is disabled by default and the assessment must complete without it,
        so this reports that it was skipped rather than failing the run.
        """
        del step
        return StepOutcome.ok(agent_analysis="skipped_model_disabled")

    def report(step: StepContext) -> StepOutcome:
        step.check_cancelled()
        if context.snapshot is None:
            return StepOutcome.fail("no_snapshot_to_report")
        return StepOutcome.ok(report_ready=True)

    return {
        "plan": plan,
        "collect.dns": collect("dns", OperationClass.DNS_QUERY),
        "collect.email": collect("email", OperationClass.DNS_QUERY),
        "collect.tls": collect("tls", OperationClass.TLS_INSPECTION),
        "collect.http": collect("http", OperationClass.HTTP_SURFACE),
        "collect.rdap": collect("rdap", OperationClass.RDAP_QUERY),
        "collect.ct": collect("ct", OperationClass.CT_QUERY),
        "normalize": normalize,
        "evaluate": evaluate,
        "score": score,
        "findings": findings,
        "agent_analysis": agent_analysis,
        "report": report,
    }
