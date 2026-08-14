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
from siembiot_worker.collectors.mail_transport import MailTransportCollector
from siembiot_worker.collectors.network_attribution import NetworkAttributionCollector
from siembiot_worker.collectors.port_surface import PortSurfaceCollector
from siembiot_worker.collectors.rdap import RDAPCollector
from siembiot_worker.collectors.reputation import ReputationCollector, ReputationProvider
from siembiot_worker.collectors.tls_certificate import TLSCertificateCollector
from siembiot_worker.network_safety.collection_broker import CollectionNetworkBroker
from siembiot_worker.network_safety.collection_policy import OperationClass
from siembiot_worker.observation.mode import allowed_operation_classes
from siembiot_worker.observation.pipeline import EmptyCTSource, withhold_unavailable_checks
from siembiot_worker.observation.runtime import ObservationRuntime
from siembiot_worker.policy.catalog import HOST_SCOPED_OBSERVATION_PREFIXES, PolicyCatalog
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
    normalize_attribution,
    normalize_ct,
    normalize_dns,
    normalize_email,
    normalize_http,
    normalize_mail_transport,
    normalize_ports,
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

    #: Reputation sources, and empty by default on purpose. No provider ships: Spamhaus's
    #: terms do not address using their data inside a tool offered to other organisations,
    #: and an unanswered licence question is not something to build past. With none
    #: configured the collector reports `reputation_provider_unconfigured` and the check
    #: resolves to `unknown` -- a platform with no reputation key must not report a clean
    #: reputation for anybody.
    reputation_providers: tuple[ReputationProvider, ...] = ()

    #: Hosts a person accepted into scope, assessed alongside the domain itself. Empty
    #: unless somebody reviewed a discovered candidate and said yes: discovery is not
    #: ownership, so nothing is probed because a certificate log mentioned it.
    accepted_assets: tuple[str, ...] = ()

    collection: dict[str, CollectionResult] = field(default_factory=dict)
    observations: tuple[NormalizedObservation, ...] = ()
    evaluations: tuple[CheckEvaluation, ...] = ()
    #: Kept apart from `observations` and `evaluations` rather than merged into them.
    #: The score is computed from the domain's own results under methodology 1.0.0, and
    #: one shared list would let a subdomain silently move the domain's number.
    asset_observations: tuple[NormalizedObservation, ...] = ()
    asset_evaluations: tuple[CheckEvaluation, ...] = ()
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
    """Translate a collection result into three genuinely different outcomes.

    Transient and permanent failures are distinguished so a retry budget is not spent
    on something that cannot succeed. `not_applicable` is distinguished from both:
    nothing went wrong, so it must not degrade the run to `partially_completed` and
    report a problem the reader would go looking for and never find.
    """
    if result.usable:
        return StepOutcome.ok(**{f"{name}_status": str(result.status)})
    reason = result.reason_code or "collection_failed"
    if result.status is CollectionStatus.NOT_APPLICABLE:
        return StepOutcome.skip(reason)
    if reason in PERMANENT_COLLECTION_REASONS:
        return StepOutcome.fail(reason)
    return StepOutcome.retry(reason)


#: Every collector, and the operation class it runs under. Declared once: the step
#: registration below and the recovery path in `normalize` both read it, so a collector
#: added later cannot be registered and then quietly left out of recovery.
COLLECTOR_OPERATIONS: dict[str, OperationClass] = {
    "dns": OperationClass.DNS_QUERY,
    "email": OperationClass.DNS_QUERY,
    "tls": OperationClass.TLS_INSPECTION,
    "http": OperationClass.HTTP_SURFACE,
    "rdap": OperationClass.RDAP_QUERY,
    "ct": OperationClass.CT_QUERY,
    "ports": OperationClass.PORT_PROBE,
    "asn": OperationClass.DNS_QUERY,
    "mail_tls": OperationClass.SMTP_STARTTLS,
    "reputation": OperationClass.REPUTATION_QUERY,
}


def _mail_hosts(context: AssessmentContext) -> tuple[str, ...]:
    """The MX hosts the e-mail collector observed, in preference order.

    Read from that observation rather than resolved again, for the reason attribution
    reads the DNS collector's addresses: a second lookup can answer differently, and
    transport reported for a mail host the rest of the assessment never saw describes
    neither. Where the e-mail step failed there is nothing to check, and the collector
    reports that as not applicable rather than as mail with no encryption.
    """
    email = context.collection.get("email")
    if email is None or not email.usable:
        return ()
    hosts = email.payload.get("mx", {}).get("hosts", [])
    ordered = sorted(hosts, key=lambda entry: entry.get("preference", 0))
    return tuple(entry["exchange"] for entry in ordered if entry.get("exchange"))


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

    def collect_one(name: str, operation_class: OperationClass) -> CollectionResult:
        """Run one collector. Pure with respect to the run: it reads public data only."""
        request = context.runtime.request(operation_class, context.host)
        if name == "dns":
            return DNSResilienceCollector(context.broker, context.clock).collect(request)
        if name == "email":
            return EmailTrustCollector(context.broker, context.clock).collect(
                request, declared_dkim_selectors=context.declared_dkim_selectors
            )
        if name == "tls":
            return TLSCertificateCollector(context.broker, context.clock).collect(
                request, probe_protocols=context.probe_tls_protocols
            )
        if name == "http":
            return HTTPSurfaceCollector(context.broker, context.clock).collect(request)
        if name == "rdap":
            return RDAPCollector(context.broker, context.rdap_endpoint, context.clock).collect(
                request
            )
        if name == "ports":
            return PortSurfaceCollector(context.broker, context.clock).collect(request)
        if name == "asn":
            dns = context.collection.get("dns")
            addresses = (
                tuple(dns.payload.get("addresses", {}).get("ipv4", []))
                if dns is not None and dns.usable
                else ()
            )
            return NetworkAttributionCollector(context.broker, context.clock).collect(
                request, addresses
            )
        if name == "reputation":
            # Asks providers about the host; makes no request to the institution, which
            # is why it takes the host rather than a collection request.
            return ReputationCollector(context.reputation_providers, context.clock).collect(
                context.host
            )
        if name == "mail_tls":
            return MailTransportCollector(context.broker, context.clock).collect(
                request, _mail_hosts(context)
            )
        return CertificateTransparencyCollector(
            context.broker, context.ct_source, context.clock
        ).collect(request)

    def collect(name: str, operation_class: OperationClass) -> StepHandler:
        def run(step: StepContext) -> StepOutcome:
            step.check_cancelled()
            # A passive run does not attempt the operation and then get refused; it never
            # asks. The broker would refuse anyway, but a refusal recorded against a run
            # nobody authorized reads as an attempt that was blocked rather than one that
            # was never made.
            if operation_class not in allowed_operation_classes(context.runtime.mode):
                return StepOutcome.skip("requires_authorized_assessment")
            # A source nobody configured is not a source that failed. Reputation is the
            # only collector that can be absent by choice rather than by outage, and
            # running it anyway would mark every assessment partially completed for as
            # long as no key existed -- an institution reading "partially completed"
            # about a provider they never asked for.
            #
            # The distinction this preserves is between "we chose not to look" and "we
            # looked and could not see": skipping leaves the check `not_applicable` and
            # coverage untouched, whereas a configured provider that cannot be reached
            # still returns `inconclusive` and still costs coverage, which is correct --
            # that is a gap in what was measured rather than a decision.
            if name == "reputation" and not context.reputation_providers:
                return StepOutcome.skip("no_reputation_provider_configured")
            result = collect_one(name, operation_class)
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
        _recover_lost_collections(step)
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
        if (ports := context.collection.get("ports")) is not None:
            observations.extend(normalize_ports(ports, **shared))
        if (asn := context.collection.get("asn")) is not None:
            observations.extend(normalize_attribution(asn, **shared))
        if (mail_tls := context.collection.get("mail_tls")) is not None:
            observations.extend(normalize_mail_transport(mail_tls, **shared))

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

    def _recover_lost_collections(step: StepContext) -> None:
        """Re-collect anything that succeeded in an execution that has since ended.

        Collection results live in `context.collection`, which is memory belonging to one
        execution of the run. The step *records* are durable, so a step that succeeded
        stays succeeded and is never offered again -- and on a resumed execution its
        result is simply gone.

        That combination silently drops evidence. Found on a real Romanian municipal
        site: one HTTP retry sent the run round again, DNS, email and TLS were skipped as
        already-succeeded, and the run finished `completed` having normalized nothing but
        HTTP. Coverage fell from most of the surface to half of it and no step failed, so
        the only symptom was a smaller number.

        Re-collecting is safe: every collector is a read of public data, and the run has
        not yet normalized anything. The alternative -- normalizing whatever happens to
        be in memory -- produces a confident coverage figure that describes this process
        rather than the domain.
        """
        succeeded = step.succeeded_steps()
        for name, operation_class in COLLECTOR_OPERATIONS.items():
            if name in context.collection or f"collect.{name}" not in succeeded:
                continue
            context.collection[name] = collect_one(name, operation_class)

    def evaluate(step: StepContext) -> StepOutcome:
        step.check_cancelled()
        evaluations = evaluate_assessment(
            context.catalog,
            context.observations,
            organization_id=context.organization_id,
            assessment_id=context.assessment_id,
            subject=context.subject,
            evaluated_at=context.clock(),
        )
        # A check this mode may not perform is marked not applicable, never left as
        # unknown and never as a pass.
        #
        # Methodology 1.1.0 adds three checks only an authorized assessment can collect.
        # Without this, every passive run would evaluate them as unknown, which reduces
        # coverage -- and a domain whose surface nobody was allowed to scan would lose
        # its band for a scan it was never eligible for. Not applicable leaves the
        # denominator instead, which is what "we were not permitted to look" means.
        context.evaluations = withhold_unavailable_checks(
            context.catalog, evaluations, context.runtime.mode
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

    def assess_assets(step: StepContext) -> StepOutcome:
        """Assess each accepted host for what is true of a host.

        Until now the twenty-two checks all ran against the authorized domain and
        nothing else, so an institution could accept `vpn.primaria.ro` into scope and see
        no difference at all -- the accept button changed a row and nothing looked at the
        host. Most of what actually gets exploited lives on a subdomain nobody
        remembered, so this is where the surface stops being one name.

        Only the host-scoped checks run: a certificate, a redirect, a header and a cookie
        belong to whatever answered on that name, while DNSSEC and SPF belong to the zone
        however many hosts it has. Re-asking the zone's questions per host would repeat
        one answer under many subjects and read as broader coverage than was observed.
        """
        step.check_cancelled()
        if not context.accepted_assets:
            return StepOutcome.skip("no_accepted_assets")

        checks = tuple(
            check
            for check in context.catalog.checks
            if check.observation_type.startswith(HOST_SCOPED_OBSERVATION_PREFIXES)
        )
        observations: list[NormalizedObservation] = []
        evaluations: list[CheckEvaluation] = []
        now = context.clock()

        for host in context.accepted_assets:
            step.check_cancelled()
            subject = domain_subject(host)
            request = context.runtime.request(OperationClass.HTTP_SURFACE, host)
            http_result = HTTPSurfaceCollector(context.broker, context.clock).collect(request)
            tls_request = context.runtime.request(OperationClass.TLS_INSPECTION, host)
            tls_result = TLSCertificateCollector(context.broker, context.clock).collect(
                tls_request, probe_protocols=context.probe_tls_protocols
            )
            host_observations = (
                *normalize_http(
                    http_result,
                    organization_id=context.organization_id,
                    assessment_id=context.assessment_id,
                    subject=subject,
                    now=now,
                    window_seconds=context.freshness_window_seconds,
                ),
                *normalize_tls(
                    tls_result,
                    organization_id=context.organization_id,
                    assessment_id=context.assessment_id,
                    subject=subject,
                    now=now,
                    window_seconds=context.freshness_window_seconds,
                ),
            )
            observations.extend(host_observations)
            evaluations.extend(
                evaluate_assessment(
                    context.catalog,
                    host_observations,
                    organization_id=context.organization_id,
                    assessment_id=context.assessment_id,
                    subject=subject,
                    evaluated_at=now,
                    checks=checks,
                )
            )

        context.asset_observations = tuple(observations)
        context.asset_evaluations = tuple(evaluations)
        return StepOutcome.ok(
            assessed_hosts=len(context.accepted_assets),
            asset_evaluation_count=len(evaluations),
        )

    def findings(step: StepContext) -> StepOutcome:
        step.check_cancelled()
        context.findings = derive_findings(
            context.catalog,
            (*context.evaluations, *context.asset_evaluations),
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
        **{
            f"collect.{name}": collect(name, operation_class)
            for name, operation_class in COLLECTOR_OPERATIONS.items()
        },
        "assess.assets": assess_assets,
        "normalize": normalize,
        "evaluate": evaluate,
        "score": score,
        "findings": findings,
        "agent_analysis": agent_analysis,
        "report": report,
    }
