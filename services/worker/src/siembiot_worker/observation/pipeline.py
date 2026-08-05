"""Passive observation, end to end.

Collect, normalize, evaluate, score, derive findings — the same deterministic engines
the authorized path uses, driven against live public data instead of fixtures. Nothing
here reimplements scoring; if it did, the two paths could disagree.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from siembiot_worker.adapters.contract import CollectionResult
from siembiot_worker.collectors.ct_log import CertificateTransparencyCollector, CTEntrySource
from siembiot_worker.collectors.dns_records import DNSResilienceCollector
from siembiot_worker.collectors.email_records import EmailTrustCollector
from siembiot_worker.collectors.http_surface import HTTPSurfaceCollector
from siembiot_worker.collectors.rdap import RDAPCollector
from siembiot_worker.collectors.tls_certificate import TLSCertificateCollector
from siembiot_worker.network_safety.collection_policy import OperationClass
from siembiot_worker.network_safety.host_policy import HostPolicyError, canonical_host
from siembiot_worker.observation.mode import (
    AssessmentMode,
    ModeCoverage,
    is_check_available,
    mode_coverage,
)
from siembiot_worker.observation.runtime import (
    OBSERVATORY_ORGANIZATION_ID,
    ObservationRuntime,
    build_observation_runtime,
)
from siembiot_worker.policy.catalog import PolicyCatalog, Result, load_catalog
from siembiot_worker.policy.evaluation import evaluate_assessment
from siembiot_worker.policy.evidence import CheckEvaluation, NormalizedObservation, Subject
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

#: The default public RDAP bootstrap service. Configurable, and the collector treats
#: every response as hostile input regardless of which endpoint answers.
DEFAULT_RDAP_ENDPOINT = "rdap.org"


class EmptyCTSource:
    """No Certificate Transparency provider configured.

    Returns nothing rather than guessing, so the CT-derived checks resolve to
    not-applicable instead of quietly implying the domain has no certificates.
    """

    def entries(self, canonical_domain: str) -> tuple[dict[str, Any], ...]:
        del canonical_domain
        return ()


@dataclass(frozen=True)
class ObservationReport:
    host: str
    mode: AssessmentMode
    coverage: ModeCoverage
    snapshot: ScoreSnapshot
    evaluations: tuple[CheckEvaluation, ...]
    findings: tuple[Finding, ...]
    observations: tuple[NormalizedObservation, ...]
    collection: dict[str, CollectionResult] = field(default_factory=dict)
    network_decisions: tuple[dict[str, Any], ...] = ()

    @property
    def unavailable_collectors(self) -> tuple[str, ...]:
        return tuple(sorted(name for name, result in self.collection.items() if not result.usable))


def observe_domain(
    host: str,
    *,
    runtime: ObservationRuntime | None = None,
    catalog: PolicyCatalog | None = None,
    declared_dkim_selectors: tuple[str, ...] = (),
    rdap_endpoint: str = DEFAULT_RDAP_ENDPOINT,
    ct_source: CTEntrySource | None = None,
    probe_tls_protocols: bool = False,
    now: datetime | None = None,
) -> ObservationReport:
    """Assess one public domain using passive observation only.

    ``probe_tls_protocols`` is off by default. Probing deprecated TLS versions means
    several extra handshakes purely to see whether they are refused, which is more than
    a visitor would do, so it stays opt-in.
    """
    try:
        canonical = canonical_host(host.strip().lower().rstrip("."))
    except HostPolicyError as error:
        raise ValueError(f"not a canonical public host name: {host}") from error

    resolved_catalog = catalog or load_catalog()
    resolved_runtime = runtime or build_observation_runtime()
    moment = now or datetime.now(UTC)
    assessment_id = uuid4()
    subject = domain_subject(canonical)
    windows = resolved_catalog.methodology.freshness_windows_seconds
    window = max(windows.values()) if windows else 604_800

    collection = _collect(
        resolved_runtime,
        canonical,
        declared_dkim_selectors=declared_dkim_selectors,
        rdap_endpoint=rdap_endpoint,
        ct_source=ct_source or EmptyCTSource(),
        probe_tls_protocols=probe_tls_protocols,
    )
    observations = _normalize(
        collection,
        assessment_id=assessment_id,
        subject=subject,
        now=moment,
        window_seconds=window,
    )
    observations = (
        *observations,
        derive_freshness_observation(
            observations,
            organization_id=OBSERVATORY_ORGANIZATION_ID,
            assessment_id=assessment_id,
            subject=subject,
            now=moment,
            windows=windows,
        ),
    )

    evaluations = evaluate_assessment(
        resolved_catalog,
        observations,
        organization_id=OBSERVATORY_ORGANIZATION_ID,
        assessment_id=assessment_id,
        subject=subject,
        evaluated_at=moment,
    )
    evaluations = _withhold_unavailable_checks(resolved_catalog, evaluations, resolved_runtime.mode)

    snapshot = compute_score(
        resolved_catalog,
        evaluations,
        observations,
        snapshot_id=uuid4(),
        organization_id=OBSERVATORY_ORGANIZATION_ID,
        assessment_id=assessment_id,
        computed_at=moment,
    )
    findings = derive_findings(
        resolved_catalog,
        evaluations,
        organization_id=OBSERVATORY_ORGANIZATION_ID,
        assessment_id=assessment_id,
        observed_at=moment,
    )
    return ObservationReport(
        host=canonical,
        mode=resolved_runtime.mode,
        coverage=mode_coverage(resolved_catalog, resolved_runtime.mode),
        snapshot=snapshot,
        evaluations=evaluations,
        findings=findings,
        observations=observations,
        collection=collection,
        network_decisions=tuple(resolved_runtime.policy.decisions),
    )


def _collect(
    runtime: ObservationRuntime,
    host: str,
    *,
    declared_dkim_selectors: tuple[str, ...],
    rdap_endpoint: str,
    ct_source: CTEntrySource,
    probe_tls_protocols: bool,
) -> dict[str, CollectionResult]:
    broker = runtime.broker
    results: dict[str, CollectionResult] = {}

    results["dns"] = DNSResilienceCollector(broker).collect(
        runtime.request(OperationClass.DNS_QUERY, host)
    )
    results["email"] = EmailTrustCollector(broker).collect(
        runtime.request(OperationClass.DNS_QUERY, host),
        declared_dkim_selectors=declared_dkim_selectors,
    )
    results["tls"] = TLSCertificateCollector(broker).collect(
        runtime.request(OperationClass.TLS_INSPECTION, host),
        probe_protocols=probe_tls_protocols,
    )
    results["http"] = HTTPSurfaceCollector(broker).collect(
        runtime.request(OperationClass.HTTP_SURFACE, host)
    )
    results["rdap"] = RDAPCollector(broker, rdap_endpoint).collect(
        runtime.request(OperationClass.RDAP_QUERY, host)
    )
    results["ct"] = CertificateTransparencyCollector(broker, ct_source).collect(
        runtime.request(OperationClass.CT_QUERY, host)
    )
    return results


def _normalize(
    collection: dict[str, CollectionResult],
    *,
    assessment_id: UUID,
    subject: Subject,
    now: datetime,
    window_seconds: int,
) -> tuple[NormalizedObservation, ...]:
    shared: dict[str, Any] = {
        "organization_id": OBSERVATORY_ORGANIZATION_ID,
        "assessment_id": assessment_id,
        "subject": subject,
        "now": now,
        "window_seconds": window_seconds,
    }
    return (
        *normalize_dns(collection["dns"], **shared),
        *normalize_email(collection["email"], **shared),
        *normalize_tls(collection["tls"], **shared),
        *normalize_http(collection["http"], **shared),
        *normalize_rdap(collection["rdap"], **shared),
        *normalize_ct(collection["ct"], **shared),
    )


def _withhold_unavailable_checks(
    catalog: PolicyCatalog,
    evaluations: tuple[CheckEvaluation, ...],
    mode: AssessmentMode,
) -> tuple[CheckEvaluation, ...]:
    """Mark checks this mode may not perform as not applicable, never as a pass.

    A withheld check must not look like a passing one, or a passive score would flatter
    a domain simply because the deeper checks were never allowed to run.
    """
    withheld = {check.check_id for check in catalog.checks if not is_check_available(check, mode)}
    if not withheld:
        return evaluations
    return tuple(
        replace(
            evaluation,
            result=str(Result.NOT_APPLICABLE),
            reason_code="requires_authorized_assessment",
        )
        if evaluation.check_id in withheld
        else evaluation
        for evaluation in evaluations
    )
