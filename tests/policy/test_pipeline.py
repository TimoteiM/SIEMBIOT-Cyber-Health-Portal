"""Collector payload to score, end to end, with no network and no model.

This is the milestone's integration proof: the Milestone 3 collectors produce real
payloads against fixtures, and the Milestone 4 engines turn them into a reproducible
score and a set of findings.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "collectors"))

from collector_support import build_broker, frozen_clock, request_for, response  # noqa: E402
from siembiot_worker.collectors.dns_records import DNSResilienceCollector  # noqa: E402
from siembiot_worker.collectors.email_records import EmailTrustCollector  # noqa: E402
from siembiot_worker.collectors.http_surface import HTTPSurfaceCollector  # noqa: E402
from siembiot_worker.policy.catalog import Result, load_catalog  # noqa: E402
from siembiot_worker.policy.evaluation import evaluate_assessment  # noqa: E402
from siembiot_worker.policy.evidence import (  # noqa: E402
    CheckEvaluation,
    NormalizedObservation,
    ObservationStatus,
    Subject,
)
from siembiot_worker.policy.findings import Finding, derive_findings  # noqa: E402
from siembiot_worker.policy.normalization import (  # noqa: E402
    derive_freshness_observation,
    domain_subject,
    normalize_dns,
    normalize_email,
    normalize_http,
)
from siembiot_worker.policy.scoring import ScoreSnapshot, compute_score  # noqa: E402

CATALOG = load_catalog()
ORGANIZATION = uuid4()
ASSESSMENT = uuid4()
NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
WINDOW = 604800

STRONG_POLICY = b"version: STSv1\nmode: enforce\nmx: mail.strong.example.test\nmax_age: 604800\n"
HARDENED_HEADERS = {
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
}


def collect_and_normalize(
    host: str, *, hardened: bool
) -> tuple[Subject, tuple[NormalizedObservation, ...]]:
    subject = domain_subject(host)
    routes = {
        f"https://mta-sts.{host}/.well-known/mta-sts.txt": response(
            200, {"content-type": "text/plain"}, STRONG_POLICY
        ),
        f"http://{host}/": response(301, {"location": f"https://{host}/"})
        if hardened
        else response(200, {"server": "nginx/1.2.3"}, b"plain"),
        f"https://{host}/": response(
            200, HARDENED_HEADERS if hardened else {"server": "nginx/1.2.3"}, b"<html></html>"
        ),
    }
    broker = build_broker(routes=routes)
    dns_result = DNSResilienceCollector(broker, frozen_clock).collect(request_for(host))
    email_result = EmailTrustCollector(broker, frozen_clock).collect(
        request_for(host), declared_dkim_selectors=("selector1",)
    )
    http_result = HTTPSurfaceCollector(broker, frozen_clock).collect(request_for(host))

    observations = (
        *normalize_dns(
            dns_result,
            organization_id=ORGANIZATION,
            assessment_id=ASSESSMENT,
            subject=subject,
            now=NOW,
            window_seconds=WINDOW,
        ),
        *normalize_email(
            email_result,
            organization_id=ORGANIZATION,
            assessment_id=ASSESSMENT,
            subject=subject,
            now=NOW,
            window_seconds=WINDOW,
        ),
        *normalize_http(
            http_result,
            organization_id=ORGANIZATION,
            assessment_id=ASSESSMENT,
            subject=subject,
            now=NOW,
            window_seconds=WINDOW,
        ),
    )
    freshness = derive_freshness_observation(
        observations,
        organization_id=ORGANIZATION,
        assessment_id=ASSESSMENT,
        subject=subject,
        now=NOW,
        windows=CATALOG.methodology.freshness_windows_seconds,
    )
    return subject, (*observations, freshness)


def run(
    host: str, *, hardened: bool = True
) -> tuple[
    tuple[NormalizedObservation, ...],
    tuple[CheckEvaluation, ...],
    ScoreSnapshot,
    tuple[Finding, ...],
]:
    subject, observations = collect_and_normalize(host, hardened=hardened)
    evaluations = evaluate_assessment(
        CATALOG,
        observations,
        organization_id=ORGANIZATION,
        assessment_id=ASSESSMENT,
        subject=subject,
        evaluated_at=NOW,
    )
    snapshot = compute_score(
        CATALOG,
        evaluations,
        observations,
        snapshot_id=uuid4(),
        organization_id=ORGANIZATION,
        assessment_id=ASSESSMENT,
        computed_at=NOW,
    )
    findings = derive_findings(
        CATALOG,
        evaluations,
        organization_id=ORGANIZATION,
        assessment_id=ASSESSMENT,
        observed_at=NOW,
    )
    return observations, evaluations, snapshot, findings


# -- the pipeline runs -------------------------------------------------------


def test_well_configured_domain_scores_higher_than_a_weak_one() -> None:
    _, _, strong, _ = run("strong.example.test")
    _, _, weak, _ = run("weak.example.test", hardened=False)
    assert strong.uncapped_score is not None
    assert weak.uncapped_score is not None
    assert strong.uncapped_score > weak.uncapped_score


def test_strong_domain_produces_the_expected_control_results() -> None:
    _, evaluations, _, _ = run("strong.example.test")
    results = {item.check_id: item.result for item in evaluations}
    assert results["A.dnssec_enabled"] == "pass"
    assert results["A.caa_present"] == "pass"
    assert results["B.spf_present"] == "pass"
    assert results["B.dmarc_enforced"] == "pass"
    assert results["B.mta_sts_enforced"] == "pass"
    assert results["C.http_redirects_https"] == "pass"
    assert results["C.hsts_present"] == "pass"
    assert results["C.security_headers"] == "pass"


def test_weak_domain_surfaces_its_real_weaknesses() -> None:
    _, evaluations, _, findings = run("weak.example.test", hardened=False)
    results = {item.check_id: item.result for item in evaluations}
    assert results["A.dnssec_enabled"] == "fail"
    assert results["A.caa_present"] == "warning"
    assert results["B.dmarc_enforced"] == "warning"
    assert results["C.http_redirects_https"] == "fail"
    assert results["C.hsts_present"] == "fail"
    assert {item.check_id for item in findings} >= {
        "A.dnssec_enabled",
        "C.http_redirects_https",
        "C.hsts_present",
    }


def test_unresolvable_dns_yields_unknown_rather_than_a_bad_score() -> None:
    # This fixture times out on DNS while still serving HTTP, so only the DNS- and
    # e-mail-derived checks should be unknown. Nothing they cover may produce a finding.
    _, evaluations, snapshot, findings = run("unknown.example.test", hardened=False)
    results = {item.check_id: item.result for item in evaluations}
    assert results["A.dnssec_enabled"] == "unknown"
    assert results["B.spf_present"] == "unknown"
    dns_and_email = [item for item in evaluations if item.check_id.startswith(("A.", "B."))]
    assert all(item.result in {"unknown", "not_applicable"} for item in dns_and_email)
    assert not any(item.check_id.startswith(("A.", "B.")) for item in findings)
    assert snapshot.coverage.sufficient is False
    assert snapshot.band == "insufficient_coverage"


def test_hostile_records_never_crash_the_pipeline() -> None:
    _, evaluations, snapshot, _ = run("hostile.example.test", hardened=False)
    assert len(evaluations) == len(CATALOG.checks)
    assert snapshot.policy_digest == CATALOG.digest


# -- the invariants that matter ----------------------------------------------


def test_the_whole_pipeline_is_reproducible() -> None:
    first = run("strong.example.test")[2].as_dict()
    second = run("strong.example.test")[2].as_dict()
    first.pop("snapshot_id")
    second.pop("snapshot_id")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_every_evaluation_traces_back_to_an_observation_or_says_why_not() -> None:
    observations, evaluations, _, _ = run("strong.example.test")
    known = {item.observation_id for item in observations}
    for evaluation in evaluations:
        if evaluation.observation_ids:
            assert set(evaluation.observation_ids) <= known
        else:
            assert evaluation.result in {"unknown", "not_applicable"}


def test_every_finding_cites_immutable_evidence() -> None:
    observations, _, _, findings = run("weak.example.test", hardened=False)
    known = {item.observation_id for item in observations}
    for finding in findings:
        assert finding.evidence
        assert set(finding.evidence) <= known


def test_inconclusive_collection_never_becomes_a_pass_or_a_fail() -> None:
    observations, evaluations, _, _ = run("unknown.example.test", hardened=False)
    inconclusive_types = {
        item.observation_type
        for item in observations
        if item.status is ObservationStatus.INCONCLUSIVE
    }
    assert inconclusive_types
    for evaluation in evaluations:
        check = CATALOG.by_id(evaluation.check_id)
        if check.observation_type in inconclusive_types:
            assert Result(evaluation.result) not in {Result.PASS, Result.FAIL, Result.WARNING}


def test_stale_evidence_is_reported_rather_than_hidden() -> None:
    subject, observations = collect_and_normalize("strong.example.test", hardened=True)
    stale = derive_freshness_observation(
        observations,
        organization_id=ORGANIZATION,
        assessment_id=ASSESSMENT,
        subject=subject,
        now=NOW + timedelta(days=400),
        windows=CATALOG.methodology.freshness_windows_seconds,
    )
    assert stale.attributes["stale_observation_count"] > 0


@pytest.mark.parametrize("host", ["strong.example.test", "weak.example.test"])
def test_no_pillar_is_silently_skipped(host: str) -> None:
    _, _, snapshot, _ = run(host, hardened=host == "strong.example.test")
    assert len(snapshot.pillars) == len(CATALOG.methodology.pillar_weights)


def test_reputation_stays_unknown_without_a_configured_provider() -> None:
    _, evaluations, _, _ = run("strong.example.test")
    reputation = next(item for item in evaluations if item.check_id == "E.domain_reputation_clean")
    assert reputation.result in {"unknown", "not_applicable"}
    assert reputation.score_bearing is False
