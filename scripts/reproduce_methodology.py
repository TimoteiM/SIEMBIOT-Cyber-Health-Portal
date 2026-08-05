"""Prove a score is reproducible from a fixed evidence set.

Run twice, get the same digests and the same score. This is the command referenced by
the methodology as the reproducibility check, and CI runs it with --check.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "worker" / "src"))

from siembiot_worker.policy.catalog import load_catalog  # noqa: E402
from siembiot_worker.policy.evaluation import evaluate_assessment  # noqa: E402
from siembiot_worker.policy.evidence import (  # noqa: E402
    Confidence,
    NormalizedObservation,
    ObservationStatus,
    Subject,
    SubjectKind,
)
from siembiot_worker.policy.scoring import compute_score  # noqa: E402

ORGANIZATION = UUID("11111111-1111-4111-8111-111111111111")
ASSESSMENT = UUID("22222222-2222-4222-8222-222222222222")
SNAPSHOT = UUID("33333333-3333-4333-8333-333333333333")
NAMESPACE = UUID("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d")
AT = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
SUBJECT = Subject(SubjectKind.DOMAIN, "reference.example.test")
EXPECTED = ROOT / "docs" / "methodology" / "v1" / "reference-snapshot.json"

# A fixed, fictional reference domain spanning every result state the engine can reach.
FIXTURE: tuple[tuple[str, ObservationStatus, dict[str, object]], ...] = (
    ("dns.dnssec", ObservationStatus.OBSERVED, {"state": "signed_and_delegated"}),
    (
        "dns.caa",
        ObservationStatus.OBSERVED,
        {"present": True, "issue_count": 1, "has_unparsed": False},
    ),
    (
        "dns.delegation",
        ObservationStatus.OBSERVED,
        {"nameserver_count": 2, "distinct_parent_count": 2},
    ),
    ("dns.wildcard", ObservationStatus.OBSERVED, {"resolves": False}),
    (
        "rdap.registration",
        ObservationStatus.OBSERVED,
        {"days_until_expiry": 200, "transfer_prohibited": True, "delete_prohibited": True},
    ),
    (
        "email.spf",
        ObservationStatus.OBSERVED,
        {
            "present": True,
            "valid": True,
            "permissive_all": False,
            "soft_all": False,
            "exceeds_lookup_limit": False,
            "multiple_records": False,
            "dns_lookup_count": 3,
        },
    ),
    (
        "email.dmarc",
        ObservationStatus.OBSERVED,
        {
            "present": True,
            "valid": True,
            "policy": "reject",
            "subdomain_policy": "reject",
            "percentage": 100,
            "external_authorization_required": False,
        },
    ),
    (
        "email.mta_sts",
        ObservationStatus.OBSERVED,
        {"mx_present": True, "mode": "testing", "policy_invalid": False, "max_age_seconds": 86400},
    ),
    (
        "email.tls_rpt",
        ObservationStatus.OBSERVED,
        {"mx_present": True, "present": True, "valid": True},
    ),
    (
        "email.dkim",
        ObservationStatus.OBSERVED,
        {
            "declared_selector_count": 1,
            "present_selector_count": 1,
            "all_selectors_present": True,
            "any_selector_present": True,
        },
    ),
    (
        "http.availability",
        ObservationStatus.OBSERVED,
        {"https_reachable": True, "http_reachable": True, "https_status_code": 200},
    ),
    (
        "http.redirect",
        ObservationStatus.OBSERVED,
        {"http_reachable": True, "redirects_to_https": True},
    ),
    (
        "tls.certificate",
        ObservationStatus.OBSERVED,
        {
            "expired": False,
            "not_yet_valid": False,
            "days_until_expiry": 120,
            "hostname_covered": True,
            "weak_signature": False,
            "weak_key": False,
            "self_signed": False,
            "trusted": True,
        },
    ),
    (
        "tls.protocols",
        ObservationStatus.OBSERVED,
        {
            "supported": ["TLSv1.2", "TLSv1.3"],
            "deprecated_supported_count": 0,
            "inconclusive_count": 0,
        },
    ),
    (
        "http.security_headers",
        ObservationStatus.OBSERVED,
        {
            "https_reachable": True,
            "hsts_present": True,
            "hsts_max_age": 31536000,
            "hsts_include_subdomains": True,
            "missing_baseline_count": 1,
        },
    ),
    ("http.cookies", ObservationStatus.OBSERVED, {"cookie_count": 1, "insecure_cookie_count": 1}),
    (
        "http.disclosure",
        ObservationStatus.OBSERVED,
        {"https_reachable": True, "version_disclosing_count": 0},
    ),
    (
        "assets.candidates",
        ObservationStatus.OBSERVED,
        {"candidate_count": 3, "unreviewed_count": 2, "low_confidence_count": 1},
    ),
    # Reputation stays inconclusive: no provider is configured in the reference run.
    ("reputation.domain", ObservationStatus.INCONCLUSIVE, {}),
    (
        "assessment.freshness",
        ObservationStatus.OBSERVED,
        {"stale_observation_count": 0, "total_observation_count": 19},
    ),
)


def build_observations() -> tuple[NormalizedObservation, ...]:
    from uuid import uuid5

    return tuple(
        NormalizedObservation(
            observation_id=uuid5(NAMESPACE, f"{ASSESSMENT}:{SUBJECT.identifier}:{name}"),
            organization_id=ORGANIZATION,
            assessment_id=ASSESSMENT,
            subject=SUBJECT,
            observation_type=name,
            status=status,
            attributes=attributes,
            confidence=Confidence(1.0, 1.0, 1.0),
            adapter_id="reference",
            adapter_version="1.0.0",
            collected_at=AT,
        )
        for name, status, attributes in FIXTURE
    )


def render() -> dict[str, object]:
    catalog = load_catalog()
    observations = build_observations()
    evaluations = evaluate_assessment(
        catalog,
        observations,
        organization_id=ORGANIZATION,
        assessment_id=ASSESSMENT,
        subject=SUBJECT,
        evaluated_at=AT,
    )
    snapshot = compute_score(
        catalog,
        evaluations,
        observations,
        snapshot_id=SNAPSHOT,
        organization_id=ORGANIZATION,
        assessment_id=ASSESSMENT,
        computed_at=AT,
    )
    document = snapshot.as_dict()
    document["evaluations"] = [
        {"check_id": item.check_id, "result": item.result, "reason_code": item.reason_code}
        for item in sorted(evaluations, key=lambda item: item.check_id)
    ]
    return document


def main() -> int:
    document = render()
    serialized = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if not EXPECTED.is_file():
            print(f"{EXPECTED} is missing; run scripts/reproduce_methodology.py")
            return 1
        if EXPECTED.read_text(encoding="utf-8") != serialized:
            print(
                "Reference snapshot changed. If this was intentional, publish a new "
                "methodology version and regenerate; historical scores must not shift "
                "under an unchanged version."
            )
            return 1
        print(f"Methodology {document['methodology_version']} reproduced exactly.")
        return 0
    EXPECTED.parent.mkdir(parents=True, exist_ok=True)
    EXPECTED.write_text(serialized, encoding="utf-8")
    print(f"wrote {EXPECTED}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
