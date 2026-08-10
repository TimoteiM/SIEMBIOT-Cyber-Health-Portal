"""Normalizers: collector payloads to immutable observations.

A normalizer decides only *what was seen*, never whether it is good. The critical
rule here is that an inconclusive collection stays inconclusive — it must never be
flattened into "absent", because absent is a proven negative and would be scored.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from typing import Any
from uuid import UUID, uuid5

from siembiot_worker.adapters.contract import CollectionResult, CollectionStatus
from siembiot_worker.policy.catalog import Pillar
from siembiot_worker.policy.evidence import (
    Confidence,
    NormalizedObservation,
    ObservationStatus,
    Subject,
    SubjectKind,
)

OBSERVATION_NAMESPACE = UUID("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d")
BASELINE_SECURITY_HEADERS = (
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
)
VERSION_PATTERN_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")

ADAPTER_SOURCE_CONFIDENCE = {
    "dns_resilience": 1.0,
    "email_trust": 1.0,
    "tls_certificate": 1.0,
    "http_surface": 1.0,
    "rdap_registration": 0.9,
    "certificate_transparency": 0.7,
}


class NormalizationError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _identity(assessment_id: UUID, subject: Subject, observation_type: str) -> UUID:
    return uuid5(OBSERVATION_NAMESPACE, f"{assessment_id}:{subject.identifier}:{observation_type}")


def _freshness(result: CollectionResult, now: datetime, window_seconds: int) -> float:
    age = result.provenance.age_seconds if result.provenance.observed_at else 0.0
    if window_seconds <= 0:
        return 1.0
    return max(0.0, min(1.0, 1.0 - age / window_seconds))


def _confidence(
    result: CollectionResult,
    *,
    attribution: float,
    now: datetime,
    window_seconds: int,
) -> Confidence:
    reasons: list[str] = []
    source = ADAPTER_SOURCE_CONFIDENCE.get(result.provenance.adapter_id, 0.5)
    if result.provenance.from_cache:
        reasons.append("served_from_cache")
    if result.status is CollectionStatus.PARTIAL:
        reasons.append("partial_collection")
    freshness = _freshness(result, now, window_seconds)
    if freshness < 1.0:
        reasons.append("evidence_aged")
    if attribution < 1.0:
        reasons.append("attribution_uncertain")
    return Confidence(attribution, source, freshness, tuple(sorted(set(reasons))))


class ObservationBuilder:
    """Small helper so each normalizer reads as a list of facts, not plumbing."""

    def __init__(
        self,
        *,
        organization_id: UUID,
        assessment_id: UUID,
        subject: Subject,
        result: CollectionResult,
        confidence: Confidence,
    ) -> None:
        self._organization_id = organization_id
        self._assessment_id = assessment_id
        self._subject = subject
        self._result = result
        self._confidence = confidence

    def make(
        self,
        observation_type: str,
        status: ObservationStatus,
        attributes: dict[str, Any] | None = None,
    ) -> NormalizedObservation:
        provenance = self._result.provenance
        return NormalizedObservation(
            observation_id=_identity(self._assessment_id, self._subject, observation_type),
            organization_id=self._organization_id,
            assessment_id=self._assessment_id,
            subject=self._subject,
            observation_type=observation_type,
            status=status,
            attributes=attributes or {},
            confidence=self._confidence,
            adapter_id=provenance.adapter_id,
            adapter_version=provenance.adapter_version,
            collected_at=provenance.collected_at,
            observed_at=provenance.observed_at,
            from_cache=provenance.from_cache,
            source_reference=provenance.source_reference,
        )


def _status_from_section(present: bool, conclusive: bool) -> ObservationStatus:
    """The single place the presence/conclusiveness rule is expressed."""
    if not conclusive:
        return ObservationStatus.INCONCLUSIVE
    return ObservationStatus.OBSERVED if present else ObservationStatus.ABSENT


def normalize_dns(
    result: CollectionResult,
    *,
    organization_id: UUID,
    assessment_id: UUID,
    subject: Subject,
    now: datetime,
    window_seconds: int,
) -> tuple[NormalizedObservation, ...]:
    confidence = _confidence(result, attribution=1.0, now=now, window_seconds=window_seconds)
    builder = ObservationBuilder(
        organization_id=organization_id,
        assessment_id=assessment_id,
        subject=subject,
        result=result,
        confidence=confidence,
    )
    if not result.usable:
        return tuple(
            builder.make(name, ObservationStatus.INCONCLUSIVE)
            for name in ("dns.dnssec", "dns.caa", "dns.delegation", "dns.wildcard")
        )

    payload = result.payload
    lookups = payload.get("lookups", {})
    observations: list[NormalizedObservation] = []

    dnssec = payload.get("dnssec", {})
    state = dnssec.get("state", "unknown")
    observations.append(builder.make("dns.dnssec", ObservationStatus.OBSERVED, {"state": state}))

    caa = payload.get("caa")
    caa_conclusive = bool(lookups.get("caa", {}).get("conclusive", False))
    if caa is None:
        observations.append(builder.make("dns.caa", _status_from_section(False, caa_conclusive)))
    else:
        observations.append(
            builder.make(
                "dns.caa",
                ObservationStatus.OBSERVED,
                {
                    "present": bool(caa.get("present")),
                    "issue_count": len(caa.get("issue", [])),
                    "has_unparsed": bool(caa.get("unparsed")),
                },
            )
        )

    delegation = payload.get("delegation", {})
    ns_conclusive = bool(lookups.get("ns", {}).get("conclusive", False))
    observations.append(
        builder.make(
            "dns.delegation",
            ObservationStatus.OBSERVED if ns_conclusive else ObservationStatus.INCONCLUSIVE,
            {
                "nameserver_count": delegation.get("nameserver_count", 0),
                "distinct_parent_count": delegation.get("distinct_parent_count", 0),
            }
            if ns_conclusive
            else None,
        )
    )

    wildcard = payload.get("wildcard", {})
    observations.append(
        builder.make(
            "dns.wildcard",
            ObservationStatus.OBSERVED
            if wildcard.get("conclusive")
            else ObservationStatus.INCONCLUSIVE,
            {"resolves": bool(wildcard.get("resolves"))} if wildcard.get("conclusive") else None,
        )
    )
    return tuple(observations)


def normalize_email(
    result: CollectionResult,
    *,
    organization_id: UUID,
    assessment_id: UUID,
    subject: Subject,
    now: datetime,
    window_seconds: int,
) -> tuple[NormalizedObservation, ...]:
    confidence = _confidence(result, attribution=1.0, now=now, window_seconds=window_seconds)
    builder = ObservationBuilder(
        organization_id=organization_id,
        assessment_id=assessment_id,
        subject=subject,
        result=result,
        confidence=confidence,
    )
    types = ("email.spf", "email.dmarc", "email.mta_sts", "email.tls_rpt", "email.dkim")
    if not result.usable:
        return tuple(builder.make(name, ObservationStatus.INCONCLUSIVE) for name in types)

    payload = result.payload
    mx_present = bool(payload.get("mx", {}).get("present"))
    observations: list[NormalizedObservation] = []

    spf = payload.get("spf", {})
    parsed = spf.get("parsed")
    if spf.get("multiple_records"):
        observations.append(
            builder.make("email.spf", ObservationStatus.OBSERVED, {"multiple_records": True})
        )
    elif parsed is not None:
        observations.append(
            builder.make(
                "email.spf",
                ObservationStatus.OBSERVED,
                {
                    "present": True,
                    "multiple_records": False,
                    "valid": bool(parsed.get("valid")),
                    "permissive_all": bool(parsed.get("permissive_all")),
                    "soft_all": bool(parsed.get("soft_all")),
                    "exceeds_lookup_limit": bool(parsed.get("exceeds_lookup_limit")),
                    "dns_lookup_count": parsed.get("dns_lookup_count", 0),
                },
            )
        )
    else:
        observations.append(
            builder.make("email.spf", _status_from_section(False, bool(spf.get("conclusive"))))
        )

    dmarc = payload.get("dmarc", {})
    dmarc_parsed = dmarc.get("parsed")
    if dmarc_parsed is not None:
        observations.append(
            builder.make(
                "email.dmarc",
                ObservationStatus.OBSERVED,
                {
                    "present": True,
                    "valid": bool(dmarc_parsed.get("valid")),
                    "policy": dmarc_parsed.get("policy"),
                    "subdomain_policy": dmarc_parsed.get("subdomain_policy"),
                    "percentage": dmarc_parsed.get("percentage"),
                    "external_authorization_required": bool(
                        dmarc_parsed.get("external_authorization_required")
                    ),
                },
            )
        )
    else:
        observations.append(
            builder.make("email.dmarc", _status_from_section(False, bool(dmarc.get("conclusive"))))
        )

    mta_sts = payload.get("mta_sts", {})
    policy = mta_sts.get("policy")
    if policy is not None:
        observations.append(
            builder.make(
                "email.mta_sts",
                ObservationStatus.OBSERVED,
                {
                    "mx_present": mx_present,
                    "mode": policy.get("mode"),
                    "policy_invalid": not policy.get("valid", False),
                    "max_age_seconds": policy.get("max_age_seconds"),
                },
            )
        )
    elif mta_sts.get("dns_record_present"):
        observations.append(
            builder.make(
                "email.mta_sts",
                ObservationStatus.OBSERVED,
                {
                    "mx_present": mx_present,
                    "mode": None,
                    "policy_invalid": True,
                    "policy_fetch_reason": mta_sts.get("policy_fetch_reason"),
                },
            )
        )
    else:
        status = _status_from_section(False, bool(mta_sts.get("conclusive")))
        observations.append(
            builder.make(
                "email.mta_sts",
                ObservationStatus.OBSERVED if status is ObservationStatus.ABSENT else status,
                {"mx_present": mx_present, "present": False}
                if status is ObservationStatus.ABSENT
                else None,
            )
        )

    tls_rpt = payload.get("tls_rpt", {})
    if tls_rpt.get("present"):
        observations.append(
            builder.make(
                "email.tls_rpt",
                ObservationStatus.OBSERVED,
                {
                    "mx_present": mx_present,
                    "present": True,
                    "valid": bool(tls_rpt.get("valid")),
                },
            )
        )
    else:
        status = _status_from_section(False, bool(tls_rpt.get("conclusive")))
        observations.append(
            builder.make(
                "email.tls_rpt",
                ObservationStatus.OBSERVED if status is ObservationStatus.ABSENT else status,
                {"mx_present": mx_present, "present": False}
                if status is ObservationStatus.ABSENT
                else None,
            )
        )

    dkim = payload.get("dkim", {})
    selectors = dkim.get("selectors", [])
    if not selectors:
        observations.append(builder.make("email.dkim", ObservationStatus.NOT_APPLICABLE))
    else:
        present = [item for item in selectors if item.get("present")]
        conclusive = all(item.get("conclusive") for item in selectors)
        if not conclusive:
            observations.append(builder.make("email.dkim", ObservationStatus.INCONCLUSIVE))
        elif not present:
            observations.append(builder.make("email.dkim", ObservationStatus.ABSENT))
        else:
            observations.append(
                builder.make(
                    "email.dkim",
                    ObservationStatus.OBSERVED,
                    {
                        "declared_selector_count": len(selectors),
                        "present_selector_count": len(present),
                        "all_selectors_present": len(present) == len(selectors),
                        "any_selector_present": True,
                    },
                )
            )
    return tuple(observations)


def normalize_tls(
    result: CollectionResult,
    *,
    organization_id: UUID,
    assessment_id: UUID,
    subject: Subject,
    now: datetime,
    window_seconds: int,
) -> tuple[NormalizedObservation, ...]:
    confidence = _confidence(result, attribution=1.0, now=now, window_seconds=window_seconds)
    builder = ObservationBuilder(
        organization_id=organization_id,
        assessment_id=assessment_id,
        subject=subject,
        result=result,
        confidence=confidence,
    )
    if not result.usable:
        return (
            builder.make("tls.certificate", ObservationStatus.INCONCLUSIVE),
            builder.make("tls.protocols", ObservationStatus.INCONCLUSIVE),
        )

    payload = result.payload
    leaf = payload.get("leaf")
    observations: list[NormalizedObservation] = []
    if leaf is None:
        observations.append(builder.make("tls.certificate", ObservationStatus.INCONCLUSIVE))
    else:
        observations.append(
            builder.make(
                "tls.certificate",
                ObservationStatus.OBSERVED,
                {
                    "expired": bool(leaf.get("expired")),
                    "not_yet_valid": bool(leaf.get("not_yet_valid")),
                    "days_until_expiry": leaf.get("days_until_expiry"),
                    "hostname_covered": bool(leaf.get("hostname_covered")),
                    "weak_signature": bool(leaf.get("weak_signature")),
                    "weak_key": bool(leaf.get("public_key", {}).get("weak")),
                    "self_signed": bool(leaf.get("self_signed")),
                    "trusted": bool(payload.get("handshake", {}).get("trusted")),
                },
            )
        )

    protocols = payload.get("protocols", {})
    probed = protocols.get("probed", [])
    if not probed:
        observations.append(builder.make("tls.protocols", ObservationStatus.INCONCLUSIVE))
    else:
        observations.append(
            builder.make(
                "tls.protocols",
                ObservationStatus.OBSERVED,
                {
                    "supported": list(protocols.get("supported", [])),
                    "deprecated_supported_count": len(protocols.get("deprecated_supported", [])),
                    "inconclusive_count": len(protocols.get("inconclusive", [])),
                },
            )
        )
    return tuple(observations)


def normalize_http(
    result: CollectionResult,
    *,
    organization_id: UUID,
    assessment_id: UUID,
    subject: Subject,
    now: datetime,
    window_seconds: int,
) -> tuple[NormalizedObservation, ...]:
    confidence = _confidence(result, attribution=1.0, now=now, window_seconds=window_seconds)
    builder = ObservationBuilder(
        organization_id=organization_id,
        assessment_id=assessment_id,
        subject=subject,
        result=result,
        confidence=confidence,
    )
    types = (
        "http.availability",
        "http.redirect",
        "http.security_headers",
        "http.cookies",
        "http.disclosure",
    )
    if not result.usable:
        return tuple(builder.make(name, ObservationStatus.INCONCLUSIVE) for name in types)

    payload = result.payload
    https = payload.get("https", {})
    http = payload.get("http", {})
    https_reachable = bool(https.get("reachable"))
    observations = [
        builder.make(
            "http.availability",
            ObservationStatus.OBSERVED,
            {
                "https_reachable": https_reachable,
                "http_reachable": bool(http.get("reachable")),
                "https_status_code": https.get("status_code"),
            },
        ),
        builder.make(
            "http.redirect",
            ObservationStatus.OBSERVED,
            {
                "http_reachable": bool(http.get("reachable")),
                "redirects_to_https": bool(
                    payload.get("redirects_http_to_https", {}).get("redirects")
                ),
            },
        ),
    ]

    headers = payload.get("security_headers")
    if headers is None:
        observations.append(builder.make("http.security_headers", ObservationStatus.INCONCLUSIVE))
    else:
        hsts = headers.get("hsts") or {}
        present = headers.get("present", {})
        missing_baseline = [name for name in BASELINE_SECURITY_HEADERS if name not in present]
        observations.append(
            builder.make(
                "http.security_headers",
                ObservationStatus.OBSERVED,
                {
                    "https_reachable": https_reachable,
                    "hsts_present": "strict-transport-security" in present,
                    "hsts_max_age": hsts.get("max_age_seconds") or 0,
                    "hsts_include_subdomains": bool(hsts.get("include_subdomains")),
                    "missing_baseline_count": len(missing_baseline),
                    "missing_baseline": missing_baseline,
                },
            )
        )

    cookies = payload.get("cookies")
    if cookies is None:
        observations.append(builder.make("http.cookies", ObservationStatus.INCONCLUSIVE))
    elif not cookies:
        observations.append(builder.make("http.cookies", ObservationStatus.ABSENT))
    else:
        insecure = [
            cookie for cookie in cookies if not cookie.get("secure") or not cookie.get("http_only")
        ]
        observations.append(
            builder.make(
                "http.cookies",
                ObservationStatus.OBSERVED,
                {
                    "cookie_count": len(cookies),
                    "insecure_cookie_count": len(insecure),
                },
            )
        )

    disclosure = payload.get("disclosure_headers")
    if disclosure is None:
        observations.append(builder.make("http.disclosure", ObservationStatus.INCONCLUSIVE))
    else:
        disclosing = [
            name
            for name, value in disclosure.items()
            if name in VERSION_PATTERN_HEADERS and any(ch.isdigit() for ch in value)
        ]
        observations.append(
            builder.make(
                "http.disclosure",
                ObservationStatus.OBSERVED,
                {
                    "https_reachable": https_reachable,
                    "version_disclosing_count": len(disclosing),
                    "disclosing_headers": sorted(disclosing),
                },
            )
        )
    return tuple(observations)


def normalize_rdap(
    result: CollectionResult,
    *,
    organization_id: UUID,
    assessment_id: UUID,
    subject: Subject,
    now: datetime,
    window_seconds: int,
) -> tuple[NormalizedObservation, ...]:
    confidence = _confidence(result, attribution=1.0, now=now, window_seconds=window_seconds)
    builder = ObservationBuilder(
        organization_id=organization_id,
        assessment_id=assessment_id,
        subject=subject,
        result=result,
        confidence=confidence,
    )
    if result.status is CollectionStatus.NOT_APPLICABLE:
        return (builder.make("rdap.registration", ObservationStatus.NOT_APPLICABLE),)
    if not result.usable:
        return (builder.make("rdap.registration", ObservationStatus.INCONCLUSIVE),)

    registration = result.payload.get("registration", {})
    expiration = registration.get("expiration_date")
    if expiration is None:
        return (builder.make("rdap.registration", ObservationStatus.INCONCLUSIVE),)
    days = _days_until(expiration, now)
    if days is None:
        return (builder.make("rdap.registration", ObservationStatus.INCONCLUSIVE),)
    return (
        builder.make(
            "rdap.registration",
            ObservationStatus.OBSERVED,
            {
                "days_until_expiry": days,
                "transfer_prohibited": bool(registration.get("transfer_prohibited")),
                "delete_prohibited": bool(registration.get("delete_prohibited")),
            },
        ),
    )


def normalize_ct(
    result: CollectionResult,
    *,
    organization_id: UUID,
    assessment_id: UUID,
    subject: Subject,
    now: datetime,
    window_seconds: int,
    accepted_names: frozenset[str] = frozenset(),
) -> tuple[NormalizedObservation, ...]:
    """CT candidates carry reduced attribution confidence until a human accepts them."""
    confidence = _confidence(result, attribution=0.7, now=now, window_seconds=window_seconds)
    builder = ObservationBuilder(
        organization_id=organization_id,
        assessment_id=assessment_id,
        subject=subject,
        result=result,
        confidence=confidence,
    )
    if result.status is CollectionStatus.NOT_APPLICABLE:
        return (builder.make("assets.candidates", ObservationStatus.ABSENT),)
    if not result.usable:
        return (builder.make("assets.candidates", ObservationStatus.INCONCLUSIVE),)
    candidates = result.payload.get("candidates", [])
    unreviewed = [item for item in candidates if item.get("name") not in accepted_names]
    return (
        builder.make(
            "assets.candidates",
            ObservationStatus.OBSERVED,
            {
                "candidate_count": len(candidates),
                "unreviewed_count": len(unreviewed),
                "low_confidence_count": sum(
                    1 for item in candidates if float(item.get("confidence", 0)) < 0.5
                ),
            },
        ),
    )


def derive_freshness_observation(
    observations: tuple[NormalizedObservation, ...],
    *,
    organization_id: UUID,
    assessment_id: UUID,
    subject: Subject,
    now: datetime,
    windows: dict[Pillar, int],
) -> NormalizedObservation:
    """A derived observation so staleness is scored explicitly rather than assumed away."""
    default_window = max(windows.values()) if windows else 604800
    stale = [item for item in observations if item.is_stale(now, default_window)]
    return NormalizedObservation(
        observation_id=_identity(assessment_id, subject, "assessment.freshness"),
        organization_id=organization_id,
        assessment_id=assessment_id,
        subject=subject,
        observation_type="assessment.freshness",
        status=ObservationStatus.OBSERVED,
        attributes={
            "stale_observation_count": len(stale),
            "total_observation_count": len(observations),
        },
        confidence=Confidence(1.0, 1.0, 1.0),
        adapter_id="derived",
        adapter_version="1.0.0",
        collected_at=now,
    )


def _days_until(value: str, now: datetime) -> int | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if parsed.tzinfo is None:
        return None
    return (parsed - now).days


def domain_subject(canonical_host: str, authorized_domain_id: UUID | None = None) -> Subject:
    return Subject(SubjectKind.DOMAIN, canonical_host, authorized_domain_id)


def iter_observations(
    *groups: tuple[NormalizedObservation, ...],
) -> Iterator[NormalizedObservation]:
    for group in groups:
        yield from group


def normalize_ports(
    result: CollectionResult,
    *,
    organization_id: UUID,
    assessment_id: UUID,
    subject: Subject,
    now: datetime,
    window_seconds: int,
) -> tuple[NormalizedObservation, ...]:
    """The exposed service inventory, as one observation.

    One observation rather than one per port. A port is not a subject: what a reader
    needs to know is what this host exposes, and thirty rows saying "closed" would bury
    the two that say otherwise.

    A scan that reached nothing is inconclusive, never an empty inventory. "We found no
    open ports" and "our probes never arrived" look identical in a summary and mean
    opposite things about an institution's safety.
    """
    confidence = _confidence(result, attribution=1.0, now=now, window_seconds=window_seconds)
    builder = ObservationBuilder(
        organization_id=organization_id,
        assessment_id=assessment_id,
        subject=subject,
        result=result,
        confidence=confidence,
    )
    if not result.usable:
        return (builder.make("surface.ports", ObservationStatus.INCONCLUSIVE),)

    payload = result.payload
    open_ports = [item for item in payload.get("ports", []) if item.get("state") == "open"]
    return (
        builder.make(
            "surface.ports",
            ObservationStatus.OBSERVED,
            {
                "open_count": int(payload.get("open_count", 0)),
                "probed_count": int(payload.get("probed_count", 0)),
                "worst_exposure": payload.get("worst_exposure"),
                "open_by_exposure": payload.get("open_by_exposure", {}),
                # Only the open ones are carried into the observation. A closed port is
                # the absence of a service, and an inventory of absences is not evidence
                # anybody reads.
                "open_ports": [
                    {
                        "port": item["port"],
                        "service": item["service"],
                        "exposure": item["exposure"],
                        "severity": item["severity"],
                        "banner": item.get("banner"),
                    }
                    for item in open_ports
                ],
            },
        ),
    )
