"""TLS and certificate collection (pillar C).

Handshake observations only. A weak signature or a short key is recorded as an
observed property; whether it fails a check is the scoring engine's decision.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from siembiot_worker.adapters.contract import (
    AdapterDescriptor,
    AdapterGroup,
    CachePolicy,
    CollectionResult,
    CostUnit,
    DataClassification,
    RateLimitPolicy,
)
from siembiot_worker.collectors.base import Collector
from siembiot_worker.network_safety.collection_broker import CollectionRequest
from siembiot_worker.network_safety.tls_client import ProtocolProbeResult, TLSObservation

WEAK_SIGNATURE_ALGORITHMS = frozenset({"md5", "sha1", "md2", "md4"})
DEPRECATED_PROTOCOLS = frozenset({"TLSv1", "TLSv1.1"})
MINIMUM_RSA_BITS = 2048
MINIMUM_EC_BITS = 256

TLS_DESCRIPTOR = AdapterDescriptor(
    adapter_id="tls_certificate",
    version="1.0.0",
    group=AdapterGroup.TLS_HTTP,
    title="TLS and certificate collector",
    capabilities=frozenset({"tls.certificate", "tls.chain", "tls.protocols", "tls.expiry"}),
    data_classification=DataClassification.PUBLIC_OBSERVATION,
    terms_notes="Direct TLS handshakes against the authorized host; no data is sent.",
    terms_url=None,
    required_secrets=frozenset(),
    timeout_seconds=8.0,
    rate_limit=RateLimitPolicy(5, 1.0, burst=2, minimum_interval_seconds=0.1),
    cost_unit=CostUnit.NONE,
    cache=CachePolicy(900),
    supports_fixtures=True,
)


def _key_properties(certificate: x509.Certificate) -> dict[str, Any]:
    key = certificate.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return {"type": "rsa", "bits": key.key_size, "weak": key.key_size < MINIMUM_RSA_BITS}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {
            "type": "ec",
            "bits": key.curve.key_size,
            "curve": key.curve.name,
            "weak": key.curve.key_size < MINIMUM_EC_BITS,
        }
    if isinstance(key, dsa.DSAPublicKey):
        return {"type": "dsa", "bits": key.key_size, "weak": True}
    if isinstance(key, ed25519.Ed25519PublicKey):
        return {"type": "ed25519", "bits": 256, "weak": False}
    if isinstance(key, ed448.Ed448PublicKey):
        return {"type": "ed448", "bits": 448, "weak": False}
    return {"type": "unknown", "bits": None, "weak": None}


def _subject_alternative_names(certificate: x509.Certificate) -> list[str]:
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return sorted(extension.value.get_values_for_type(x509.DNSName))


def hostname_covered(hostname: str, names: list[str]) -> bool:
    """Match a hostname against SAN entries, allowing a single leftmost wildcard."""
    lowered = hostname.lower()
    for name in names:
        candidate = name.lower()
        if candidate == lowered:
            return True
        if candidate.startswith("*."):
            suffix = candidate[1:]
            if lowered.endswith(suffix) and lowered.count(".") == candidate.count("."):
                return True
    return False


def describe_certificate(der: bytes, hostname: str, now: datetime) -> dict[str, Any]:
    certificate = x509.load_der_x509_certificate(der)
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    names = _subject_alternative_names(certificate)
    algorithm = (
        (certificate.signature_hash_algorithm.name or "unknown").lower()
        if (certificate.signature_hash_algorithm is not None)
        else "unknown"
    )
    return {
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serial_number": format(certificate.serial_number, "x"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": (not_after - now).days,
        "expired": now > not_after,
        "not_yet_valid": now < not_before,
        "validity_days": (not_after - not_before).days,
        "signature_algorithm": algorithm,
        "weak_signature": algorithm in WEAK_SIGNATURE_ALGORITHMS,
        "public_key": _key_properties(certificate),
        "subject_alternative_names": names,
        "hostname_covered": hostname_covered(hostname, names),
        "self_signed": certificate.issuer == certificate.subject,
    }


class TLSCertificateCollector(Collector):
    descriptor = TLS_DESCRIPTOR

    def collect(
        self, request: CollectionRequest, *, probe_protocols: bool = True
    ) -> CollectionResult:
        observation, probes = self._broker.inspect_tls(request, probe_protocols=probe_protocols)
        host = request.canonical_host
        if observation.status in {"timeout", "connection_refused"}:
            return self.unavailable(
                observation.status, {"host": host, "handshake": self._handshake(observation)}
            )
        if observation.status == "error":
            return self.error(observation.verification_error or "tls_error")

        payload: dict[str, Any] = {
            "host": host,
            "handshake": self._handshake(observation),
            "protocols": self._protocols(probes),
            "chain": [],
            "leaf": None,
            "chain_parse_errors": [],
        }
        now = self._clock().astimezone(UTC)
        for index, der in enumerate(observation.certificate_chain):
            try:
                described = describe_certificate(der, host, now)
            except (ValueError, TypeError):
                payload["chain_parse_errors"].append(index)
                continue
            payload["chain"].append(described)
        if payload["chain"]:
            payload["leaf"] = payload["chain"][0]
        payload["chain_length"] = len(payload["chain"])

        reasons: list[str] = []
        if payload["chain_parse_errors"]:
            reasons.append("certificate_parse_failed")
        if observation.status == "handshake_failed":
            reasons.append("handshake_failed")
        if probe_protocols and not probes:
            reasons.append("protocol_probes_unavailable")
        if not payload["chain"]:
            reasons.append("no_certificate_observed")
        if reasons:
            return self.partial(payload, tuple(reasons), source=host)
        return self.ok(payload, source=host)

    @staticmethod
    def _handshake(observation: TLSObservation) -> dict[str, Any]:
        return {
            "status": observation.status,
            "negotiated_version": observation.negotiated_version,
            "negotiated_cipher": observation.negotiated_cipher,
            "trusted": observation.trusted,
            "hostname_verified": observation.hostname_verified,
            "verification_error": observation.verification_error,
        }

    @staticmethod
    def _protocols(probes: tuple[ProtocolProbeResult, ...]) -> dict[str, Any]:
        supported = sorted(probe.version for probe in probes if probe.supported)
        inconclusive = sorted(
            probe.version
            for probe in probes
            if not probe.supported and probe.status in {"timeout", "error"}
        )
        return {
            "probed": [
                {"version": probe.version, "supported": probe.supported, "status": probe.status}
                for probe in probes
            ],
            "supported": supported,
            "deprecated_supported": sorted(set(supported) & DEPRECATED_PROTOCOLS),
            "inconclusive": inconclusive,
        }
