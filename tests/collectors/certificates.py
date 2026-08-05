"""Deterministic in-memory certificate fixtures.

Certificates are generated rather than checked in so no fixture can expire and
silently change a golden test's meaning.
"""

from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

REFERENCE_NOW = dt.datetime(2026, 8, 5, 12, 0, tzinfo=dt.UTC)


def build_certificate(
    *,
    common_name: str,
    dns_names: tuple[str, ...],
    not_before: dt.datetime = REFERENCE_NOW - dt.timedelta(days=30),
    not_after: dt.datetime = REFERENCE_NOW + dt.timedelta(days=300),
    issuer_name: str | None = None,
    rsa_bits: int | None = None,
) -> bytes:
    if rsa_bits is not None:
        key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey = rsa.generate_private_key(
            public_exponent=65537, key_size=rsa_bits
        )
    else:
        key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name or common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names]),
            critical=False,
        )
    )
    return builder.sign(key, hashes.SHA256()).public_bytes(encoding=Encoding.DER)
