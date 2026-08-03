from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from siembiot.domains.normalization import (
    DomainValidationError,
    PublicSuffixList,
    normalize_domain,
)

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def psl() -> PublicSuffixList:
    return PublicSuffixList.from_text(
        """
        // deterministic test subset
        com
        de
        ro
        uk
        co.uk
        *.ck
        !www.ck
        """
    )


@pytest.mark.parametrize(
    ("value", "canonical", "display", "registrable"),
    [
        ("Example.COM", "example.com", "example.com", "example.com"),
        ("școală.ro", "xn--coal-3sa77n.ro", "școală.ro", "xn--coal-3sa77n.ro"),
        ("www.service.co.uk", "www.service.co.uk", "www.service.co.uk", "service.co.uk"),
        ("www.ck", "www.ck", "www.ck", "www.ck"),
        ("host.a.ck", "host.a.ck", "host.a.ck", "host.a.ck"),
    ],
)
def test_normalizes_exact_domain_identity(
    psl: PublicSuffixList,
    value: str,
    canonical: str,
    display: str,
    registrable: str,
) -> None:
    result = normalize_domain(value, psl)
    assert result.canonical_name == canonical
    assert result.unicode_display == display
    assert result.registrable_domain == registrable


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("com", "public_suffix"),
        ("co.uk", "public_suffix"),
        ("a.ck", "public_suffix"),
        ("127.0.0.1", "ip_literal"),
        ("[::1]", "ip_literal"),
        ("https://example.com", "url_not_domain"),
        ("example.com/path", "url_not_domain"),
        ("user@example.com", "credentials_not_allowed"),
        ("example.com:443", "port_not_allowed"),
        ("*.example.com", "wildcard_not_allowed"),
        ("example.com.", "trailing_dot"),
        (" example.com", "whitespace"),
        ("example..com", "malformed_domain"),
        ("-bad.com", "malformed_domain"),
        ("bad-.com", "malformed_domain"),
    ],
)
def test_rejects_non_domain_or_ambiguous_input(
    psl: PublicSuffixList, value: str, reason: str
) -> None:
    with pytest.raises(DomainValidationError) as caught:
        normalize_domain(value, psl)
    assert caught.value.reason == reason


def test_surfaces_neutral_idn_and_mixed_script_warnings(psl: PublicSuffixList) -> None:
    result = normalize_domain("exаmple.com", psl)  # Cyrillic small a
    assert result.canonical_name.startswith("xn--")
    assert result.warnings == ("idn_present", "mixed_scripts")


def test_default_psl_is_pinned_and_has_recorded_provenance() -> None:
    data_path = ROOT / "packages" / "policy" / "public_suffix_list" / "public_suffix_list.dat"
    provenance_path = data_path.with_name("PROVENANCE.md")
    digest = hashlib.sha256(data_path.read_bytes()).hexdigest()
    provenance = provenance_path.read_text(encoding="utf-8")
    assert digest == "fe6adc7fb8014f57d28d69b18d0aa3e581efb432544922e12131a5d4a87bd954"
    assert "e1b8015c3b2f0f4f8c18659c2480fc1a22c07b20" in provenance
    assert digest in provenance
    assert normalize_domain("institutie.ro").registrable_domain == "institutie.ro"


@given(
    first=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=20),
    second=st.sampled_from(["com", "de", "ro"]),
)
def test_canonical_output_is_lowercase_and_unambiguous(
    psl: PublicSuffixList, first: str, second: str
) -> None:
    result = normalize_domain(f"{first}.{second}", psl)
    assert result.canonical_name == result.canonical_name.lower()
    assert not result.canonical_name.endswith(".")
    assert ":" not in result.canonical_name
