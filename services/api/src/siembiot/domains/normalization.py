from __future__ import annotations

import ipaddress
import unicodedata
from dataclasses import dataclass
from pathlib import Path

import idna


class DomainValidationError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class NormalizedDomain:
    canonical_name: str
    unicode_display: str
    registrable_domain: str
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class PublicSuffixList:
    exact_rules: frozenset[str]
    wildcard_bases: frozenset[str]
    exception_rules: frozenset[str]

    @classmethod
    def from_text(cls, text: str) -> PublicSuffixList:
        exact: set[str] = set()
        wildcards: set[str] = set()
        exceptions: set[str] = set()
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("//"):
                continue
            normalized = idna.encode(
                line.removeprefix("!").removeprefix("*."),
                uts46=True,
                std3_rules=True,
                transitional=False,
            ).decode("ascii")
            if line.startswith("!"):
                exceptions.add(normalized)
            elif line.startswith("*."):
                wildcards.add(normalized)
            else:
                exact.add(normalized)
        return cls(frozenset(exact), frozenset(wildcards), frozenset(exceptions))

    @classmethod
    def load_default(cls) -> PublicSuffixList:
        root = Path(__file__).resolve().parents[5]
        path = root / "packages" / "policy" / "public_suffix_list" / "public_suffix_list.dat"
        return cls.from_text(path.read_text(encoding="utf-8"))

    def public_suffix_labels(self, canonical_name: str) -> int:
        labels = canonical_name.split(".")
        for index in range(len(labels)):
            suffix = ".".join(labels[index:])
            if suffix in self.exception_rules:
                return len(labels) - index - 1

        match_length = 1
        for index in range(len(labels)):
            suffix = ".".join(labels[index:])
            suffix_length = len(labels) - index
            if suffix in self.exact_rules:
                match_length = max(match_length, suffix_length)
            if index > 0 and suffix in self.wildcard_bases:
                match_length = max(match_length, suffix_length + 1)
        return match_length

    def registrable_domain(self, canonical_name: str) -> str:
        labels = canonical_name.split(".")
        suffix_length = self.public_suffix_labels(canonical_name)
        if len(labels) <= suffix_length:
            raise DomainValidationError("public_suffix")
        return ".".join(labels[-(suffix_length + 1) :])


def _reject_non_domain(value: str) -> None:
    if value != value.strip() or any(character.isspace() for character in value):
        raise DomainValidationError("whitespace")
    if not value:
        raise DomainValidationError("malformed_domain")
    if value.endswith("."):
        raise DomainValidationError("trailing_dot")
    if "*" in value:
        raise DomainValidationError("wildcard_not_allowed")
    if "@" in value:
        raise DomainValidationError("credentials_not_allowed")
    if "://" in value or any(character in value for character in "/\\?#"):
        raise DomainValidationError("url_not_domain")

    candidate = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise DomainValidationError("ip_literal")
    if ":" in value:
        raise DomainValidationError("port_not_allowed")


def _script_warnings(display: str) -> tuple[str, ...]:
    if display.isascii():
        return ()
    scripts: set[str] = set()
    for character in display:
        if not character.isalpha():
            continue
        name = unicodedata.name(character, "")
        for script in ("LATIN", "CYRILLIC", "GREEK"):
            if script in name:
                scripts.add(script)
                break
    warnings = ["idn_present"]
    if len(scripts) > 1:
        warnings.append("mixed_scripts")
    return tuple(warnings)


def normalize_domain(value: str, psl: PublicSuffixList | None = None) -> NormalizedDomain:
    _reject_non_domain(value)
    try:
        canonical = (
            idna.encode(
                unicodedata.normalize("NFC", value),
                uts46=True,
                std3_rules=True,
                transitional=False,
            )
            .decode("ascii")
            .lower()
        )
        display = idna.decode(canonical.encode("ascii"), uts46=True, std3_rules=True).lower()
    except idna.IDNAError as exc:
        raise DomainValidationError("malformed_domain") from exc

    if len(canonical) > 253 or any(len(label) > 63 for label in canonical.split(".")):
        raise DomainValidationError("malformed_domain")

    suffix_list = psl or PublicSuffixList.load_default()
    return NormalizedDomain(
        canonical_name=canonical,
        unicode_display=display,
        registrable_domain=suffix_list.registrable_domain(canonical),
        warnings=_script_warnings(display),
    )
