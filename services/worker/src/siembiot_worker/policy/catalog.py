"""Policy-as-data loader.

The catalog is reviewed configuration, not code. Loading validates it strictly and
computes a digest, so a score snapshot can name exactly which policy produced it.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

POLICY_ROOT = Path(__file__).resolve().parents[5] / "packages" / "policy"


class PolicyError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Pillar(StrEnum):
    DNS = "dns"
    EMAIL = "email"
    WEB_TLS = "web_tls"
    ATTACK_SURFACE = "attack_surface"
    REPUTATION = "reputation"
    EXPOSURE_HYGIENE = "exposure_hygiene"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class PublicSafetyClass(StrEnum):
    PUBLIC_AGGREGATE = "public_aggregate"
    PUBLIC_PROFILE = "public_profile"
    PRIVATE_ONLY = "private_only"


class Result(StrEnum):
    PASS = "pass"  # noqa: S105 - a check outcome, not a credential
    FAIL = "fail"
    WARNING = "warning"
    UNKNOWN = "unknown"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"
    SUPPRESSED = "suppressed"
    ACCEPTED_RISK = "accepted_risk"


SCORE_BEARING_RESULTS = frozenset({Result.PASS, Result.WARNING, Result.FAIL})
COVERAGE_REDUCING_RESULTS = frozenset({Result.UNKNOWN, Result.ERROR})
DENOMINATOR_LEAVING_RESULTS = frozenset(
    {Result.NOT_APPLICABLE, Result.SUPPRESSED, Result.ACCEPTED_RISK}
)


@dataclass(frozen=True)
class Rule:
    """One ordered condition. The first matching rule decides the result."""

    result: Result
    attribute: str | None = None
    equals: Any = None
    at_least: float | None = None
    at_most: float | None = None
    status: str | None = None
    reason_code: str | None = None


#: Observations that describe *one host* rather than the zone or the organization.
#:
#: A certificate, a redirect, a security header and a cookie belong to whatever answered
#: on that name. DNSSEC, SPF and registration expiry belong to the domain no matter how
#: many hosts it has, and asking them again per host would produce the same answer with
#: a different subject attached -- inflating coverage without observing anything new.
#:
#: Read off `observation_type` rather than listed per check, so a check added later is
#: classified by what it looks at instead of by somebody remembering this list.
HOST_SCOPED_OBSERVATION_PREFIXES: tuple[str, ...] = ("http.", "tls.")


@dataclass(frozen=True)
class Check:
    check_id: str
    version: str
    pillar: Pillar
    title_ro: str
    title_en: str
    rationale_ro: str
    rationale_en: str
    collection_mode: str
    observation_type: str
    applicability: dict[str, Any]
    rules: tuple[Rule, ...]
    weight: float
    severity: Severity
    public_safety_class: PublicSafetyClass
    remediation_template: str
    references: tuple[str, ...]

    def title(self, language: str) -> str:
        return self.title_ro if language == "ro" else self.title_en


@dataclass(frozen=True)
class Cap:
    cap_id: str
    ceiling: float
    requires_confidence: str
    check_ids: frozenset[str]
    justification_ro: str
    justification_en: str


@dataclass(frozen=True)
class Band:
    band: str
    minimum: float
    maximum: float
    label_ro: str
    label_en: str


@dataclass(frozen=True)
class Methodology:
    version: str
    pillar_weights: dict[Pillar, float]
    result_factors: dict[Result, float]
    minimum_coverage_percentage: float
    bands: tuple[Band, ...]
    caps: tuple[Cap, ...]
    high_confidence_minimum: float
    medium_confidence_minimum: float
    freshness_windows_seconds: dict[Pillar, int]
    notice: str

    def band_for(self, score: float) -> str:
        for band in self.bands:
            if band.minimum <= score <= band.maximum:
                return band.band
        raise PolicyError("score_outside_all_bands")


@dataclass(frozen=True)
class PolicyCatalog:
    methodology: Methodology
    checks: tuple[Check, ...]
    digest: str

    def by_id(self, check_id: str) -> Check:
        for check in self.checks:
            if check.check_id == check_id:
                return check
        raise PolicyError("unknown_check_id")

    def for_pillar(self, pillar: Pillar) -> tuple[Check, ...]:
        return tuple(check for check in self.checks if check.pillar is pillar)

    @property
    def check_ids(self) -> frozenset[str]:
        return frozenset(check.check_id for check in self.checks)


def _rule(raw: dict[str, Any]) -> Rule:
    when = raw.get("when")
    if not isinstance(when, dict):
        raise PolicyError("rule_missing_when")
    try:
        result = Result(raw["result"])
    except (KeyError, ValueError) as exc:
        raise PolicyError("rule_invalid_result") from exc
    unknown = set(when) - {"attribute", "equals", "at_least", "at_most", "status"}
    if unknown:
        raise PolicyError("rule_unknown_condition")
    return Rule(
        result=result,
        attribute=when.get("attribute"),
        equals=when.get("equals"),
        at_least=when.get("at_least"),
        at_most=when.get("at_most"),
        status=when.get("status"),
        reason_code=raw.get("reason_code"),
    )


def _check(raw: dict[str, Any], pillar: Pillar, letter: str) -> Check:
    check_id = raw.get("check_id")
    if not isinstance(check_id, str) or not check_id.startswith(f"{letter}."):
        raise PolicyError("check_id_pillar_mismatch")
    rules = raw.get("rules")
    if not isinstance(rules, list) or not rules:
        raise PolicyError("check_missing_rules")
    weight = raw.get("weight")
    if not isinstance(weight, int | float) or weight <= 0:
        raise PolicyError("check_invalid_weight")
    for field in ("title_ro", "title_en", "rationale_ro", "rationale_en"):
        if not str(raw.get(field, "")).strip():
            raise PolicyError("check_missing_localized_text")
    if not str(raw.get("remediation_template", "")).strip():
        raise PolicyError("check_missing_remediation_template")
    return Check(
        check_id=check_id,
        version=str(raw["version"]),
        pillar=pillar,
        title_ro=raw["title_ro"],
        title_en=raw["title_en"],
        rationale_ro=raw["rationale_ro"],
        rationale_en=raw["rationale_en"],
        collection_mode=str(raw["collection_mode"]),
        observation_type=str(raw["observation_type"]),
        applicability=dict(raw.get("applicability", {})),
        rules=tuple(_rule(item) for item in rules),
        weight=float(weight),
        severity=Severity(raw["severity"]),
        public_safety_class=PublicSafetyClass(raw["public_safety_class"]),
        remediation_template=str(raw["remediation_template"]),
        references=tuple(raw.get("references", ())),
    )


def _methodology(raw: dict[str, Any]) -> Methodology:
    weights = {Pillar(key): float(value) for key, value in raw["pillar_weights"].items()}
    if set(weights) != set(Pillar):
        raise PolicyError("pillar_weights_incomplete")
    if abs(sum(weights.values()) - 1.0) > 1e-9:
        raise PolicyError("pillar_weights_do_not_sum_to_one")
    factors = {Result(key): float(value) for key, value in raw["result_factors"].items()}
    if set(factors) != SCORE_BEARING_RESULTS:
        raise PolicyError("result_factors_must_cover_exactly_scoring_results")
    bands = tuple(
        Band(
            item["band"],
            float(item["minimum"]),
            float(item["maximum"]),
            item["label_ro"],
            item["label_en"],
        )
        for item in raw["bands"]
    )
    _validate_bands(bands)
    rollup = raw["confidence_rollup"]
    return Methodology(
        version=str(raw["methodology_version"]),
        pillar_weights=weights,
        result_factors=factors,
        minimum_coverage_percentage=float(raw["minimum_coverage_percentage"]),
        bands=bands,
        caps=tuple(
            Cap(
                item["cap_id"],
                float(item["ceiling"]),
                str(item["requires_confidence"]),
                frozenset(item["check_ids"]),
                item["justification_ro"],
                item["justification_en"],
            )
            for item in raw["caps"]
        ),
        high_confidence_minimum=float(rollup["high_minimum"]),
        medium_confidence_minimum=float(rollup["medium_minimum"]),
        freshness_windows_seconds={
            Pillar(key): int(value) for key, value in raw["freshness_windows_seconds"].items()
        },
        notice=str(raw["notice"]),
    )


def _validate_bands(bands: tuple[Band, ...]) -> None:
    ordered = sorted(bands, key=lambda band: band.minimum)
    if ordered[0].minimum != 0 or ordered[-1].maximum != 100:
        raise PolicyError("bands_must_span_zero_to_one_hundred")
    for lower, upper in zip(ordered, ordered[1:], strict=False):
        if upper.minimum - lower.maximum != 1:
            raise PolicyError("bands_must_be_contiguous_without_overlap")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


#: The methodology a new assessment runs under. Older versions stay loadable forever --
#: every stored score names the version and digest that produced it, and must remain
#: reproducible from them.
CURRENT_METHODOLOGY_VERSION = "1.1.0"


def load_catalog(
    root: Path | None = None, version: str = CURRENT_METHODOLOGY_VERSION
) -> PolicyCatalog:
    base = root or POLICY_ROOT
    methodology_raw = json.loads(
        (base / "methodology" / f"v{version}.json").read_text(encoding="utf-8")
    )
    methodology = _methodology(methodology_raw)

    # Which check documents this methodology is made of.
    #
    # Absent means `["v1"]`, which is what every existing version says by saying nothing,
    # so their digests are unchanged by this key existing. A later methodology adds a
    # directory rather than editing an existing one: a published version must keep
    # loading exactly the documents it was published with, or every score ever computed
    # under it becomes unreproducible.
    check_sets = methodology_raw.get("check_sets", ["v1"])

    documents: list[Any] = []
    checks: list[Check] = []
    paths = [
        path for name in check_sets for path in sorted((base / "checks" / name).glob("*.json"))
    ]
    for path in paths:
        raw = json.loads(path.read_text(encoding="utf-8"))
        documents.append(raw)
        groups = raw["pillars"] if "pillars" in raw else [raw]
        for group in groups:
            pillar = Pillar(group["pillar"])
            letter = str(group["pillar_letter"])
            checks.extend(_check(item, pillar, letter) for item in group["checks"])

    identifiers = [check.check_id for check in checks]
    if len(identifiers) != len(set(identifiers)):
        raise PolicyError("duplicate_check_id")
    covered = {check.pillar for check in checks}
    if covered != set(Pillar):
        raise PolicyError("catalog_missing_pillar")
    known = {check.check_id for check in checks}
    for cap in methodology.caps:
        if not cap.check_ids <= known:
            raise PolicyError("cap_references_unknown_check")

    digest = hashlib.sha256(
        _canonical({"methodology": methodology_raw, "checks": documents})
    ).hexdigest()
    return PolicyCatalog(methodology, tuple(sorted(checks, key=lambda item: item.check_id)), digest)
