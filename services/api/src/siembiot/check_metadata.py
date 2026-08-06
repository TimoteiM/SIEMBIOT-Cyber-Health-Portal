"""Presentation metadata for checks, read from the shared policy package.

A finding row stores what was decided -- the check, the severity, the reason, the
evidence it rests on -- and deliberately not the prose that explains it. Copying
titles and rationales into every row would duplicate the catalog thousands of times
and let the copies drift from the policy that actually produced the result.

So the row is the record and this is the rendering. The API reads `packages/policy/`
directly: it is shared data, not worker code, and the API gains no dependency on the
worker service by reading it.

Two things this module refuses to do:

*It does not evaluate anything.* Only titles, rationales, severities and references
are read. The rules that decide pass or fail are the worker's business, and a second
implementation of them here would eventually disagree with the first.

*It does not invent remediation.* The catalog names a `remediation_template` per check
but the templates do not exist yet, so the identifier is passed through as-is. Writing
plausible-sounding security advice to fill the gap would be worse than the gap: a
reader cannot tell invented guidance from reviewed guidance, and would act on it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

POLICY_ROOT = Path(__file__).resolve().parents[4] / "packages" / "policy"


class CheckMetadataError(RuntimeError):
    pass


@dataclass(frozen=True)
class CheckMetadata:
    """What a reader needs to understand a finding, in both languages."""

    check_id: str
    version: str
    pillar: str
    pillar_letter: str
    title_ro: str
    title_en: str
    rationale_ro: str
    rationale_en: str
    severity: str
    weight: int
    public_safety_class: str
    remediation_template: str | None
    references: tuple[str, ...]


def _metadata(raw: dict[str, Any], pillar: str, letter: str) -> CheckMetadata:
    return CheckMetadata(
        check_id=str(raw["check_id"]),
        version=str(raw["version"]),
        pillar=pillar,
        pillar_letter=letter,
        title_ro=str(raw["title_ro"]),
        title_en=str(raw["title_en"]),
        rationale_ro=str(raw["rationale_ro"]),
        rationale_en=str(raw["rationale_en"]),
        severity=str(raw["severity"]),
        weight=int(raw["weight"]),
        public_safety_class=str(raw["public_safety_class"]),
        remediation_template=(
            str(raw["remediation_template"]) if raw.get("remediation_template") else None
        ),
        references=tuple(str(item) for item in raw.get("references", ())),
    )


@lru_cache(maxsize=8)
def load_check_metadata(version: str = "1.0.0") -> dict[str, CheckMetadata]:
    """Every check in the catalog, keyed by identifier.

    Cached because the files do not change while the process runs, and a findings list
    would otherwise re-read and re-parse the whole catalog per request.
    """
    directory = POLICY_ROOT / "checks" / f"v{version.split('.')[0]}"
    if not directory.is_dir():
        raise CheckMetadataError(f"no check catalog for methodology {version}")

    metadata: dict[str, CheckMetadata] = {}
    for path in sorted(directory.glob("*.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        # Some files carry one pillar, others carry several under "pillars". Both
        # shapes are the catalog's, not ours to normalize at the source.
        groups = raw["pillars"] if "pillars" in raw else [raw]
        for group in groups:
            pillar = str(group["pillar"])
            letter = str(group["pillar_letter"])
            for item in group["checks"]:
                entry = _metadata(item, pillar, letter)
                if entry.check_id in metadata:
                    raise CheckMetadataError(f"duplicate check {entry.check_id}")
                metadata[entry.check_id] = entry
    if not metadata:
        raise CheckMetadataError(f"empty check catalog for methodology {version}")
    return metadata
