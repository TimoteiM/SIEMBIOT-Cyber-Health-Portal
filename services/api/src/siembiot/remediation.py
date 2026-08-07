"""Remediation guidance, read from the shared policy package.

A finding says what is wrong. This says what to do about it, which is the part anybody
outside a security team actually needs.

Three decisions are worth stating, because each is a place this could have gone wrong.

**It is outside the scoring digest.** The digest covers the methodology and the checks,
so correcting a sentence here does not invalidate every stored score snapshot. Guidance
and measurement version independently on purpose: fixing a typo in advice is not a
change to how anything was scored.

**Every template declares a review status.** The text below was drafted from the
standards each check already cites, and has not been through security review. The
interface says so. Presenting draft guidance as settled advice would be worse than
showing none, because a reader cannot tell the difference and would act on it either
way.

**Caveats are part of the content, not a footnote.** Most of these changes can break
something: DMARC enforcement rejects real mail, HSTS is remembered by browsers for as
long as it claims, a CAA record that omits the wrong authority blocks renewal months
later. Advice that omits the failure mode is advice that costs somebody an outage.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, cast, get_args

POLICY_ROOT = Path(__file__).resolve().parents[4] / "packages" / "policy"

#: Guidance that has not been reviewed is labelled, never silently presented as final.
ReviewStatus = Literal["draft", "reviewed"]
Effort = Literal["low", "medium", "high"]
REVIEWED = "reviewed"
DRAFT = "draft"


class RemediationError(RuntimeError):
    pass


def _one_of(value: str, allowed: tuple[str, ...], field: str, template: str) -> str:
    """Reject an unknown value while loading rather than while answering a request.

    A typo in the catalogue is a mistake by whoever edited it, and it should stop the
    catalogue from loading. Letting it through turns into a failed response for a
    reader who did nothing wrong, at a moment nobody is watching the logs.
    """
    if value not in allowed:
        raise RemediationError(f"{template}: {field} is {value!r}, expected one of {allowed}")
    return value


@dataclass(frozen=True)
class Remediation:
    template_id: str
    version: str
    review_status: ReviewStatus
    effort: Effort
    references: tuple[str, ...]
    summary_ro: str
    summary_en: str
    steps_ro: tuple[str, ...]
    steps_en: tuple[str, ...]
    verification_ro: str
    verification_en: str
    #: Present only where following the guidance can break something. Absent is a
    #: claim that nothing obvious goes wrong, so it is left out rather than filled
    #: with a reassuring sentence.
    caveat_ro: str | None
    caveat_en: str | None

    @property
    def is_reviewed(self) -> bool:
        return self.review_status == REVIEWED


def _remediation(raw: dict[str, Any]) -> Remediation:
    return Remediation(
        template_id=str(raw["template_id"]),
        version=str(raw["version"]),
        review_status=cast(
            ReviewStatus,
            _one_of(
                str(raw["review_status"]),
                get_args(ReviewStatus),
                "review_status",
                str(raw["template_id"]),
            ),
        ),
        effort=cast(
            Effort,
            _one_of(str(raw["effort"]), get_args(Effort), "effort", str(raw["template_id"])),
        ),
        references=tuple(str(item) for item in raw.get("references", ())),
        summary_ro=str(raw["summary_ro"]),
        summary_en=str(raw["summary_en"]),
        steps_ro=tuple(str(item) for item in raw["steps_ro"]),
        steps_en=tuple(str(item) for item in raw["steps_en"]),
        verification_ro=str(raw["verification_ro"]),
        verification_en=str(raw["verification_en"]),
        caveat_ro=str(raw["caveat_ro"]) if raw.get("caveat_ro") else None,
        caveat_en=str(raw["caveat_en"]) if raw.get("caveat_en") else None,
    )


@lru_cache(maxsize=8)
def load_remediation(version: str = "1.0.0") -> dict[str, Remediation]:
    """Every remediation template, keyed by identifier."""
    directory = POLICY_ROOT / "remediation" / f"v{version.split('.')[0]}"
    if not directory.is_dir():
        raise RemediationError(f"no remediation catalog for methodology {version}")

    templates: dict[str, Remediation] = {}
    for path in sorted(directory.glob("*.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        groups = raw["pillars"] if "pillars" in raw else [raw]
        for group in groups:
            for item in group["templates"]:
                entry = _remediation(item)
                if entry.template_id in templates:
                    raise RemediationError(f"duplicate remediation {entry.template_id}")
                templates[entry.template_id] = entry
    if not templates:
        raise RemediationError(f"empty remediation catalog for methodology {version}")
    return templates
