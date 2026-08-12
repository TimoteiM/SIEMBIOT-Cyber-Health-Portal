"""Whether a claim is supported by something a reader could check.

Written before anything that calls a model, deliberately. A validator added afterwards is
written to accept what the model already produces; written first, it says what will be
accepted and the model has to meet it.

The rule is narrow and unforgiving: **a claim cites at least one immutable evidence
identifier that belongs to this run's scope, or an approved knowledge-base reference, or
it is dropped.** Not flagged, not shown with a caveat, not rendered in grey -- dropped.

That is deliberate and it is the whole point. A sentence a reader cannot check is
indistinguishable from one that is invented, and this platform's readers are public
institutions who will act on what it says. A plausible unsupported sentence is worse than
a missing one, because the missing one is obviously missing.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

#: Knowledge-base references a claim may cite. A closed set: an "approved reference" that
#: the model can invent is not a reference, and a citation to a document nobody vetted
#: carries the authority of one that was.
APPROVED_REFERENCES: frozenset[str] = frozenset(
    {
        "rfc1034",
        "rfc3207",
        "rfc4033",
        "rfc4035",
        "rfc4592",
        "rfc5280",
        "rfc6125",
        "rfc6265bis",
        "rfc6376",
        "rfc6797",
        "rfc6962",
        "rfc7208",
        "rfc7483",
        "rfc7489",
        "rfc8460",
        "rfc8461",
        "rfc8659",
        "rfc8996",
        "rfc9110",
        "owasp_secure_headers",
        "nist_sp_800_41",
        "nist_sp_800_46",
        "provider_terms",
    }
)

MISSING_SUPPORT = "claim_cites_nothing"
UNKNOWN_EVIDENCE = "claim_cites_unknown_evidence"
OUT_OF_SCOPE_EVIDENCE = "claim_cites_evidence_outside_scope"
UNKNOWN_REFERENCE = "claim_cites_unapproved_reference"
FORBIDDEN_NUMBER = "claim_states_a_score"


@dataclass(frozen=True)
class Support:
    type: str
    id: str


@dataclass(frozen=True)
class Claim:
    text: str
    kind: str
    support: tuple[Support, ...]


@dataclass(frozen=True)
class Verdict:
    accepted: tuple[Claim, ...]
    rejected: tuple[tuple[Claim, str], ...]

    @property
    def rejection_reasons(self) -> tuple[str, ...]:
        return tuple(reason for _, reason in self.rejected)


#: Words that would make a claim a scoring statement. The model may describe what is
#: wrong; it may not say how bad it is on this platform's scale, because a severity or a
#: band is a deterministic output and a sentence asserting one competes with it.
_SCORING_TERMS = (
    "score",
    "scor",
    "band",
    "nivel",
    "severity",
    "severitate",
    "critical",
    "critic",
    "resilient",
    "rezilient",
    "out of 100",
    "din 100",
)


def _states_a_score(text: str) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in _SCORING_TERMS)


def validate_claims(
    claims: tuple[Claim, ...],
    *,
    known_evidence: frozenset[UUID],
    references: frozenset[str] = APPROVED_REFERENCES,
) -> Verdict:
    """Keep the claims that are supported; drop the rest, with a reason for each.

    `known_evidence` is the set of identifiers this run is entitled to, gathered from the
    tenant-scoped tools that served it. Checking against that rather than against "does
    this look like a UUID" is what makes a citation to another organization's evidence a
    rejection rather than a footnote.
    """
    accepted: list[Claim] = []
    rejected: list[tuple[Claim, str]] = []

    for claim in claims:
        reason = _reason_to_reject(claim, known_evidence, references)
        if reason is None:
            accepted.append(claim)
        else:
            rejected.append((claim, reason))

    return Verdict(tuple(accepted), tuple(rejected))


def _reason_to_reject(
    claim: Claim, known_evidence: frozenset[UUID], references: frozenset[str]
) -> str | None:
    if not claim.support:
        return MISSING_SUPPORT

    # A scoring statement is refused even when it is perfectly well cited: the objection
    # is not that it might be wrong but that it is not the model's to make.
    if _states_a_score(claim.text):
        return FORBIDDEN_NUMBER

    for support in claim.support:
        if support.type == "reference":
            if support.id not in references:
                return UNKNOWN_REFERENCE
            continue

        try:
            evidence_id = UUID(support.id)
        except ValueError:
            return UNKNOWN_EVIDENCE
        if evidence_id not in known_evidence:
            # Deliberately one reason rather than two. "That evidence exists but is not
            # yours" tells a caller something about another tenant's data; "not in this
            # run" tells them only about their own.
            return OUT_OF_SCOPE_EVIDENCE

    return None
