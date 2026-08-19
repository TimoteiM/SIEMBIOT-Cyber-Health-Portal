"""Downloading an assessment as a document.

Two steps, deliberately. Asking for a report mints a short-lived, single-use grant;
downloading redeems it. One step would have meant a URL that produces a confidential
document every time it is opened, and such URLs end up in browser history, referrer
headers, chat threads and screen shares.

**The token is not sufficient on its own.** Redeeming still requires the session of the
person it was issued to, so a leaked link does nothing for anybody else. The token's job
is to bound the window and make each download deliberate; the session's job is to say who
is asking. Together they mean a copied URL is inert.

The report is rendered on demand from the stored snapshot rather than saved anywhere.
That is what keeps it reproducible, and it means there is no second copy of a
confidential document sitting in a table waiting to be read.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response
from siembiot_worker.policy.catalog import load_catalog
from siembiot_worker.reports import (
    LOCALES,
    ReportAssetGroup,
    ReportCap,
    ReportCheck,
    ReportDocument,
    ReportEvidence,
    ReportFinding,
    ReportInsight,
    ReportPillar,
    render_report,
)
from siembiot_worker.reports.pdf import RENDERER_UNAVAILABLE, render_pdf, renderer_available
from sqlalchemy import Connection, text

from siembiot.auth import current_principal
from siembiot.authorization import Action
from siembiot.check_metadata import CheckMetadata, load_check_metadata
from siembiot.contracts import ContractModel
from siembiot.db import Database
from siembiot.errors import AppError
from siembiot.identity import Principal
from siembiot.organizations import authorize
from siembiot.remediation import load_remediation

#: Long enough to click a link and for a slow browser to follow it; short enough that a
#: link left in history is almost always already dead.
GRANT_LIFETIME = timedelta(minutes=5)

#: 32 bytes from the system CSPRNG. Guessing is not a threat model anybody has to reason
#: about at this size; the interesting risks are leakage and replay, which the binding to
#: a session and the single use address.
TOKEN_BYTES = 32


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _filename_part(domain: str) -> str:
    """A domain name reduced to characters that are safe in a header.

    Host policy already restricts what can be enrolled, so in practice nothing is
    removed. It is done anyway because this value is interpolated into an HTTP header:
    a newline in a header is response splitting, and "the other validator makes this
    impossible" is the assumption every such bug is built on.
    """
    safe = "".join(character for character in domain if character.isalnum() or character in "-.")
    return safe[:100] or "assessment"


class ReportGrantResponse(ContractModel):
    """Where to download the report, and for how long.

    The token is returned exactly once, here. It is stored hashed, so this response is
    the only moment it exists in readable form -- by design.
    """

    download_path: str
    locale: str
    document_format: str
    assessment_id: UUID
    expires_at: datetime


def _database(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def _latest_scored_assessment(connection: Connection, domain_id: UUID) -> Any:
    row = connection.execute(
        text(
            """
            SELECT a.id AS assessment_id, a.mode, a.completed_at, a.created_at,
                   s.methodology_version, s.policy_digest, s.document, s.computed_at,
                   s.evidence_erased_at
            FROM assessments a
            JOIN score_snapshots s ON s.assessment_id = a.id
            WHERE a.domain_id = :domain_id AND s.is_projection = false
            ORDER BY s.computed_at DESC
            LIMIT 1
            """
        ),
        {"domain_id": domain_id},
    ).mappings()
    return row.first()


def _findings_for(connection: Connection, domain_id: UUID) -> list[Any]:
    """The domain's open findings.

    Keyed by domain rather than by assessment because that is what a finding is: it has a
    lifecycle across runs, with a first-seen and a last-seen, and is resolved when it
    stops being observed. Selecting "the findings of this assessment" would report only
    what the most recent run happened to re-observe, and quietly drop a weakness that is
    still there.

    Resolved ones are excluded. A list mixing fixed with unfixed reads as longer than the
    problem actually is, which is its own kind of misleading.
    """
    return list(
        connection.execute(
            text(
                """
                SELECT check_id, severity, subject_identifier, reason_code
                FROM findings
                WHERE authorized_domain_id = :domain_id AND state <> 'resolved'
                """
            ),
            {"domain_id": domain_id},
        ).mappings()
    )


#: What the evaluator records for a check a passive run was not permitted to perform.
WITHHELD_REASON = "requires_authorized_assessment"


def _withheld_checks(connection: Connection, assessment_id: UUID) -> tuple[str, ...]:
    """Checks this run was not permitted to perform.

    Read from what the run actually recorded rather than derived from the catalogue and
    the mode. Deriving it would produce a list that is right about the policy and
    possibly wrong about the run -- and the report's claim is about the run.

    Sorted, because the query has no ordering that survives a plan change and a report
    that differs from itself between renders is not reproducible.
    """
    rows = connection.execute(
        text(
            """
            SELECT DISTINCT check_id FROM check_evaluations
            WHERE assessment_id = :assessment_id AND reason_code = :reason
            """
        ),
        {"assessment_id": assessment_id, "reason": WITHHELD_REASON},
    ).scalars()
    return tuple(sorted(str(check_id) for check_id in rows))


#: Attributes that describe the platform's own bookkeeping rather than the target.
#:
#: Hidden because a reader looking for what was found should not have to step over how
#: the check was routed. Nothing is hidden that describes the institution.
_INTERNAL_ATTRIBUTES = frozenset({"mx_present", "conclusive", "status_detail"})

#: How many attributes one finding may show. Enough for the evidence behind any check in
#: the catalogue, short enough that a report stays a report.
_MAX_EVIDENCE_ROWS = 12


#: Which field names a list item by, in preference order.
#:
#: Several collectors record a list of structures rather than of scalars -- open ports
#: carry a service, an exposure class and a banner; mail servers carry a state and a
#: banner. `str()` on one of those produces a Python dict repr, and the old code cut it
#: at eighty characters, so a report to a public institution read
#: `{'port': 22, 'service': 'ssh', 'exposure': 'remote_access', 'severity': 'high', ,` --
#: mid-key, and one field short of printing the software version off their own server.
#:
#: So an item is named by the field a reader would recognise it by, and an item with no
#: such field is left out rather than dumped.
_ITEM_NAMES = ("port", "host", "name", "hostname", "address")

#: How many items of a list are shown. The rest are counted, never silently dropped.
_MAX_LIST_ITEMS = 6


def _readable_list(value: list[Any]) -> str | None:
    """One list attribute as a short string, or None when nothing in it can be shown."""
    parts: list[str] = []
    for item in value:
        if isinstance(item, dict):
            named = next(
                (item[key] for key in _ITEM_NAMES if key in item and item[key] not in (None, "")),
                None,
            )
            if named is None:
                continue
            parts.append(str(named)[:60])
        elif item not in (None, ""):
            parts.append(str(item)[:60])

    if not parts:
        return None
    shown = parts[:_MAX_LIST_ITEMS]
    rendered = ", ".join(shown)
    if len(parts) > _MAX_LIST_ITEMS:
        # Counted rather than trimmed away: a list cut without saying so reads as the
        # whole list, which is the same failure the omitted-attribute count exists for.
        rendered = f"{rendered} (+{len(parts) - len(shown)})"
    return rendered[:200]


def _readable(value: Any) -> str | None:
    """One evidence value as a short string, or None to omit it.

    Nothing here escapes anything: the element tree does that on serialization, and a
    second escaping layer would either double-encode or create a place where somebody
    later forgets. What this does is decide what is worth showing.
    """
    if value is None or value == "" or value == [] or value == {}:
        return None
    if isinstance(value, bool):
        return "da/nu"  # replaced per locale by the renderer
    if isinstance(value, int | float):
        return f"{value:g}"
    if isinstance(value, str):
        return value[:200]
    if isinstance(value, list):
        return _readable_list(value)
    if isinstance(value, dict):
        # A breakdown -- open ports by exposure class is the only one so far. Rendered as
        # `name:count` pairs and translated by the renderer, which is where the
        # vocabulary lives. Zero counts are dropped: "database: 0" is a row that occupies
        # the reader's attention to tell them nothing happened.
        pairs = [
            f"{str(key)[:60]}:{item:g}"
            if isinstance(item, int | float)
            else f"{str(key)[:60]}:{item}"
            for key, item in list(value.items())[:8]
            if item not in (None, "", 0, False)
        ]
        return ", ".join(pairs)[:200] or None
    return None


def _evidence_rows(attributes: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """The showable attributes, capped, in the order the collector recorded them."""
    rows: list[tuple[str, str]] = []
    for name, value in attributes.items():
        if name in _INTERNAL_ATTRIBUTES:
            continue
        shown = _readable(value)
        if shown is None:
            continue
        rows.append((name, "true" if value is True else "false" if value is False else shown))
        if len(rows) == _MAX_EVIDENCE_ROWS:
            break
    return tuple(rows)


def _evidence_omitted(attributes: dict[str, Any], shown: int) -> int:
    """How many attributes the cap left out.

    No collector currently emits more than eight, so this is zero everywhere today. It
    exists because the cap is the same mistake this section was built to fix: a report
    that quietly says less than it knows, in a place where the reader has no way to tell.
    A truncation nobody is told about is indistinguishable from there being nothing more.
    """
    showable = sum(
        1
        for name, value in attributes.items()
        if name not in _INTERNAL_ATTRIBUTES and _readable(value) is not None
    )
    return max(0, showable - shown)


def _observations_for(connection: Connection, assessment_id: UUID) -> dict[tuple[str, str], Any]:
    """Every observation of this run, indexed by what it observed and about whom.

    Keyed on subject as well as type because an assessment covers the domain and any
    accepted asset, and attaching a subdomain's evidence to the domain's finding would be
    a quiet lie about where the weakness is.
    """
    rows = connection.execute(
        text(
            """
            SELECT observation_type, subject_identifier, status, attributes
            FROM normalized_observations WHERE assessment_id = :assessment_id
            """
        ),
        {"assessment_id": assessment_id},
    ).mappings()
    return {(str(r["observation_type"]), str(r["subject_identifier"])): r for r in rows}


def _finding_document(
    row: Any,
    metadata: dict[str, CheckMetadata],
    remediation: dict[str, Any],
    observations: dict[tuple[str, str], Any] | None = None,
) -> ReportFinding:
    check_id = str(row["check_id"])
    entry = metadata.get(check_id)
    # A check the catalogue no longer describes still renders, under its identifier.
    # Dropping it would quietly shorten the list of weaknesses, which is the one mistake
    # this document must never make.
    guidance = (
        remediation.get(entry.remediation_template)
        if entry and entry.remediation_template
        else None
    )
    observed = (
        (observations or {}).get((entry.observation_type, str(row["subject_identifier"])))
        if entry
        else None
    )
    evidence = _evidence_rows(observed["attributes"]) if observed else ()
    return ReportFinding(
        check_id=check_id,
        severity=str(row["severity"]),
        subject=str(row["subject_identifier"]),
        title_ro=entry.title_ro if entry else check_id,
        title_en=entry.title_en if entry else check_id,
        rationale_ro=entry.rationale_ro if entry else "",
        rationale_en=entry.rationale_en if entry else "",
        reason_code=row["reason_code"],
        remediation_summary_ro=getattr(guidance, "summary_ro", None),
        remediation_summary_en=getattr(guidance, "summary_en", None),
        remediation_steps_ro=tuple(getattr(guidance, "steps_ro", ()) or ()),
        remediation_steps_en=tuple(getattr(guidance, "steps_en", ()) or ()),
        remediation_caveat_ro=getattr(guidance, "caveat_ro", None),
        remediation_caveat_en=getattr(guidance, "caveat_en", None),
        remediation_review_status=getattr(guidance, "review_status", None),
        evidence=evidence,
        evidence_omitted=(
            _evidence_omitted(observed["attributes"], len(evidence)) if observed else 0
        ),
        evidence_status=str(observed["status"]) if observed else None,
        evidence_type=entry.observation_type if observed and entry else None,
    )


#: Which outcome wins when one check was evaluated against several subjects.
#:
#: Worst-first, and deliberately so: a check that passes on the domain and fails on an
#: accepted subdomain is a check the institution has to act on, and reporting the
#: domain's result alone would describe a weakness that exists as one that does not.
#: `unknown` outranks `pass` for the same reason -- one subject we could not test is not
#: evidence that the check is satisfied.
_OUTCOME_PRECEDENCE = ("fail", "warning", "unknown", "pass", "not_applicable")


def _checks_for(
    connection: Connection,
    assessment_id: UUID,
    metadata: dict[str, CheckMetadata],
    subject: str,
) -> tuple[ReportCheck, ...]:
    """Every check this assessment evaluated, with the outcome it reached.

    Read from the evaluations rather than from the findings, because findings are only
    the negative ones -- that is what a finding is. The question this answers is the
    other one: what was looked at, and what came back clean.

    A check the catalogue no longer describes still appears, under its identifier, on the
    same reasoning that keeps an unknown finding in the list: dropping it would shorten
    the account of what was examined, and shortening that is the failure this section
    exists to prevent.

    Scoped to the domain, because the score, the pillars and the findings all are. An
    assessment also evaluates every accepted subdomain, and folding those in put a check
    under "requirements not met" that had failed on a subdomain while the pillar beside
    it said the domain passed and no finding explained either. Three parts of one page
    describing three different subjects is worse than any of them being wrong.
    """
    rows = connection.execute(
        text(
            """
            SELECT check_id, result
            FROM check_evaluations
            WHERE assessment_id = :assessment_id
              AND subject_identifier = :subject
            """
        ),
        {"assessment_id": assessment_id, "subject": subject},
    ).mappings()

    worst = worst_outcome_per_check((str(row["check_id"]), str(row["result"])) for row in rows)

    return tuple(
        ReportCheck(
            check_id=check_id,
            title_ro=metadata[check_id].title_ro if check_id in metadata else check_id,
            title_en=metadata[check_id].title_en if check_id in metadata else check_id,
            outcome=outcome,
        )
        for check_id, outcome in sorted(worst.items())
    )


def worst_outcome_per_check(pairs: Iterable[tuple[str, str]]) -> dict[str, str]:
    """One outcome per check, worst first, from evaluations across every subject.

    Kept apart from the query because it is the part that decides something. A check that
    passes on the domain and fails on an accepted subdomain is a check the institution has
    to act on, and reporting the domain's row alone would describe a weakness that exists
    as one that does not. `unknown` outranks `pass` for the same reason: one subject we
    could not test is not evidence that the check is satisfied everywhere.
    """
    worst: dict[str, str] = {}
    for check_id, outcome in pairs:
        current = worst.get(check_id)
        if current is None or _rank(outcome) < _rank(current):
            worst[check_id] = outcome
    return worst


def _rank(outcome: str) -> int:
    """Position in the precedence order; anything unrecognised sorts last but is kept."""
    return (
        _OUTCOME_PRECEDENCE.index(outcome)
        if outcome in _OUTCOME_PRECEDENCE
        else len(_OUTCOME_PRECEDENCE)
    )


#: A citation the model wrote into its own sentence, as `[<uuid>]`.
#:
#: The instructions ask it to cite, and it complies by appending the identifier to the
#: prose. The identifiers are also carried structurally, and the report renders those --
#: so leaving both in printed a 36-character identifier twice in a row, once mid-sentence,
#: on a page written for somebody without a security team.
_INLINE_CITATION = re.compile(
    r"\s*\[[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\]"
)


def _without_inline_citations(sentence: str) -> str:
    """The sentence as a reader should see it.

    Only well-formed identifiers are removed. Anything else in brackets is the model's
    prose and stays: silently deleting text a model wrote is how a sentence ends up
    meaning something its author did not.
    """
    return _INLINE_CITATION.sub("", sentence).strip()


def _observations_by_id(connection: Connection, assessment_id: UUID) -> dict[str, Any]:
    """This run's observations, indexed by their own identifier.

    The model cites evidence by identifier, and an identifier printed on a page is not
    evidence -- it proves a link exists to whoever can query the database, and tells the
    reader nothing. This is what turns a citation back into something readable.
    """
    rows = connection.execute(
        text(
            """
            SELECT id, observation_type, subject_identifier, status, attributes
            FROM normalized_observations WHERE assessment_id = :assessment_id
            """
        ),
        {"assessment_id": assessment_id},
    ).mappings()
    return {str(row["id"]): row for row in rows}


def _resolve_evidence(cited: Any, observations: dict[str, Any]) -> tuple[ReportEvidence, ...]:
    """The observations a claim cited, in the order it cited them.

    An identifier that resolves to nothing is dropped rather than shown. It would mean
    the model cited evidence this run does not hold, which the grounding validator is
    meant to make impossible -- and a dangling reference on the page invites a reader to
    treat an unverifiable claim as a checked one.
    """
    if not isinstance(cited, list):
        return ()
    resolved: list[ReportEvidence] = []
    for identifier in cited:
        row = observations.get(str(identifier))
        if row is None:
            continue
        resolved.append(
            ReportEvidence(
                observation_type=str(row["observation_type"]),
                subject=str(row["subject_identifier"]),
                status=str(row["status"]),
                attributes=_evidence_rows(dict(row["attributes"] or {})),
            )
        )
    return tuple(resolved)


def _insights_for(connection: Connection, assessment_id: UUID) -> tuple[ReportInsight, ...]:
    """What the model said about this run, read back from the step that produced it.

    Returns nothing at all when the analysis did not run, was not configured, or failed.
    That is the ordinary case and not an error: the whole design rests on a report being
    complete without a model, so this is additive or it is absent.

    Everything here is model output and therefore untrusted text. It reaches the page
    through the element tree like any other string and is escaped on serialization.
    """
    row = (
        connection.execute(
            text(
                """
            SELECT result
            FROM assessment_steps
            WHERE assessment_id = :assessment_id AND name = 'agent_analysis'
            """
            ),
            {"assessment_id": assessment_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        return ()

    observations = _observations_by_id(connection, assessment_id)
    claims = (row["result"] or {}).get("claims")
    if not isinstance(claims, list):
        return ()

    insights: list[ReportInsight] = []
    for claim in claims:
        if not isinstance(claim, dict):
            continue
        sentence = _without_inline_citations(str(claim.get("text") or ""))
        if not sentence:
            continue
        insights.append(
            ReportInsight(
                text=sentence,
                kind=str(claim.get("kind") or ""),
                evidence=_resolve_evidence(claim.get("support"), observations),
            )
        )
    return tuple(insights)


def _caps_for(document: Any, methodology_version: str) -> tuple[ReportCap, ...]:
    """The ceilings this score hit, each with the justification the methodology carries.

    The snapshot records which cap applied and to what; the reason lives in the
    methodology, written when the cap was, in both languages. Joining them here means the
    report explains a capped score in the words somebody reviewed rather than in a phrase
    invented at render time.
    """
    applied = (document.get("overall") or {}).get("caps_applied") or []
    if not applied:
        return ()

    try:
        catalog = load_catalog(version=methodology_version)
    except Exception:  # noqa: BLE001 - a report must render without the catalogue
        return ()
    definitions = {cap.cap_id: cap for cap in catalog.methodology.caps}

    caps: list[ReportCap] = []
    for item in applied:
        if not isinstance(item, dict):
            continue
        definition = definitions.get(str(item.get("cap_id") or ""))
        caps.append(
            ReportCap(
                cap_id=str(item.get("cap_id") or ""),
                ceiling=float(item.get("ceiling") or 0.0),
                justification_ro=getattr(definition, "justification_ro", ""),
                justification_en=getattr(definition, "justification_en", ""),
                triggering_check_ids=tuple(
                    str(check) for check in item.get("triggering_check_ids") or []
                ),
            )
        )
    return tuple(caps)


def _asset_groups(connection: Connection, domain_id: UUID) -> tuple[ReportAssetGroup, ...]:
    """Discovered names for this domain, grouped by why we think they belong to it.

    Ordered by confidence, strongest first: the names an institution should look at are
    the ones the platform is most sure about, and a list that opens with sixty-two
    guesses teaches them to close it.
    """
    rows = connection.execute(
        text(
            """
            SELECT name, attribution_basis, attribution_confidence, shared_hosting
            FROM asset_candidates
            WHERE domain_id = :domain_id AND state <> 'rejected'
            ORDER BY attribution_confidence DESC, name
            """
        ),
        {"domain_id": domain_id},
    ).mappings()

    collected: dict[tuple[str, float], list[Any]] = {}
    for row in rows:
        key = (str(row["attribution_basis"]), float(row["attribution_confidence"]))
        collected.setdefault(key, []).append(row)

    groups: list[ReportAssetGroup] = []
    for (basis, confidence), items in sorted(collected.items(), key=lambda kv: -kv[0][1]):
        # Every name, not a page's worth. A count an institution cannot expand is not
        # disclosure, and the renderer -- not this -- decides how many meet the eye
        # first. Bounded upstream: `ct_log.MAX_CANDIDATES` admits at most 500 per run.
        groups.append(
            ReportAssetGroup(
                basis=basis,
                confidence=confidence,
                names=tuple(str(item["name"]) for item in items),
                shared_hosting=sum(1 for item in items if item["shared_hosting"]),
            )
        )
    return tuple(groups)


def build_report_document(
    connection: Connection,
    organization_name: str,
    domain_name: str,
    domain_id: UUID,
    assessment: Any,
    generated_at: datetime,
) -> ReportDocument:
    """Assemble what the report says from what is stored.

    Reads the snapshot document rather than recomputing anything. A report that
    recalculated the score could disagree with the score the organisation was shown, and
    the report is the version that gets forwarded.
    """
    snapshot = assessment["document"]
    coverage = snapshot.get("coverage", {})
    overall = snapshot.get("overall", {})
    metadata = load_check_metadata(str(assessment["methodology_version"]))
    remediation = load_remediation()

    observations = _observations_for(connection, assessment["assessment_id"])
    findings = tuple(
        _finding_document(row, metadata, remediation, observations)
        for row in _findings_for(connection, domain_id)
    )
    withheld = _withheld_checks(connection, assessment["assessment_id"])
    checks = _checks_for(connection, assessment["assessment_id"], metadata, domain_name)
    insights = _insights_for(connection, assessment["assessment_id"])

    return ReportDocument(
        organization_name=organization_name,
        domain=domain_name,
        score=overall.get("score"),
        band=overall.get("band"),
        coverage_percentage=float(coverage.get("percentage", 0.0)),
        coverage_sufficient=bool(coverage.get("sufficient", False)),
        methodology_version=str(assessment["methodology_version"]),
        policy_digest=str(assessment["policy_digest"]),
        assessment_mode=str(assessment["mode"]),
        observed_at=assessment["computed_at"],
        generated_at=generated_at,
        evidence_erased_at=assessment["evidence_erased_at"],
        pillars=tuple(
            ReportPillar(
                pillar=str(pillar["pillar"]),
                score=pillar.get("score"),
                weight=float(pillar.get("weight", 0.0)),
            )
            for pillar in snapshot.get("pillars", [])
        ),
        findings=findings,
        checks=checks,
        insights=insights,
        uncapped_score=overall.get("uncapped_score"),
        caps_applied=_caps_for(snapshot, str(assessment["methodology_version"])),
        asset_groups=_asset_groups(connection, domain_id),
        undetermined_checks=tuple(coverage.get("undetermined_checks", [])),
        withheld_checks=withheld,
    )


def build_report_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["reports"])

    @router.post(
        "/organizations/{organization_id}/domains/{domain_id}/reports",
        response_model=ReportGrantResponse,
        status_code=201,
    )
    def mint(
        organization_id: UUID,
        domain_id: UUID,
        request: Request,
        locale: str = "ro",
        document_format: str = "html",
        principal: Principal = Depends(current_principal),
    ) -> ReportGrantResponse:
        if locale not in LOCALES:
            raise AppError(422, "unsupported_locale", "The requested language is not available.")
        if document_format not in {"html", "pdf"}:
            raise AppError(422, "unsupported_format", "The requested format is not available.")
        if document_format == "pdf" and not renderer_available():
            # Named rather than a generic failure. "PDF is unavailable in this
            # deployment" is a sentence somebody can act on; a 500 is not.
            raise AppError(
                503,
                RENDERER_UNAVAILABLE,
                "This deployment cannot produce PDF. The HTML report is available.",
            )

        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            authorize(connection, request, principal, organization_id, Action.ASSESSMENT_READ)

            domain = connection.execute(
                text(
                    "SELECT registrable_domain FROM domains WHERE id = :domain_id "
                    "AND organization_id = :organization_id"
                ),
                {"domain_id": domain_id, "organization_id": organization_id},
            ).scalar_one_or_none()
            if domain is None:
                raise AppError(404, "not_found", "The requested resource was not found.")

            assessment = _latest_scored_assessment(connection, domain_id)
            if assessment is None:
                # Distinct from an empty report. A domain that has never been assessed
                # has no document to produce, and inventing an empty one would present
                # "nothing has been checked" as "nothing is wrong".
                raise AppError(
                    409,
                    "no_scored_assessment",
                    "This domain has no completed assessment to report on yet.",
                )

            token = secrets.token_urlsafe(TOKEN_BYTES)
            expires_at = datetime.now(UTC) + GRANT_LIFETIME
            connection.execute(
                text(
                    """
                    INSERT INTO report_grants (organization_id, domain_id, assessment_id,
                                               token_hash, locale, document_format,
                                               issued_to_user_id, expires_at)
                    VALUES (:organization_id, :domain_id, :assessment_id, :token_hash,
                            :locale, :document_format, :user_id, :expires_at)
                    """
                ),
                {
                    "organization_id": organization_id,
                    "domain_id": domain_id,
                    "assessment_id": assessment["assessment_id"],
                    "token_hash": _hash(token),
                    "locale": locale,
                    "document_format": document_format,
                    "user_id": principal.user_id,
                    "expires_at": expires_at,
                },
            )

        return ReportGrantResponse(
            download_path=f"/api/v1/reports/{token}",
            locale=locale,
            document_format=document_format,
            assessment_id=assessment["assessment_id"],
            expires_at=expires_at,
        )

    @router.get("/reports/{token}", response_class=Response)
    def download(
        token: str,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> Response:
        # Claimed by the hash of what was presented; the token itself is compared
        # against nothing, because nothing stored is the token.
        #
        # Which organization the grant belongs to is not known until it is claimed, and
        # row-level security needs that organization to be set before it will show the
        # row -- so the claim runs as a definer function on a connection carrying only
        # the caller's identity. The function checks the hash, the owner, the expiry and
        # the single use in one statement, so all four failures are one empty result and
        # two simultaneous requests cannot both succeed.
        with _database(request).user_connection(principal.user_id) as connection:
            grant = (
                connection.execute(
                    text(
                        "SELECT id, organization_id, domain_id, assessment_id, locale, "
                        "document_format FROM app_claim_report_grant(:token_hash)"
                    ),
                    {"token_hash": _hash(token)},
                )
                .mappings()
                .first()
            )

        if grant is None:
            raise AppError(404, "not_found", "The requested resource was not found.")

        organization_id = grant["organization_id"]
        with _database(request).tenant_connection(principal.user_id, organization_id) as connection:
            # Still authorized, even though the grant was minted under the same check.
            # Membership can be revoked between minting and downloading, and the grant
            # is a bound on when a document may be produced -- not a stored decision that
            # the person may still have it.
            authorize(connection, request, principal, organization_id, Action.ASSESSMENT_READ)

            names = (
                connection.execute(
                    text(
                        """
                    SELECT o.name AS organization_name, d.registrable_domain AS domain_name
                    FROM organizations o JOIN domains d ON d.organization_id = o.id
                    WHERE o.id = :organization_id AND d.id = :domain_id
                    """
                    ),
                    {"organization_id": organization_id, "domain_id": grant["domain_id"]},
                )
                .mappings()
                .one()
            )

            assessment = (
                connection.execute(
                    text(
                        """
                    SELECT a.id AS assessment_id, a.mode, s.methodology_version,
                           s.policy_digest, s.document, s.computed_at,
                           s.evidence_erased_at
                    FROM assessments a
                    JOIN score_snapshots s ON s.assessment_id = a.id
                    WHERE a.id = :assessment_id AND s.is_projection = false
                    ORDER BY s.computed_at DESC
                    LIMIT 1
                    """
                    ),
                    {"assessment_id": grant["assessment_id"]},
                )
                .mappings()
                .first()
            )
            if assessment is None:
                raise AppError(404, "not_found", "The requested resource was not found.")

            document = build_report_document(
                connection,
                str(names["organization_name"]),
                str(names["domain_name"]),
                grant["domain_id"],
                assessment,
                datetime.now(UTC),
            )

        html = render_report(document, str(grant["locale"]))
        wanted_pdf = str(grant["document_format"]) == "pdf"
        rendered = render_pdf(html) if wanted_pdf else None
        if wanted_pdf and rendered is None:
            # The renderer was available when the grant was minted and is not now.
            # Reported rather than silently downgraded to HTML: somebody expecting a
            # document to hand to an auditor should not receive a different thing under
            # the same name.
            raise AppError(
                503,
                RENDERER_UNAVAILABLE,
                "This deployment cannot produce PDF. Ask for the HTML report.",
            )

        suffix = "pdf" if wanted_pdf else "html"
        return Response(
            content=rendered if rendered is not None else html,
            media_type=("application/pdf" if wanted_pdf else "text/html; charset=utf-8"),
            headers={
                # `no-store` rather than `private`: a shared or corporate proxy is not
                # the only cache that matters, and a confidential document written to
                # disk by the browser outlives the session that fetched it.
                "Cache-Control": "no-store, no-cache, must-revalidate, private",
                "Pragma": "no-cache",
                # Downloaded rather than rendered in the origin, so nothing in the
                # document shares a context with the application.
                "Content-Disposition": (
                    f'attachment; filename="report-{_filename_part(names["domain_name"])}.{suffix}"'
                ),
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                # The document loads nothing, so the policy that describes it is the
                # empty one. Stated rather than assumed: if a stylesheet link were ever
                # added, this is what would stop it.
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
            },
        )

    return router
