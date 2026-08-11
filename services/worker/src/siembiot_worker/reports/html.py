"""The assessment report, as one self-contained HTML file.

Self-contained deliberately: no stylesheet link, no font URL, no image host. A report is
opened from a downloads folder, forwarded, and read on a machine that may have no route
to this platform -- and a page that fetches anything tells whoever hosts that thing when
a confidential document was opened and by whom.

Every string that came from evidence goes through the element tree in `markup`, which
escapes on serialization. There is no path in this module that concatenates untrusted
text into markup.
"""

from __future__ import annotations

from datetime import datetime

from siembiot_worker.reports.document import ReportDocument, ReportFinding
from siembiot_worker.reports.markup import Element, Node, Raw, document, element

LOCALES = ("ro", "en")
DEFAULT_LOCALE = "ro"

#: Marked on the page itself, not only in the covering e-mail. A printed page separated
#: from the message that carried it should still say what it is.
_TEXT: dict[str, dict[str, str]] = {
    "ro": {
        "confidential": "CONFIDENȚIAL",
        "confidential_note": (
            "Acest raport descrie slăbiciuni ale unei instituții publice. Distribuie-l "
            "doar persoanelor care au nevoie de el pentru a le remedia."
        ),
        "title": "Raport de igienă cibernetică",
        "organization": "Instituție",
        "domain": "Domeniu",
        "generated": "Generat la",
        "observed": "Observat la",
        "score": "Scor",
        "band": "Nivel",
        "coverage": "Acoperire",
        "band_withheld": (
            "Nivelul nu este acordat: acoperirea este sub pragul metodologiei. Scorul "
            "rămâne, dar este calculat pe mai puține dovezi decât cere o concluzie."
        ),
        "pillars": "Pe domenii de evaluare",
        "no_pillar_score": "fără scor",
        "weight": "pondere",
        "findings": "Ce trebuie remediat",
        "no_findings": "Nu a fost identificată nicio slăbiciune în verificările efectuate.",
        "requirement_unmet": "Cerință neîndeplinită",
        "affects": "Se referă la",
        "why": "De ce contează",
        "what_to_do": "Ce este de făcut",
        "caveat": "Înainte să schimbi ceva",
        "draft_guidance": (
            "Această recomandare este în lucru și nu a fost încă revizuită. "
            "Verific-o înainte de a acționa."
        ),
        "undetermined": "Verificări neconcludente",
        "undetermined_note": ("Nu am putut stabili aceste lucruri. Nu înseamnă că sunt în regulă."),
        "withheld": "Verificări neefectuate",
        "withheld_note": (
            "Acestea necesită o autorizare pe care această evaluare nu a avut-o. "
            "Nu au fost încercate."
        ),
        "evidence_erased": (
            "Dovezile pe baza cărora a fost calculat acest scor au fost șterse la "
            "{when}, conform politicii de păstrare a datelor. Scorul rămâne ca "
            "înregistrare a ceea ce s-a constatat atunci, dar nu mai poate fi recalculat."
        ),
        "methodology": "Metodologie",
        "mode": "Mod de observare",
        "notice": (
            "O evaluare externă de igienă, bazată pe observație publică și "
            "neintruzivă. Nu este o garanție de securitate, un audit, o certificare "
            "sau o determinare de conformitate NIS2."
        ),
        "severity.critical": "critic",
        "severity.high": "ridicat",
        "severity.medium": "mediu",
        "severity.low": "scăzut",
        "severity.informational": "informativ",
    },
    "en": {
        "confidential": "CONFIDENTIAL",
        "confidential_note": (
            "This report describes weaknesses in a public institution. Share it only "
            "with the people who need it in order to fix them."
        ),
        "title": "Cyber hygiene report",
        "organization": "Institution",
        "domain": "Domain",
        "generated": "Generated",
        "observed": "Observed",
        "score": "Score",
        "band": "Band",
        "coverage": "Coverage",
        "band_withheld": (
            "No band is awarded: coverage is below the methodology's threshold. The "
            "score stands, but it rests on less evidence than a conclusion requires."
        ),
        "pillars": "By area",
        "no_pillar_score": "no score",
        "weight": "weight",
        "findings": "What needs fixing",
        "no_findings": "No weakness was identified in the checks that were performed.",
        "requirement_unmet": "Requirement not met",
        "affects": "Concerns",
        "why": "Why it matters",
        "what_to_do": "What to do",
        "caveat": "Before you change anything",
        "draft_guidance": (
            "This guidance is a draft and has not yet been reviewed. Check it before acting on it."
        ),
        "undetermined": "Inconclusive checks",
        "undetermined_note": ("We could not establish these. That does not mean they are fine."),
        "withheld": "Checks not performed",
        "withheld_note": (
            "These require an authorization this assessment did not hold. They were not attempted."
        ),
        "evidence_erased": (
            "The evidence this score was computed from was removed on {when} under the "
            "data retention policy. The score stands as a record of what was found at "
            "the time, but it can no longer be recomputed."
        ),
        "methodology": "Methodology",
        "mode": "Observation mode",
        "notice": (
            "An external hygiene assessment based on public, non-intrusive "
            "observation. Not a security guarantee, audit, certification, or NIS2 "
            "conformity determination."
        ),
        "severity.critical": "critical",
        "severity.high": "high",
        "severity.medium": "medium",
        "severity.low": "low",
        "severity.informational": "informational",
    },
}

#: Inline, because a linked stylesheet is a network request and this file has to render
#: identically from a downloads folder with no connectivity.
_STYLE = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; padding: 0 0 3rem; font: 15px/1.55 "Segoe UI", system-ui, sans-serif;
       color: #16202b; background: #fff; }
.sheet { max-width: 48rem; margin: 0 auto; padding: 0 1.5rem; }
.confidential { background: #7a1420; color: #fff; padding: 0.5rem 1.5rem;
                font-weight: 700; letter-spacing: 0.08em; }
.confidential p { margin: 0.35rem 0 0; font-weight: 400; letter-spacing: 0;
                  font-size: 0.85rem; }
h1 { font-size: 1.6rem; margin: 1.6rem 0 0.25rem; }
h2 { font-size: 1.15rem; margin: 2rem 0 0.6rem; border-bottom: 1px solid #d7dee6;
     padding-bottom: 0.3rem; }
h3 { font-size: 1rem; margin: 0 0 0.3rem; }
dl.facts { display: grid; grid-template-columns: max-content 1fr; gap: 0.2rem 1rem;
           margin: 0.8rem 0 0; }
dl.facts dt { color: #5a6673; }
dl.facts dd { margin: 0; }
.headline { display: flex; gap: 2rem; align-items: baseline; margin: 1.2rem 0 0; }
.headline .value { font-size: 2.4rem; font-weight: 700; }
.note { background: #f3f6f9; border-left: 3px solid #8a99a8; padding: 0.6rem 0.9rem;
        margin: 0.8rem 0; }
.caveat { background: #fdf4e7; border-left: 3px solid #b8791f; padding: 0.6rem 0.9rem;
          margin: 0.6rem 0; }
.draft { background: #fdf4e7; border-left: 3px solid #b8791f; padding: 0.4rem 0.9rem;
         margin: 0.6rem 0; font-size: 0.85rem; }
.finding { border: 1px solid #d7dee6; border-radius: 6px; padding: 0.9rem 1.1rem;
           margin: 0.8rem 0; page-break-inside: avoid; }
.severity { display: inline-block; font-size: 0.72rem; font-weight: 700;
            text-transform: uppercase; letter-spacing: 0.06em; padding: 0.1rem 0.5rem;
            border-radius: 999px; border: 1px solid currentColor; }
.severity-critical, .severity-high { color: #7a1420; }
.severity-medium { color: #8a5a12; }
.severity-low, .severity-informational { color: #4a5560; }
.muted { color: #5a6673; }
.unmet { margin: 0.5rem 0 0.1rem; font-size: 0.78rem; font-weight: 700;
         letter-spacing: 0.04em; text-transform: uppercase; color: #7a1420; }
.subject { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
           font-size: 0.9rem; }
table.pillars { width: 100%; border-collapse: collapse; margin-top: 0.6rem; }
table.pillars th, table.pillars td { text-align: left; padding: 0.35rem 0.5rem;
                                     border-bottom: 1px solid #e6ebf0; }
table.pillars td.number { text-align: right; font-variant-numeric: tabular-nums; }
footer { margin-top: 2.5rem; padding-top: 0.8rem; border-top: 1px solid #d7dee6;
         font-size: 0.82rem; color: #5a6673; }
code { font-family: ui-monospace, Consolas, monospace; font-size: 0.85em;
       word-break: break-all; }
@media print { .confidential { position: fixed; top: 0; left: 0; right: 0; }
               .sheet { padding-top: 4.5rem; } }
"""


def _text(locale: str, key: str) -> str:
    return _TEXT[locale][key]


def _pick(locale: str, romanian: str, english: str) -> str:
    return romanian if locale == "ro" else english


def _stamp(moment: datetime) -> str:
    """A fixed, unambiguous rendering.

    Not the reader's locale format: a report is forwarded, and "03/08/2026" means two
    different days depending on who opens it.
    """
    return moment.strftime("%Y-%m-%d %H:%M UTC")


def render_report(report: ReportDocument, locale: str = DEFAULT_LOCALE) -> str:
    if locale not in _TEXT:
        raise ValueError(f"unsupported report locale: {locale}")

    return document(
        element(
            "head",
            element("meta", charset="utf-8"),
            element("meta", name="viewport", content="width=device-width, initial-scale=1"),
            # No indexing, and no referrer if a link is ever followed out of the page.
            element("meta", name="robots", content="noindex, nofollow, noarchive"),
            element("meta", name="referrer", content="no-referrer"),
            element("title", f"{_text(locale, 'title')} — {report.domain}"),
            element("style", Raw(_STYLE)),
        ),
        element(
            "body",
            _confidential(locale),
            element(
                "div",
                _header(report, locale),
                _headline(report, locale),
                _pillars(report, locale),
                _findings(report, locale),
                _not_determined(report, locale),
                _footer(report, locale),
                class_="sheet",
            ),
        ),
        lang=locale,
    )


def _confidential(locale: str) -> Element:
    return element(
        "div",
        element("div", _text(locale, "confidential")),
        element("p", _text(locale, "confidential_note")),
        class_="confidential",
    )


def _header(report: ReportDocument, locale: str) -> Element:
    return element(
        "header",
        element("h1", _text(locale, "title")),
        element(
            "dl",
            element("dt", _text(locale, "organization")),
            element("dd", report.organization_name),
            element("dt", _text(locale, "domain")),
            element("dd", element("span", report.domain, class_="subject")),
            element("dt", _text(locale, "observed")),
            element("dd", _stamp(report.observed_at)),
            element("dt", _text(locale, "generated")),
            element("dd", _stamp(report.generated_at)),
            class_="facts",
        ),
    )


def _headline(report: ReportDocument, locale: str) -> Element:
    children: list[Node] = [
        element(
            "div",
            element("div", _text(locale, "score"), class_="muted"),
            element("div", "—" if report.score is None else f"{report.score:g}", class_="value"),
        ),
        element(
            "div",
            element("div", _text(locale, "coverage"), class_="muted"),
            element("div", f"{report.coverage_percentage:g}%", class_="value"),
        ),
    ]
    # The band is shown only where the methodology awards one. Below the coverage floor
    # the number stands and the band does not, so the report must not print a band-shaped
    # blank that a reader fills in themselves.
    if report.coverage_sufficient and report.band:
        children.insert(
            1,
            element(
                "div",
                element("div", _text(locale, "band"), class_="muted"),
                element("div", report.band, class_="value"),
            ),
        )

    blocks: list[Node] = [element("div", *children, class_="headline")]
    if not report.coverage_sufficient:
        blocks.append(element("p", _text(locale, "band_withheld"), class_="note"))
    if report.evidence_erased_at is not None:
        # Said beside the score rather than in the footer with the digests. A reader who
        # takes the number and stops reading should still have been told that the
        # workings behind it no longer exist.
        blocks.append(
            element(
                "p",
                _text(locale, "evidence_erased").replace(
                    "{when}", _stamp(report.evidence_erased_at)
                ),
                class_="caveat",
            )
        )
    for warning in report.warnings:
        blocks.append(element("p", warning, class_="note"))
    return element("section", *blocks)


def _pillars(report: ReportDocument, locale: str) -> Node:
    if not report.pillars:
        return element("div")
    rows = [
        element(
            "tr",
            element("td", pillar.pillar),
            element(
                "td",
                _text(locale, "no_pillar_score") if pillar.score is None else f"{pillar.score:g}",
                class_="number",
            ),
            element("td", f"{pillar.weight:g}", class_="number"),
        )
        for pillar in report.pillars
    ]
    return element(
        "section",
        element("h2", _text(locale, "pillars")),
        element(
            "table",
            element(
                "tr",
                element("th", _text(locale, "pillars")),
                element("th", _text(locale, "score")),
                element("th", _text(locale, "weight")),
            ),
            *rows,
            class_="pillars",
        ),
    )


def _findings(report: ReportDocument, locale: str) -> Element:
    ordered = report.findings_by_severity()
    if not ordered:
        return element(
            "section",
            element("h2", _text(locale, "findings")),
            element("p", _text(locale, "no_findings"), class_="note"),
        )
    return element(
        "section",
        element("h2", _text(locale, "findings")),
        *[_finding(finding, locale) for finding in ordered],
    )


def _finding(finding: ReportFinding, locale: str) -> Element:
    severity_label = _TEXT[locale].get(f"severity.{finding.severity}", finding.severity)
    blocks: list[Node] = [
        element(
            "span",
            severity_label,
            class_=f"severity severity-{finding.severity}",
        ),
        # The heading is the check's title, which states the condition that *should*
        # hold -- "SPF is published and valid". A finding is that condition failing, so
        # printing the title alone under "what needs fixing" reads as though the good
        # state were the problem. The label says which way round it is.
        element("p", _text(locale, "requirement_unmet"), class_="unmet"),
        element("h3", _pick(locale, finding.title_ro, finding.title_en)),
        element(
            "p",
            element("span", f"{_TEXT[locale]['affects']}: ", class_="muted"),
            element("span", finding.subject, class_="subject"),
        ),
        element("p", element("strong", _text(locale, "why")), " "),
        element("p", _pick(locale, finding.rationale_ro, finding.rationale_en)),
    ]

    summary = _pick(
        locale, finding.remediation_summary_ro or "", finding.remediation_summary_en or ""
    )
    steps = finding.remediation_steps_ro if locale == "ro" else finding.remediation_steps_en
    if summary or steps:
        blocks.append(element("p", element("strong", _text(locale, "what_to_do"))))
        if finding.remediation_review_status == "draft":
            blocks.append(element("p", _text(locale, "draft_guidance"), class_="draft"))
        if summary:
            blocks.append(element("p", summary))
        if steps:
            blocks.append(element("ol", *[element("li", step) for step in steps]))

    caveat = _pick(locale, finding.remediation_caveat_ro or "", finding.remediation_caveat_en or "")
    if caveat:
        blocks.append(
            element(
                "div",
                element("strong", _text(locale, "caveat")),
                element("p", caveat),
                class_="caveat",
            )
        )
    return element("article", *blocks, class_="finding")


def _not_determined(report: ReportDocument, locale: str) -> Element:
    sections: list[Node] = []
    for key, note, items in (
        ("undetermined", "undetermined_note", report.undetermined_checks),
        ("withheld", "withheld_note", report.withheld_checks),
    ):
        if not items:
            continue
        sections.extend(
            [
                element("h2", _text(locale, key)),
                element("p", _text(locale, note), class_="note"),
                element("ul", *[element("li", element("code", item)) for item in items]),
            ]
        )
    return element("section", *sections)


def _footer(report: ReportDocument, locale: str) -> Element:
    return element(
        "footer",
        element("p", _text(locale, "notice")),
        element(
            "dl",
            element("dt", _text(locale, "methodology")),
            element("dd", report.methodology_version),
            element("dt", "policy"),
            # Printed so a disputed report can be checked against the exact catalogue
            # that produced it. Without it "methodology 1.1.0" is a name, not a proof.
            element("dd", element("code", report.policy_digest)),
            element("dt", _text(locale, "mode")),
            element("dd", report.assessment_mode),
            class_="facts",
        ),
    )
