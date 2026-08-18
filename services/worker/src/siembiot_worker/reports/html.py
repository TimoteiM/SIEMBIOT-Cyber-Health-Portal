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

from siembiot_worker.reports.document import SEVERITY_ORDER, ReportDocument, ReportFinding
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
        "impact": "Cât de afectată este instituția",
        "impact_none": "Nicio slăbiciune identificată în verificările efectuate.",
        "impact_lead": (
            "Fiecare slăbiciune de mai jos este o cale prin care cineva ar putea "
            "ajunge la instituție. Cele critice și ridicate se remediază primele."
        ),
        "scale_worst": "Critic",
        "scale_best": "Rezilient",
        "score_of_100": "din 100",
        "coverage_explained": (
            "Am putut verifica {coverage}% din ceea ce măsoară metodologia. Restul a "
            "rămas neconcludent, deci scorul se sprijină pe mai puține dovezi."
        ),
        "coverage_explained_full": (
            "Am putut verifica {coverage}% din ceea ce măsoară metodologia."
        ),
        "legend": "Cum se citesc culorile",
        "legend_direction": "100 este cel mai bun rezultat, 0 cel mai slab.",
        "importance": "importanță",
        "importance_high": "ridicată",
        "importance_medium": "medie",
        "importance_low": "scăzută",
        "no_pillar_score_why": "niciun furnizor de reputație nu este configurat",
        "no_pillar_score_generic": "nu au existat verificări concludente în această zonă",
        "band.resilient": "Rezilient",
        "band.managed": "Gestionat",
        "band.developing": "În dezvoltare",
        "band.exposed": "Expus",
        "band.critical": "Critic",
        "pillar.dns": "DNS",
        "pillar.email": "E-mail",
        "pillar.web_tls": "Web și TLS",
        "pillar.attack_surface": "Suprafață de atac",
        "pillar.reputation": "Reputație",
        "pillar.exposure_hygiene": "Igiena expunerii",
        "findings": "Ce trebuie remediat",
        "no_findings": "Nu a fost identificată nicio slăbiciune în verificările efectuate.",
        "requirement_unmet": "Cerință neîndeplinită",
        "affects": "Se referă la",
        "why": "De ce contează",
        "evidence_heading": "Ce am observat",
        "evidence_note": (
            "Datele pe care se sprijină această constatare, exact cum au fost colectate."
        ),
        "obs.observed": "măsurat",
        "obs.absent": "lipsește",
        "obs.inconclusive": "neconcludent",
        "obs.not_applicable": "nu se aplică",
        "value_true": "da",
        "value_false": "nu",
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
        "impact": "How exposed this institution is",
        "impact_none": "No weakness was identified in the checks that were performed.",
        "impact_lead": (
            "Each weakness below is a way somebody could reach this institution. "
            "Critical and high ones are fixed first."
        ),
        "scale_worst": "Critical",
        "scale_best": "Resilient",
        "score_of_100": "out of 100",
        "coverage_explained": (
            "We could check {coverage}% of what the methodology measures. The rest was "
            "inconclusive, so the score rests on less evidence."
        ),
        "coverage_explained_full": "We could check {coverage}% of what the methodology measures.",
        "legend": "How to read the colours",
        "legend_direction": "100 is the best result, 0 the worst.",
        "importance": "importance",
        "importance_high": "high",
        "importance_medium": "medium",
        "importance_low": "low",
        "no_pillar_score_why": "no reputation provider is configured",
        "no_pillar_score_generic": "no conclusive checks in this area",
        "band.resilient": "Resilient",
        "band.managed": "Managed",
        "band.developing": "Developing",
        "band.exposed": "Exposed",
        "band.critical": "Critical",
        "pillar.dns": "DNS",
        "pillar.email": "E-mail",
        "pillar.web_tls": "Web and TLS",
        "pillar.attack_surface": "Attack surface",
        "pillar.reputation": "Reputation",
        "pillar.exposure_hygiene": "Exposure hygiene",
        "findings": "What needs fixing",
        "no_findings": "No weakness was identified in the checks that were performed.",
        "requirement_unmet": "Requirement not met",
        "affects": "Concerns",
        "why": "Why it matters",
        "evidence_heading": "What we observed",
        "evidence_note": "The evidence this finding rests on, exactly as it was collected.",
        "obs.observed": "measured",
        "obs.absent": "not present",
        "obs.inconclusive": "inconclusive",
        "obs.not_applicable": "not applicable",
        "value_true": "yes",
        "value_false": "no",
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
table.pillars th, table.pillars td { text-align: left; padding: 0.4rem 0.5rem;
                                     border-bottom: 1px solid #e6ebf0;
                                     vertical-align: middle; }
table.pillars td.number { text-align: right; font-variant-numeric: tabular-nums;
                          font-weight: 700; width: 3.4rem; }
table.pillars td.name { width: 11rem; }
table.pillars td.importance { width: 7rem; font-size: 0.8rem; color: #5a6673; }

/* Bars are a filled div inside a track, not a chart library and not an image.
   WeasyPrint runs no JavaScript and this report embeds nothing, so a percentage
   width is the whole mechanism -- it renders identically in a browser and in the
   PDF, and it degrades to a readable number if styles are stripped entirely. */
.track { background: #e9eef3; border-radius: 3px; height: 0.62rem; width: 100%; }
.fill { height: 0.62rem; border-radius: 3px; }
.fill-resilient { background: #1d7a4c; }
.fill-managed { background: #4a9e3f; }
.fill-developing { background: #c08a1e; }
.fill-exposed { background: #c2601c; }
.fill-critical { background: #a3202f; }
.fill-none { background: #c8d2db; }

.headline { margin: 1.1rem 0 0.4rem; }
.headline .value { font-size: 3rem; font-weight: 800; line-height: 1;
                   font-variant-numeric: tabular-nums; }
.headline .of { font-size: 0.95rem; color: #5a6673; margin-left: 0.35rem; }
.headline .bandname { font-size: 1.5rem; font-weight: 700; margin-left: 1.2rem; }
.scale { margin-top: 0.7rem; }
.scale .ends { font-size: 0.75rem; color: #5a6673; margin-top: 0.2rem; }
.scale .ends .right { float: right; }

/* One chip per severity, carrying its own count. Colour is never the only signal:
   the number and the word are both present, which is what keeps this readable in
   greyscale and to a screen reader. */
.impact { margin-top: 0.5rem; }
.chip { display: inline-block; border: 1px solid currentColor; border-radius: 6px;
        padding: 0.3rem 0.7rem; margin: 0 0.4rem 0.4rem 0; font-size: 0.85rem; }
.chip .count { font-weight: 800; font-size: 1.15rem; margin-right: 0.35rem;
               font-variant-numeric: tabular-nums; }
.chip-critical, .chip-high { color: #7a1420; }
.chip-medium { color: #8a5a12; }
.chip-low, .chip-informational { color: #4a5560; }
.lead { color: #3d4854; margin: 0.5rem 0 0; }

table.evidence { border-collapse: collapse; margin: 0.3rem 0 0.6rem; font-size: 0.86rem; }
table.evidence td { padding: 0.22rem 0.7rem 0.22rem 0; vertical-align: top;
                    border-bottom: 1px solid #eef2f6; }
table.evidence td.ename { color: #5a6673; font-family: ui-monospace, Consolas, monospace;
                          font-size: 0.82rem; white-space: nowrap; }
.obs-status { font-weight: 700; }

.legend { margin: 0.5rem 0 0.2rem; font-size: 0.78rem; color: #5a6673; }
.legend-title { font-weight: 700; }
.legend .keys { margin-top: 0.3rem; }
.legend .key { display: inline-block; margin: 0 0.9rem 0.25rem 0; white-space: nowrap; }
.swatch { display: inline-block; width: 0.7rem; height: 0.7rem; border-radius: 2px;
          margin-right: 0.3rem; vertical-align: -0.05rem; }
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
                # Before the areas, because it answers the question people open the
                # report with. A pillar score of 25 does not tell somebody whether to
                # worry this week; "two critical, four high" does.
                _impact(report, locale),
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


#: Where each band starts, worst first. Mirrors `bands` in the methodology, and
#: `test_report_band_labels_match_the_methodology` fails if the two drift -- the labels
#: exist in the catalogue and a report that prints `developing` to a Romanian reader is
#: not using them.
_BAND_FLOORS: tuple[tuple[str, float], ...] = (
    ("critical", 0.0),
    ("exposed", 30.0),
    ("developing", 55.0),
    ("managed", 75.0),
    ("resilient", 90.0),
)

#: Weight above which an area is called out as carrying more of the score. Read from
#: the pillar's own weight rather than hardcoded per area, so re-weighting the
#: methodology moves the wording with it.
_IMPORTANCE_HIGH = 0.2
_IMPORTANCE_MEDIUM = 0.13


def _band_for(score: float | None) -> str:
    """The band a score falls in, for colouring only.

    Not for awarding one: whether a band is *awarded* depends on coverage and is decided
    by the scorer, not here. This colours a bar, and a bar with no colour rule would be
    decoration.
    """
    if score is None:
        return "none"
    band = "critical"
    for name, floor in _BAND_FLOORS:
        if score >= floor:
            band = name
    return band


def _band_label(locale: str, band: str) -> str:
    return _TEXT[locale].get(f"band.{band}", band)


def _pillar_label(locale: str, pillar: str) -> str:
    """The area's name in the reader's language, falling back to the identifier.

    The fallback is deliberate and visible: an area added to the methodology and not
    translated shows up as `exposure_hygiene` in the report, which is ugly enough that
    somebody fixes it. Silently omitting the row would hide a whole area of the score.
    """
    return _TEXT[locale].get(f"pillar.{pillar}", pillar)


def _importance(locale: str, weight: float) -> str:
    if weight >= _IMPORTANCE_HIGH:
        return _text(locale, "importance_high")
    if weight >= _IMPORTANCE_MEDIUM:
        return _text(locale, "importance_medium")
    return _text(locale, "importance_low")


#: The narrowest a bar may render while still being a bar.
#:
#: A score of zero is a *result*: every check in that area failed. Drawn at its true
#: width it is an empty track, which on the page is indistinguishable from the area that
#: has no score at all -- so the worst possible outcome looked like a missing one. E-mail
#: scoring 0 on a real report is what made that visible.
#:
#: The sliver is deliberately too small to misread as a quantity. It says "measured, and
#: it is the bottom", and the number beside it says the rest.
_MINIMUM_VISIBLE_WIDTH = 1.5


def _bar(percent: float, band: str) -> Node:
    """A filled track.

    Clamped at both ends: above, because a bar wider than its track is a layout bug that
    reads as a better result; below, because zero drawn as nothing reads as no result at
    all.
    """
    width = max(0.0, min(100.0, percent))
    if width < _MINIMUM_VISIBLE_WIDTH:
        width = _MINIMUM_VISIBLE_WIDTH
    return element(
        "div",
        element("div", "", class_=f"fill fill-{band}", style=f"width: {width:g}%"),
        class_="track",
    )


def _legend(locale: str) -> Node:
    """What the colours mean, beside the bars that use them.

    Added because a reader looking at a coloured bar and a number has no way to know
    which direction is good. The bands and their boundaries come from `_BAND_FLOORS`, so
    a methodology that re-cuts them moves the legend with it rather than leaving a
    caption that describes the previous scale.
    """
    swatches: list[Node] = []
    for index, (band, floor) in enumerate(_BAND_FLOORS):
        ceiling = 100.0 if index + 1 == len(_BAND_FLOORS) else _BAND_FLOORS[index + 1][1] - 1.0
        swatches.append(
            element(
                "span",
                element("span", "", class_=f"swatch fill-{band}"),
                f"{_band_label(locale, band)} {floor:g}\u2013{ceiling:g}",
                class_="key",
            )
        )
    return element(
        "div",
        element(
            "span",
            f"{_text(locale, 'legend')} \u2014 {_text(locale, 'legend_direction')}",
            class_="legend-title",
        ),
        element("div", *swatches, class_="keys"),
        class_="legend",
    )


def _impact(report: ReportDocument, locale: str) -> Node:
    """How exposed the institution is, in the one form every reader understands: how
    many, and how bad.

    Placed before the areas because it answers the question people actually open the
    report with. A pillar score of 25 does not tell somebody whether to worry this week;
    two critical findings does.
    """
    counts: dict[str, int] = {}
    for finding in report.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    if not counts:
        return element(
            "section",
            element("h2", _text(locale, "impact")),
            element("p", _text(locale, "impact_none")),
        )

    chips = [
        element(
            "span",
            element("span", str(counts[severity]), class_="count"),
            _text(locale, f"severity.{severity}"),
            class_=f"chip chip-{severity}",
        )
        for severity in SEVERITY_ORDER
        if counts.get(severity)
    ]
    return element(
        "section",
        element("h2", _text(locale, "impact")),
        element("div", *chips, class_="impact"),
        element("p", _text(locale, "impact_lead"), class_="lead"),
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
                # The methodology carries `label_ro` and `label_en` for every band and
                # this printed the raw identifier, so a Romanian institution read
                # "developing" in an otherwise Romanian document.
                element("div", _band_label(locale, report.band), class_="value"),
            ),
        )

    blocks: list[Node] = [element("div", *children, class_="headline")]

    # Where the score sits on the whole scale, with both ends named. A number alone
    # leaves the reader to guess whether 55.6 is nearly good or nearly bad.
    if report.score is not None:
        blocks.append(
            element(
                "div",
                _bar(report.score, _band_for(report.score)),
                element(
                    "div",
                    element("span", _text(locale, "scale_worst")),
                    element("span", _text(locale, "scale_best"), class_="right"),
                    class_="ends",
                ),
                class_="scale",
            )
        )

    # Coverage in a sentence. "65.5%" is a fact about the assessment that reads, to
    # somebody who did not write the methodology, like a fact about the institution.
    coverage_key = "coverage_explained_full" if report.coverage_sufficient else "coverage_explained"
    blocks.append(
        element(
            "p",
            _text(locale, coverage_key).replace("{coverage}", f"{report.coverage_percentage:g}"),
            class_="lead",
        )
    )
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
    """Each area as a bar, named in the reader's language.

    The previous version printed the identifier and the raw weight -- `attack_surface`
    and `0.15` -- which are the two facts in the whole report that mean nothing to the
    person receiving it. The weight is a methodology parameter; what a reader needs is
    whether this area matters more than the next one.

    An area with no score keeps its row and says why. Dropping it would leave a report
    that silently covers five areas out of six, and a reader counting rows would have no
    way to know.
    """
    if not report.pillars:
        return element("div")

    rows = []
    for pillar in report.pillars:
        if pillar.score is None:
            reason = (
                _text(locale, "no_pillar_score_why")
                if pillar.pillar == "reputation"
                else _text(locale, "no_pillar_score_generic")
            )
            measure: Node = element(
                "span", f"{_text(locale, 'no_pillar_score')} — {reason}", class_="muted"
            )
            number: Node = element("span", "—", class_="muted")
        else:
            measure = _bar(pillar.score, _band_for(pillar.score))
            number = f"{pillar.score:g}"

        rows.append(
            element(
                "tr",
                element("td", _pillar_label(locale, pillar.pillar), class_="name"),
                element("td", measure),
                element("td", number, class_="number"),
                element(
                    "td",
                    f"{_text(locale, 'importance')} {_importance(locale, pillar.weight)}",
                    class_="importance",
                ),
            )
        )

    return element(
        "section",
        element("h2", _text(locale, "pillars")),
        _legend(locale),
        element("table", *rows, class_="pillars"),
    )


def _evidence(finding: ReportFinding, locale: str) -> list[Node]:
    """What the collectors saw, beside what the report says to change.

    Added because the report told an institution what to fix and never showed what was
    found. "Publish DMARC" is an instruction; "no DMARC record was returned for this
    domain" is the reason, and a public body being asked to change its DNS is entitled to
    the second before it acts on the first.

    The status is shown even when there are no attributes, because `absent` and
    `inconclusive` are the whole content in that case: we looked and it was not there, or
    we could not look. A reader acts differently on each.

    Values pass through the element tree like every other string here, so a header or a
    mail server banner containing markup is escaped on serialization rather than by
    anything in this function remembering to.
    """
    if finding.evidence_status is None:
        return []

    status = _TEXT[locale].get(f"obs.{finding.evidence_status}", finding.evidence_status)
    rows = [
        element(
            "tr",
            element("td", name, class_="ename"),
            element(
                "td",
                _text(locale, "value_true")
                if value == "true"
                else _text(locale, "value_false")
                if value == "false"
                else value,
            ),
        )
        for name, value in finding.evidence
    ]

    blocks: list[Node] = [
        element("p", element("strong", _text(locale, "evidence_heading"))),
        element(
            "p",
            element("span", f"{_text(locale, 'evidence_heading')}: ", class_="muted"),
            element("span", status, class_="obs-status"),
        ),
    ]
    if rows:
        blocks.append(element("table", *rows, class_="evidence"))
    return blocks


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

    # Before the remediation, deliberately. The evidence is why the instruction follows,
    # and an instruction read before its reason is one somebody applies without checking
    # whether it matches what their own infrastructure actually does.
    blocks.extend(_evidence(finding, locale))

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
