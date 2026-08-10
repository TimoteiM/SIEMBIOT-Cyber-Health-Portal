"""What may and may not change when the methodology gains checks.

A stored score names the version and digest that produced it. If loading that version
ever yields a different catalogue, every score computed under it silently stops being
reproducible -- and nothing fails, because a digest nobody recomputes is a digest nobody
notices. So the rule this file enforces is narrow and absolute: a published version loads
exactly the documents it was published with, forever.
"""

from __future__ import annotations

from siembiot_worker.observation.mode import AssessmentMode, is_check_available
from siembiot_worker.policy.catalog import CURRENT_METHODOLOGY_VERSION, load_catalog

#: The digest methodology 1.0.0 was published with, written down rather than computed.
#: Computing it from the catalogue would make this test agree with any change to the
#: catalogue, which is precisely what it exists to refuse.
PUBLISHED_1_0_0_DIGEST = "86421e35d811eee278f75a44c415370d8f3a853de8a0106fc6342726a90f4acf"


def test_a_published_methodology_never_changes() -> None:
    """1.1.0 adds three checks by naming an additional directory rather than editing the
    existing one, so 1.0.0 loads what it always did."""
    catalog = load_catalog(version="1.0.0")
    assert catalog.digest == PUBLISHED_1_0_0_DIGEST
    assert len(catalog.checks) == 22


def test_the_new_version_adds_checks_and_nothing_else() -> None:
    older = load_catalog(version="1.0.0")
    newer = load_catalog(version="1.1.0")

    added = {check.check_id for check in newer.checks} - {check.check_id for check in older.checks}
    assert added == {
        "D.remote_access_exposed",
        "D.database_exposed",
        "D.management_interface_exposed",
    }
    # Every check that existed before is unchanged, not merely still present. A reworded
    # rationale or a shifted weight would change what a domain scores for reasons nobody
    # reading the version number would expect.
    by_id = {check.check_id: check for check in newer.checks}
    for check in older.checks:
        assert by_id[check.check_id] == check, check.check_id


def test_pillar_weights_are_untouched() -> None:
    """Moving the balance between pillars silently reprices every domain assessed.

    The new checks sit inside attack_surface and change its internal weighting, which is
    what adding a check to a pillar means. The pillar's share of the score is the same.
    """
    assert (
        load_catalog(version="1.1.0").methodology.pillar_weights
        == load_catalog(version="1.0.0").methodology.pillar_weights
    )


def test_the_new_checks_are_authorized_only() -> None:
    """A passive run cannot open a connection to a port nobody advertised, so it must not
    be scored as though it looked."""
    catalog = load_catalog(version="1.1.0")
    added = [
        check
        for check in catalog.checks
        if check.check_id
        in {"D.remote_access_exposed", "D.database_exposed", "D.management_interface_exposed"}
    ]
    assert added
    for check in added:
        assert not is_check_available(check, AssessmentMode.PASSIVE_OBSERVATION)
        assert is_check_available(check, AssessmentMode.AUTHORIZED_ASSESSMENT)


def test_the_new_checks_are_never_publishable() -> None:
    """A public page listing which institutions have remote desktop open would be a
    target list, not a transparency measure."""
    catalog = load_catalog(version="1.1.0")
    for check in catalog.checks:
        if check.check_id.startswith("D.") and check.collection_mode == "authorized":
            assert check.public_safety_class.value == "private_only", check.check_id


def test_the_current_version_is_the_one_that_was_published() -> None:
    """The default a new assessment runs under, checked against the file that exists."""
    catalog = load_catalog()
    assert catalog.methodology.version == CURRENT_METHODOLOGY_VERSION == "1.1.0"
