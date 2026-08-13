"""The two paths that collect evidence must agree on what passive means.

There are two: the workflow, which runs an enrolled organisation's assessment, and the
observatory pipeline, which observes public bodies. They share the normalizers, the
evaluator and the scorer -- but each keeps its own list of which collectors to run, and
that is where they can silently drift apart.

Drift here is quiet in the worst way. A passive check the observatory never collects for
does not error and does not reduce coverage: it resolves to `not_applicable` for every
public body forever, which on the page is indistinguishable from a check that ran and
found nothing wrong. Mail transport was added to the workflow and missing here, and
that is exactly what it did.

So this asserts the two lists agree, rather than asserting either one is right.
"""

from __future__ import annotations

import inspect

from siembiot_worker.observation import pipeline
from siembiot_worker.observation.mode import PASSIVE_OPERATION_CLASSES
from siembiot_worker.workflows.handlers import COLLECTOR_OPERATIONS


def _observatory_collector_names() -> set[str]:
    """The keys the pipeline puts in its results dictionary.

    Read from the source rather than by running it, because running it would mean live
    network calls to whichever domain the test picked -- and a test that needs the
    internet to be up is a test that gets deleted the first week it is flaky.
    """
    source = inspect.getsource(pipeline._collect)
    return {
        line.split('results["')[1].split('"]')[0]
        for line in source.splitlines()
        if 'results["' in line and "] =" in line
    }


def test_the_observatory_runs_every_passive_collector_the_workflow_does() -> None:
    passive = {
        name
        for name, operation in COLLECTOR_OPERATIONS.items()
        if operation in PASSIVE_OPERATION_CLASSES
    }
    missing = passive - _observatory_collector_names()

    assert not missing, (
        f"the observatory pipeline does not collect {sorted(missing)}, so every check "
        "reading them resolves to not_applicable for every public body -- which reads "
        "as a clean result rather than as evidence nobody gathered"
    )


def test_the_observatory_runs_nothing_that_requires_authorization() -> None:
    """The other direction, and the one that actually matters for consent.

    The broker would refuse an authorized-only operation in passive mode anyway, but a
    refusal recorded against a public body nobody asked reads as an attempt that was
    blocked rather than one that was never made -- and it would be an attempt.
    """
    authorized_only = {
        name
        for name, operation in COLLECTOR_OPERATIONS.items()
        if operation not in PASSIVE_OPERATION_CLASSES
    }

    assert authorized_only, "the split is meaningless if nothing is authorized-only"
    assert not (authorized_only & _observatory_collector_names())


def test_every_collected_result_is_normalized() -> None:
    """Collecting without normalizing is evidence gathered and thrown away: the network
    cost is paid, the target is touched, and the report is identical to never having
    looked."""
    collected = _observatory_collector_names()
    normalized_source = inspect.getsource(pipeline._normalize)
    unread = {name for name in collected if f'collection["{name}"]' not in normalized_source}

    assert not unread, f"collected but never normalized: {sorted(unread)}"


def test_every_declared_collector_has_a_step_that_runs_it() -> None:
    """A collector nobody scheduled is a collector that never runs.

    `COLLECTOR_OPERATIONS` says which collectors exist and what each is allowed to do;
    the graph says which ones the workflow actually executes. Nothing connected the two,
    so a collector could be written, registered, given an operation class, covered by its
    own unit tests -- and never once be reached by an assessment.

    That failure is silent in the specific way this codebase keeps finding. The checks
    reading its evidence resolve to `not_applicable` rather than erroring, which on a
    report is indistinguishable from a check that ran and found nothing to say. It is the
    same shape as the observatory drift the tests above were written for, one layer down.

    True by inspection when this was written; nothing enforced it.
    """
    from siembiot_worker.workflows.graph import COLLECTION_STEPS, DEPENDENT_COLLECTION_STEPS

    scheduled = {step.name for step in (*COLLECTION_STEPS, *DEPENDENT_COLLECTION_STEPS)}
    declared = {f"collect.{name}" for name in COLLECTOR_OPERATIONS}

    assert declared, "no collectors are declared; this test is checking nothing"
    assert not (declared - scheduled), (
        f"{sorted(declared - scheduled)} are declared collectors with no step in the "
        "graph, so an assessment never runs them and every check reading their evidence "
        "reports not_applicable rather than missing"
    )


def test_every_collection_step_has_a_collector_behind_it() -> None:
    """The other direction. A step with no collector fails at dispatch rather than
    silently, so it is the less dangerous of the two -- but it fails on a real
    assessment against somebody's domain, which is a poor place to find out."""
    from siembiot_worker.workflows.graph import COLLECTION_STEPS, DEPENDENT_COLLECTION_STEPS

    scheduled = {step.name for step in (*COLLECTION_STEPS, *DEPENDENT_COLLECTION_STEPS)}
    declared = {f"collect.{name}" for name in COLLECTOR_OPERATIONS}

    assert not (scheduled - declared), (
        f"{sorted(scheduled - declared)} are scheduled and have no collector"
    )
