"""No check may resolve to `no_rule_matched`.

Four times now a check has been published whose rules did not cover a state its own
collector can produce. Each time the shape was identical: a rule tested the observation
*status* while the normalizer recorded a successful observation whose *attribute* carried
the absent meaning. The status test never fired, no attribute rule covered the false case,
and the check fell through -- reporting `unknown` for evidence that was not in doubt, and
charging the institution coverage for it.

    B.mta_sts_enforced      published in v1,   corrected in v1.2
    B.tls_rpt_present       published in v1,   corrected in v1.2
    C.http_redirects_https  published in v1,   corrected in v1.3
    A.caa_present           published in v1,   corrected in v1.3

The first three were found by reading the database after somebody asked a question. The
fourth was found by this test, before any domain hit it: a domain publishing only
malformed CAA records produces `observed` with `present: false`, which nothing matched.

The states are taken from the normalizer rather than written here. A list by hand goes
stale the week somebody adds a collector, which is how the first three arrived; and a
list invented by combining attributes freely reports states that cannot occur, which is
worse than useless because it trains people to edit the test. So each `builder.make` call
contributes the attribute names that branch emits, any value it pins to a literal stays
pinned, and only the genuinely variable ones vary.
"""

from __future__ import annotations

import ast
import sys
from datetime import UTC, datetime
from itertools import product
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services/worker/src"))

from siembiot_worker.policy.catalog import (  # noqa: E402
    CURRENT_METHODOLOGY_VERSION,
    Check,
    load_catalog,
)
from siembiot_worker.policy.evaluation import evaluate_check  # noqa: E402
from siembiot_worker.policy.evidence import (  # noqa: E402
    Confidence,
    NormalizedObservation,
    ObservationStatus,
    Subject,
    SubjectKind,
)

ORGANIZATION, ASSESSMENT = uuid4(), uuid4()
SUBJECT = Subject(kind=SubjectKind.DOMAIN, identifier="exemplu.test")
NOW = datetime(2026, 8, 18, tzinfo=UTC)
NORMALIZER = (
    Path(__file__).resolve().parents[2]
    / "services/worker/src/siembiot_worker/policy/normalization.py"
)


def _emitted_shapes() -> list[tuple[str, ObservationStatus, dict[str, object | None]]]:
    """Every (type, status, attributes) shape the normalizer can build.

    A value is `None` where the branch computes it and a literal where the branch pins
    it. `email.dkim` pins `any_selector_present` to `True` because that branch is only
    reached when at least one selector was found -- so a rule for the false case would be
    a rule for a state that cannot happen, and demanding one would be this test inventing
    work.
    """
    shapes: list[tuple[str, ObservationStatus, dict[str, object | None]]] = []
    tree = ast.parse(NORMALIZER.read_text(encoding="utf-8"))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "make"):
            continue
        if not node.args or not isinstance(node.args[0], ast.Constant):
            continue
        observation_type = node.args[0].value
        if not isinstance(observation_type, str):
            continue

        # `builder.make("dns.caa", _status_from_section(False, conclusive))` names no
        # status this can read. Defaulting those to `observed` invented a shape that
        # cannot exist -- an observed observation carrying no attributes at all -- and
        # the test reported it as a gap. A computed status is tried as the two it can
        # actually be when the branch passes no attributes.
        statuses = [ObservationStatus.OBSERVED]
        for argument in node.args[1:]:
            if isinstance(argument, ast.Attribute) and argument.attr in {
                "OBSERVED",
                "ABSENT",
                "INCONCLUSIVE",
                "NOT_APPLICABLE",
            }:
                statuses = [ObservationStatus(argument.attr.lower())]
                break
            if isinstance(argument, ast.Call):
                statuses = [ObservationStatus.ABSENT, ObservationStatus.INCONCLUSIVE]

        attributes: dict[str, object | None] = {}
        candidates = [a for a in node.args[1:] if isinstance(a, ast.Dict)]
        candidates += [
            branch
            for a in node.args[1:]
            if isinstance(a, ast.IfExp)
            for branch in (a.body, a.orelse)
            if isinstance(branch, ast.Dict)
        ]
        for literal in candidates:
            for key, value in zip(literal.keys, literal.values, strict=True):
                if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
                    continue
                attributes[key.value] = _kind_of(value)
        if not attributes and ObservationStatus.OBSERVED in statuses:
            continue
        shapes.extend((observation_type, status, attributes) for status in statuses)
    return shapes


def _kind_of(value: ast.expr) -> object | None:
    """What the normalizer will actually put in this attribute.

    Read from the expression rather than assumed, because guessing produces states no
    collector emits -- `present: 2` for a field the normalizer writes as `bool(...)` --
    and a test that fails on those is one somebody eventually deletes.

    A literal is pinned to itself. `bool(x)` and a comparison are booleans. `len(x)` is a
    count. Anything else is left for the catalogue to describe: the values that check's
    own rules compare against are real values by definition, and nothing else is.
    """
    if isinstance(value, ast.Constant):
        return value.value
    if isinstance(value, ast.Compare):
        return bool
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
        if value.func.id == "bool":
            return bool
        if value.func.id in {"len", "int"}:
            return int
    return None


def _variations(attributes: dict[str, object | None], check: Check) -> list[dict[str, object]]:
    """Each shape expanded over the values that could change which rule matches.

    Booleans take both. Counts take zero and either side of every threshold the check's
    rules test. Everything else takes exactly the literals those rules compare against --
    a value a rule names is a real value by definition, and one nobody names is a state
    this test would be inventing.
    """
    # `at_least` and `at_most` are floats in the catalogue -- `days_until_expiry` is a
    # count of days but nothing forces it to be whole.
    thresholds: set[float] = {0}
    literals: dict[str, set[object]] = {}
    for rule in check.rules:
        if rule.at_least is not None:
            thresholds.update({rule.at_least - 1, rule.at_least, rule.at_least + 1})
        if rule.at_most is not None:
            thresholds.update({rule.at_most, rule.at_most + 1})
        if rule.attribute is not None and isinstance(rule.equals, str):
            literals.setdefault(rule.attribute, set()).add(rule.equals)
    counts = sorted(value for value in thresholds if value >= 0)

    # An attribute reached through `.get(...)` tells this nothing about its type, but a
    # rule saying `at_least: 14` on it does: it is a number. Reading both sources is what
    # stops `days_until_expiry` being dropped and every certificate then looking like a
    # fall-through.
    numeric = {rule.attribute for rule in check.rules if rule.at_least is not None}
    numeric |= {rule.attribute for rule in check.rules if rule.at_most is not None}
    boolean = {rule.attribute for rule in check.rules if isinstance(rule.equals, bool)}

    # An attribute whose key the normalizer computes -- `f"{exposure}_open"` in a dict
    # comprehension -- cannot be read out of the source at all. The catalogue is the
    # second witness: a rule naming an attribute is evidence the collector emits it, so
    # anything the rules reference joins the shape even when the extraction missed it.
    named_by_rules = {rule.attribute for rule in check.rules if rule.attribute is not None}
    attributes = dict(attributes)
    for name in sorted(named_by_rules - set(attributes)):
        attributes[name] = None

    options: dict[str, list[object]] = {}
    for name, kind in attributes.items():
        if kind is not None and kind is not bool and kind is not int:
            options[name] = [kind]  # pinned by the branch; nothing else may override it
        elif kind is bool or name in boolean:
            options[name] = [True, False]
        elif kind is int or name in numeric:
            options[name] = list(counts)
        else:
            options[name] = sorted(literals.get(name, set()), key=repr) or [None]

    names = sorted(options)
    combinations = list(product(*(options[name] for name in names))) if names else [()]
    variations = [
        {
            name: value
            for name, value in zip(names, combo, strict=True)
            # An attribute the normalizer computes and no rule names cannot change the
            # outcome, so it is left out rather than given a value nobody would recognise.
            if value is not None
        }
        for combo in combinations
    ]
    if attributes and not any(variations):
        return []
    return variations


def test_no_check_falls_through_on_a_state_its_collector_can_produce() -> None:
    """The property the four corrections were each a symptom of missing."""
    catalog = load_catalog(version=CURRENT_METHODOLOGY_VERSION)
    by_type: dict[str, list[tuple[ObservationStatus, dict[str, object | None]]]] = {}
    for observation_type, status, attributes in _emitted_shapes():
        by_type.setdefault(observation_type, []).append((status, attributes))

    fell_through: set[str] = set()
    for check in catalog.checks:
        for status, attributes in by_type.get(check.observation_type, []):
            for variation in _variations(attributes, check):
                observation = NormalizedObservation(
                    observation_id=uuid4(),
                    organization_id=ORGANIZATION,
                    assessment_id=ASSESSMENT,
                    subject=SUBJECT,
                    observation_type=check.observation_type,
                    status=status,
                    # Only an observed observation may carry attributes; the model
                    # enforces that, and so does the database.
                    attributes=variation if status is ObservationStatus.OBSERVED else {},
                    confidence=Confidence(1.0, 1.0, 1.0),
                    collected_at=NOW,
                    observed_at=NOW,
                )
                evaluation = evaluate_check(
                    check,
                    observation,
                    catalog=catalog,
                    organization_id=ORGANIZATION,
                    assessment_id=ASSESSMENT,
                    subject=SUBJECT,
                    evaluated_at=NOW,
                )
                if evaluation.reason_code == "no_rule_matched":
                    shown = variation if status is ObservationStatus.OBSERVED else {}
                    fell_through.add(f"{check.check_id} on {status.value} with {shown}")

    assert not fell_through, (
        "these checks match no rule for a state their own normalizer can emit, and would "
        "report `unknown` while costing the institution coverage:\n  "
        + "\n  ".join(sorted(fell_through)[:20])
    )


def test_the_shapes_are_read_from_the_normalizer_and_not_empty() -> None:
    """A guard on the guard.

    If the extraction silently stopped finding anything -- a refactor, a renamed helper --
    the test above would pass by examining nothing at all, which is the failure mode it
    exists to prevent.
    """
    shapes = _emitted_shapes()
    types = {observation_type for observation_type, _, _ in shapes}
    assert len(types) >= 15, f"only {len(types)} observation types found in the normalizer"
    assert any(attributes for _, _, attributes in shapes), "no attribute shapes extracted"
