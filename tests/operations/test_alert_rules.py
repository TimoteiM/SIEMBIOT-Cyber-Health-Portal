"""Alert rules, and whether they could ever fire.

An alert rule is a promise that somebody will be told. The way that promise fails
quietly is not a wrong threshold -- a wrong threshold fires too much or too little and
somebody notices. It fails when the rule refers to a metric the exporter does not
produce: the expression evaluates over nothing, no alert is ever raised, and the file
still reads like a monitored system.

`siembiot_network_operations` was in exactly that state. Described in the exporter,
referenced by a rule, and absent from every scrape because the query returns rows only
for tables with something in them -- so an empty table removed the series entirely.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services" / "api" / "src"))

from siembiot.metrics import HELP, PREFIX, Metric, render  # noqa: E402

ALERTS = ROOT / "infra" / "observability" / "alerts.yml"


def rules() -> list[dict[str, str]]:
    """The rules, read without a YAML parser.

    Nothing else in this repository parses YAML, and pulling in a dependency so that a
    test can read a file this repository also writes is a poor trade. The fields are
    read by name from each rule's block; the purpose here is to catch a rule that is
    missing one, not to validate the grammar.
    """
    blocks = ALERTS.read_text(encoding="utf-8").split("- alert:")[1:]
    parsed: list[dict[str, str]] = []
    for block in blocks:
        rule = {"alert": block.splitlines()[0].strip()}
        for field in ("expr", "for", "severity", "summary", "description"):
            found = re.search(rf"^\s*{field}:\s*(.*)$", block, re.M)
            if found:
                rule[field] = found.group(1).strip()
        parsed.append(rule)
    return parsed


def referenced_metrics() -> set[str]:
    expressions = " ".join(rule.get("expr", "") for rule in rules())
    return {name[len(PREFIX) :] for name in re.findall(rf"{PREFIX}[a-z_]+", expressions)}


def exported_with_an_empty_database() -> set[str]:
    """What a scrape returns when the platform has done nothing at all.

    The empty case is the one that matters: a metric present only once there is data is
    a metric that cannot alert on the absence of data.
    """
    body = render([], scrape_ok=True)
    return {name[len(PREFIX) :] for name in re.findall(rf"^{PREFIX}[a-z_]+", body, re.M)}


def test_every_alerted_metric_is_exported() -> None:
    missing = referenced_metrics() - set(HELP)

    assert not missing, (
        f"{sorted(missing)} are alerted on and not exported. The expression evaluates "
        "over nothing, so the rule can never fire and nothing will say so."
    )


def test_every_metric_exists_even_when_there_is_no_data() -> None:
    """The failure this file was written for.

    A series that appears only once a table has rows means "nothing has happened" and
    "the exporter is broken" look identical to whatever is watching.
    """
    exported = exported_with_an_empty_database()
    missing = set(HELP) - exported

    assert not missing, f"{sorted(missing)} vanish from a scrape when there is no data"


def test_a_zero_reads_as_zero_rather_than_as_silence() -> None:
    body = render([Metric("domains", [({"ownership_state": "verified"}, 2.0)])], scrape_ok=True)

    assert f"{PREFIX}network_operations 0" in body
    assert f'{PREFIX}domains{{ownership_state="verified"}} 2' in body


# -- the rules themselves -------------------------------------------------------------


def test_every_rule_says_what_to_do_about_it() -> None:
    """A page at three in the morning with no description is a rule that gets silenced
    rather than acted on."""
    for rule in rules():
        assert rule.get("summary"), rule["alert"]
        assert rule.get("description"), rule["alert"]


def test_every_rule_has_a_severity_that_routing_understands() -> None:
    """Alertmanager routes on this label. A rule with a severity nobody routes on is
    delivered nowhere, which is the same as not existing."""
    routed = {"page", "warning"}

    for rule in rules():
        severity = rule.get("severity")
        assert severity in routed, f"{rule['alert']} has severity {severity!r}"


def test_every_rule_waits_before_firing() -> None:
    """`for` is what separates an alert from a graph. Without it a single scrape during
    a restart pages somebody."""
    for rule in rules():
        assert rule.get("for"), f"{rule['alert']} fires on a single scrape"
