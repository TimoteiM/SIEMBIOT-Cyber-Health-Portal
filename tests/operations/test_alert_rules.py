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
from typing import Any

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
            found = re.search(rf"^(\s*){field}:\s*(.*)$", block, re.M)
            if not found:
                continue
            value = found.group(2).strip()
            if value in {">-", "|", ">"}:
                # A folded scalar: the value is the indented block beneath it. Read
                # rather than skipped, because `expr` is written this way when it is
                # long -- and the long expressions are the ones worth checking.
                value = _folded(block[found.end() :], len(found.group(1)))
            rule[field] = value
        parsed.append(rule)
    return parsed


def _folded(remainder: str, parent_indent: int) -> str:
    """The indented continuation lines of a YAML folded scalar, joined."""
    lines: list[str] = []
    for line in remainder.splitlines()[1:]:
        if line.strip() and (len(line) - len(line.lstrip())) <= parent_indent:
            break
        lines.append(line.strip())
    return " ".join(part for part in lines if part)


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


# -- the configuration that has to agree with the rules --------------------------------

PROMETHEUS = ROOT / "infra" / "observability" / "prometheus.yml"
ALERTMANAGER = ROOT / "infra" / "observability" / "alertmanager.yml"


def test_the_job_name_matches_what_the_rules_match_on() -> None:
    """`ApiDown` matches `up{job="siembiot-api"}`, and that label comes from the scrape
    configuration. Renaming the job stops the rule working and changes nothing visible:
    the rule stays in the file, the target stays up, and the alert simply never fires."""
    scrape = PROMETHEUS.read_text(encoding="utf-8")
    jobs = set(re.findall(r"job_name:\s*(\S+)", scrape))

    for rule in rules():
        for job in re.findall(r'job="([^"]+)"', rule.get("expr", "")):
            assert job in jobs, f"{rule['alert']} matches job {job!r}, which nothing scrapes"


def test_every_severity_the_rules_use_is_routed() -> None:
    """A severity Alertmanager has no route for falls through to the default receiver,
    which is survivable, or to none, which is not. Either way the label stops meaning
    what the rule author intended."""
    routing = ALERTMANAGER.read_text(encoding="utf-8")
    routed = set(re.findall(r'severity\s*=\s*"([^"]+)"', routing))

    used = {rule["severity"] for rule in rules() if "severity" in rule}
    assert used <= routed, f"{sorted(used - routed)} is used by a rule and routed nowhere"


def test_the_rules_file_prometheus_loads_is_the_one_that_is_tested() -> None:
    """A second copy of the rules would let this file pass while the deployed stack ran
    something else."""
    assert "alerts.yml" in PROMETHEUS.read_text(encoding="utf-8")
    assert ALERTS.exists()


# -- the dashboard and the rules have to agree ------------------------------------------

DASHBOARD = ROOT / "infra" / "observability" / "dashboard.json"


def panels() -> list[dict[str, Any]]:
    import json

    document: dict[str, Any] = json.loads(DASHBOARD.read_text(encoding="utf-8"))
    return list(document["panels"])


def test_every_alert_has_a_panel_somebody_can_look_at() -> None:
    """An alert with nothing to look at is a page at three in the morning followed by
    twenty minutes of finding out what the number was doing."""
    charted = {str(panel["siembiot-alert"]) for panel in panels() if panel.get("siembiot-alert")}
    named = {rule["alert"] for rule in rules()}

    assert named <= charted, f"{sorted(named - charted)} fire with no panel"


def test_every_panel_that_claims_an_alert_names_a_real_one() -> None:
    """The other direction. A panel citing a rule that was renamed or deleted describes
    a threshold nothing enforces, which is worse than no annotation."""
    named = {rule["alert"] for rule in rules()}

    for panel in panels():
        claimed = panel.get("siembiot-alert")
        if claimed:
            assert str(claimed) in named, f"{panel['title']} cites unknown rule {claimed}"


def test_a_panel_plots_the_series_its_rule_reads() -> None:
    """Panels and alerts must be looking at the same thing.

    A dashboard whose lines are green while an alert fires teaches people to distrust one
    of the two, and the one they stop trusting is the alert.
    """
    by_alert = {rule["alert"]: rule.get("expr", "") for rule in rules()}

    for panel in panels():
        claimed = panel.get("siembiot-alert")
        if not claimed:
            continue
        expression = by_alert[str(claimed)]
        metrics = set(re.findall(rf"{PREFIX}[a-z_]+", expression)) or set(
            re.findall(r"\bup\b", expression)
        )
        plotted = " ".join(str(target.get("expr", "")) for target in panel.get("targets", []))

        assert any(metric in plotted for metric in metrics), panel["title"]
