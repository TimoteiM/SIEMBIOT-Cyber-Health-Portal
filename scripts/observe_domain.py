"""Assess a public domain using passive observation only.

    python scripts/observe_domain.py example.com
    python scripts/observe_domain.py example.com --json
    python scripts/observe_domain.py example.com --dkim-selector selector1

This runs the real collectors against live public data: DNS, RDAP, Certificate
Transparency, one HTTPS GET of the site root and a TLS handshake. It performs no
operation that requires verified domain control, so it needs no enrollment and no
authorization -- the same basis on which the Public Observatory observes public bodies.

The result is private by default. Publishing anything is a separate, consented act.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "worker" / "src"))

from siembiot_worker.observation.pipeline import ObservationReport, observe_domain  # noqa: E402
from siembiot_worker.policy.catalog import Result, load_catalog  # noqa: E402

RESULT_GLYPH = {
    "pass": "PASS",
    "warning": "WARN",
    "fail": "FAIL",
    "unknown": "????",
    "error": "ERR ",
    "not_applicable": "n/a ",
    "suppressed": "supp",
    "accepted_risk": "risk",
}


def render_text(report: ObservationReport, language: str) -> str:
    catalog = load_catalog()
    snapshot = report.snapshot
    lines: list[str] = []
    lines.append("")
    lines.append(f"  {report.host}")
    lines.append(f"  {'-' * max(len(report.host), 60)}")
    score = "n/a" if snapshot.score is None else f"{snapshot.score:g}"
    if snapshot.coverage.sufficient:
        lines.append(f"  Score        {score} / 100   band: {snapshot.band}")
        lines.append(f"  Coverage     {snapshot.coverage.percentage:g}%")
    else:
        # Leading with a precise number under thin coverage would flatter the result.
        lines.append("  Score        INSUFFICIENT COVERAGE - not a usable score")
        lines.append(
            f"  Coverage     {snapshot.coverage.percentage:g}%"
            f" (minimum {catalog.methodology.minimum_coverage_percentage:g}%)"
        )
        lines.append(f"  (uncapped arithmetic would be {score}, shown only for diagnosis)")
    confidence = snapshot.confidence.level(
        catalog.methodology.high_confidence_minimum,
        catalog.methodology.medium_confidence_minimum,
    )
    lines.append(f"  Confidence   {confidence}")
    lines.append(f"  Mode         {report.mode} (no authorization required)")
    lines.append(
        f"  Methodology  {snapshot.methodology_version}  policy {snapshot.policy_digest[:12]}"
    )
    if report.unavailable_collectors:
        lines.append(f"  Unavailable  {', '.join(report.unavailable_collectors)}")
    lines.append("")

    for pillar in snapshot.pillars:
        pillar_score = "n/a" if pillar.score is None else f"{pillar.score:g}"
        lines.append(f"  {pillar.pillar:<20} {pillar_score:>6}   (weight {pillar.weight:g})")
        for contribution in pillar.contributions:
            check = catalog.by_id(contribution.check_id)
            glyph = RESULT_GLYPH.get(contribution.result, contribution.result)
            evaluation = next(
                item for item in report.evaluations if item.check_id == contribution.check_id
            )
            reason = f"  [{evaluation.reason_code}]" if evaluation.reason_code else ""
            lines.append(f"      {glyph}  {check.title(language)}{reason}")
        lines.append("")

    if snapshot.caps_applied:
        lines.append("  Caps applied:")
        for cap in snapshot.caps_applied:
            lines.append(f"      {cap.cap_id} -> ceiling {cap.ceiling:g}")
            lines.append(f"        triggered by {', '.join(cap.triggering_check_ids)}")
        lines.append("")

    open_findings = [item for item in report.findings if item.severity != "informational"]
    lines.append(f"  Findings     {len(report.findings)} total")
    for finding in sorted(open_findings, key=lambda item: item.severity):
        lines.append(
            f"      {finding.severity:<13} {finding.check_id:<26} {finding.reason_code or ''}"
        )
    lines.append("")
    lines.append("  This is an external hygiene observation of public data.")
    lines.append("  It is not proof that the organization is secure, and not a NIS2 assessment.")
    lines.append("")
    return "\n".join(lines)


def render_json(report: ObservationReport) -> str:
    catalog = load_catalog()
    document = {
        "host": report.host,
        "mode": str(report.mode),
        "snapshot": report.snapshot.as_dict(),
        "evaluations": [
            {
                "check_id": item.check_id,
                "result": item.result,
                "reason_code": item.reason_code,
                "severity": item.severity,
                "pillar": str(item.pillar),
            }
            for item in sorted(report.evaluations, key=lambda item: item.check_id)
        ],
        "findings": [
            item.as_dict(
                catalog.methodology.high_confidence_minimum,
                catalog.methodology.medium_confidence_minimum,
            )
            for item in report.findings
        ],
        "unavailable_collectors": list(report.unavailable_collectors),
        "notice": catalog.methodology.notice,
    }
    return json.dumps(document, indent=2, ensure_ascii=False, sort_keys=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domain", help="a public registrable domain, for example example.com")
    parser.add_argument("--json", action="store_true", help="emit the full machine-readable report")
    parser.add_argument(
        "--dkim-selector",
        action="append",
        default=[],
        metavar="SELECTOR",
        help="a DKIM selector you know is in use; selectors are never guessed",
    )
    parser.add_argument(
        "--probe-tls-protocols",
        action="store_true",
        help="additionally probe for deprecated TLS versions (extra handshakes)",
    )
    parser.add_argument("--rdap-endpoint", default="rdap.org")
    parser.add_argument("--language", choices=("ro", "en"), default="en")
    arguments = parser.parse_args()

    try:
        report = observe_domain(
            arguments.domain,
            declared_dkim_selectors=tuple(arguments.dkim_selector),
            rdap_endpoint=arguments.rdap_endpoint,
            probe_tls_protocols=arguments.probe_tls_protocols,
        )
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print(render_json(report) if arguments.json else render_text(report, arguments.language))
    failed = any(Result(item.result) is Result.FAIL for item in report.evaluations)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
