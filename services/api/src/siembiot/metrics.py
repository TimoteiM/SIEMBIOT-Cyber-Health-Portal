"""Operational metrics, in Prometheus exposition format.

Logs say what happened; these say whether the system is working. The difference matters
at three in the morning, when nobody is going to read a log to discover that the queue
stopped draining four hours ago.

**Nothing here identifies a tenant or a target.** That is the design constraint the rest
follows from. A metrics endpoint is scraped on a timer and stored in a system with its
own access rules, usually looser ones -- so a label carrying `organization_id` would
quietly export the customer list, and one carrying a hostname would export the list of
domains under assessment. Neither is something an operator needs in order to know the
platform is unwell.

Every label is drawn from a closed set the schema already constrains: assessment states,
step states, network reason codes, ownership states. That keeps cardinality bounded as a
side effect, but the reason is confidentiality, not cost.

The counts come from `app_operational_metrics`, a `SECURITY DEFINER` function, rather
than from queries here. The API runs as a role that row-level security applies to, so
querying the tables directly returned **zero for everything** -- not an error, because
row-level security hides rows rather than refusing. A monitoring system would have
recorded a healthy idle platform indefinitely. Silent zeros are worse than a failed
scrape: a failed scrape is visible, a confident wrong number is not.

Written by hand rather than with a client library. The exposition format is a few lines,
every label value comes from an enumerated set, and the alternative is a dependency
carrying a registry, a collector API and a global singleton to do this much.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast

from fastapi import APIRouter, Request, Response
from sqlalchemy import text

from siembiot.db import Database

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
PREFIX = "siembiot_"

#: Added by `render` rather than read from the database, since it reports whether that
#: read worked. Named so `collect` can leave it alone instead of emitting a second copy.
SCRAPE_OK = "metrics_scrape_ok"

#: What each metric means, for whoever meets it in an alert at an unsociable hour.
HELP: dict[str, str] = {
    "assessments": "Assessments by lifecycle state, across all tenants.",
    "assessment_steps": (
        "Assessment steps by state. A rising dead_lettered count means work is being "
        "abandoned rather than retried."
    ),
    "domains": (
        "Domains by ownership state. A rising reverification_required count means "
        "proofs are lapsing faster than they are renewed."
    ),
    "network_operations": (
        "Network operations by reason code. Refusals are normal; a change in their mix "
        "is what to look at."
    ),
    "oldest_unsettled_assessment_seconds": (
        "Age of the oldest assessment that has not settled. The clearest signal that "
        "work has stopped flowing."
    ),
    "schedules_due": (
        "Schedules past their next run time. Sustained above zero means the scheduler "
        "is not dispatching."
    ),
    "provider_quota_used": (
        "Provider budget spent today, per adapter, across every worker. Snapshotted "
        "from the shared counter; a per-process number would understate it by however "
        "many workers are running."
    ),
    "provider_quota_denied": (
        "Calls refused today because the budget was spent. Without this, a used count "
        "at its limit cannot distinguish one call turned away from ten thousand."
    ),
    "build_info": "Schema version currently applied.",
    "metrics_scrape_ok": "Whether this scrape could read the database.",
}

#: Escaped even though every value comes from a closed set, so that a label added later
#: from somewhere less constrained cannot break the format silently.
_ESCAPES = str.maketrans({"\\": "\\\\", '"': '\\"', "\n": "\\n"})


@dataclass
class Metric:
    name: str
    samples: list[tuple[dict[str, str], float]] = field(default_factory=list)

    def render(self) -> str:
        full = f"{PREFIX}{self.name}"
        lines = [
            f"# HELP {full} {HELP.get(self.name, 'No description.')}",
            f"# TYPE {full} gauge",
        ]
        for labels, value in self.samples:
            if labels:
                rendered = ",".join(
                    f'{key}="{value_.translate(_ESCAPES)}"'
                    for key, value_ in sorted(labels.items())
                )
                lines.append(f"{full}{{{rendered}}} {value}")
            else:
                lines.append(f"{full} {value}")
        return "\n".join(lines)


def collect(database: Database) -> list[Metric]:
    """Read the aggregates through the one function allowed to cross tenants.

    Queried on scrape rather than accumulated in memory: the API runs as several
    replicas, and an in-process counter would report one replica's share of the truth
    while looking like the whole of it.
    """
    grouped: dict[str, Metric] = {}
    with database.engine.connect() as connection:
        rows = connection.execute(text("SELECT * FROM app_operational_metrics()")).all()

    for metric_name, label_key, label_value, value in rows:
        metric = grouped.setdefault(str(metric_name), Metric(str(metric_name)))
        labels = {str(label_key): str(label_value)} if label_key is not None else {}
        metric.samples.append((labels, float(value)))

    # A deterministic order, so a diff between two scrapes is about the numbers.
    return [grouped[name] for name in sorted(grouped)]


def render(metrics: list[Metric], scrape_ok: bool) -> str:
    """The scrape body, always carrying every metric this exporter describes.

    A metric with nothing to report still reports. The database returns rows only for
    what exists, so an empty table used to remove its series from the scrape entirely --
    and a missing series is indistinguishable from a zero one, and from an exporter that
    has broken. `siembiot_network_operations` was absent from every scrape for exactly
    that reason while an alert rule referred to it, so the rule could never have fired
    and nothing would ever have said so.

    Filled in here rather than in `collect`, because the guarantee is about what a scrape
    contains: stated here, it holds however the metrics were gathered.
    """
    present = {metric.name for metric in metrics}
    # Unlabelled, because "there were none at all" is not a fact about any label value.
    missing = [
        Metric(name, [({}, 0.0)])
        for name in sorted(HELP)
        if name not in present and name != SCRAPE_OK
    ]

    body = "\n".join(metric.render() for metric in [*metrics, *missing])
    ok = Metric(SCRAPE_OK, [({}, 1.0 if scrape_ok else 0.0)])
    return (f"{body}\n" if body else "") + ok.render() + "\n"


def build_metrics_router() -> APIRouter:
    router = APIRouter(tags=["system"])

    @router.get("/metrics", include_in_schema=False)
    def metrics(request: Request) -> Response:
        """Unauthenticated, and safe to be so.

        Kept out of the OpenAPI document because it is not part of the product's
        contract and nothing should generate a client for it.

        Ingress should not expose this path -- but it is built so that exposure would be
        an embarrassment rather than a breach. Relying on a proxy rule alone leaves the
        customer list one misconfiguration away from being published; there is nothing
        here that names a tenant, a domain or a person.
        """
        database = cast(Database, request.app.state.database)
        try:
            body = render(collect(database), scrape_ok=True)
        except Exception:  # noqa: BLE001 - a scrape must never take the process with it
            # Reported as a metric rather than a 500, so the monitoring system records
            # "could not read the database" instead of recording nothing -- which looks
            # identical to a healthy, quiet system.
            body = render([], scrape_ok=False)
        return Response(content=body, media_type=CONTENT_TYPE)

    return router
