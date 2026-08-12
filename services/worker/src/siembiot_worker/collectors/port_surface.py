"""Which services a host exposes to the internet (pillar D, authorized only).

Every other collector reads what a domain publishes. This one connects to ports nobody
advertised, so it runs only under a signed authorization and only against a domain whose
control was proved.

What it produces is deliberately an *inventory* rather than a verdict. "Port 3389 is
open" is not something a town clerk can act on; "the remote desktop service is reachable
from anywhere on the internet, and that is how most ransomware arrives" is. The port
catalogue carries that sentence in both languages, and it lives outside the scoring
digest so it can be corrected without invalidating every stored score.

The catalogue is also a bound. Nineteen ports across four exposure classes, not a range:
scanning everything is a different activity with different legal weight, and the long
tail produces noise rather than findings anybody acts on.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from siembiot_worker.adapters.contract import (
    AdapterDescriptor,
    AdapterGroup,
    CachePolicy,
    CollectionResult,
    CostUnit,
    DataClassification,
    RateLimitPolicy,
)
from siembiot_worker.collectors.base import Clock, Collector, utc_now
from siembiot_worker.network_safety.collection_broker import (
    CollectionNetworkBroker,
    CollectionRequest,
)

POLICY_ROOT = Path(__file__).resolve().parents[5] / "packages" / "policy"

#: Exposure classes, ordered by how much trouble an open port in each one means. The
#: order is used to summarise a host in one word, so it has to be a total order rather
#: than a set.
EXPOSURE_ORDER = ("remote_access", "database", "management", "infrastructure")

PORT_DESCRIPTOR = AdapterDescriptor(
    adapter_id="port_surface",
    version="1.0.0",
    group=AdapterGroup.ACTIVE_PROBE,
    title="Exposed service inventory",
    capabilities=frozenset({"surface.ports"}),
    data_classification=DataClassification.TENANT_CONFIDENTIAL,
    terms_notes=(
        "Opens TCP connections to a bounded list of ports on a host whose control has "
        "been verified and for which a signed authorization is in force. Sends nothing; "
        "reads only what a service announces on connect."
    ),
    terms_url=None,
    required_secrets=frozenset(),
    timeout_seconds=30.0,
    rate_limit=RateLimitPolicy(1, 1.0, burst=1, minimum_interval_seconds=0.2),
    cost_unit=CostUnit.NONE,
    # Never cached. Every other collector's answer stays true for a while; this one
    # describes somebody's network at one moment, and a cached scan is a stale claim
    # wearing fresh evidence.
    cache=CachePolicy(0),
    supports_fixtures=True,
    # The one collector here that asks a host a question rather than reading something
    # it published. The group already said `active_probe`; this flag defaulted to True
    # and nothing read it, so the descriptor claimed the port prober was passive until a
    # page started disclosing it to institutions.
    passive=False,
)


class PortCatalogError(RuntimeError):
    pass


@dataclass(frozen=True)
class PortDefinition:
    port: int
    service: str
    exposure: str
    severity: str
    title_ro: str
    title_en: str
    rationale_ro: str
    rationale_en: str


@lru_cache(maxsize=4)
def load_port_catalog(version: str = "1.0.0") -> tuple[PortDefinition, ...]:
    """The ports this product probes, validated on the way in.

    A malformed catalogue stops the collector from loading rather than producing a
    half-empty scan that reads as a clean result.
    """
    path = POLICY_ROOT / "ports" / f"v{version.split('.')[0]}" / "ports.json"
    if not path.is_file():
        raise PortCatalogError(f"no port catalog for version {version}")
    raw = json.loads(path.read_text(encoding="utf-8"))

    definitions: list[PortDefinition] = []
    seen: set[int] = set()
    for item in raw["ports"]:
        port = int(item["port"])
        if not 1 <= port <= 65535:
            raise PortCatalogError(f"port {port} is out of range")
        if port in seen:
            raise PortCatalogError(f"duplicate port {port}")
        if item["exposure"] not in EXPOSURE_ORDER:
            raise PortCatalogError(f"port {port}: unknown exposure {item['exposure']!r}")
        seen.add(port)
        definitions.append(
            PortDefinition(
                port=port,
                service=str(item["service"]),
                exposure=str(item["exposure"]),
                severity=str(item["severity"]),
                title_ro=str(item["title_ro"]),
                title_en=str(item["title_en"]),
                rationale_ro=str(item["rationale_ro"]),
                rationale_en=str(item["rationale_en"]),
            )
        )
    if not definitions:
        raise PortCatalogError("empty port catalog")
    return tuple(definitions)


class PortSurfaceCollector(Collector):
    descriptor = PORT_DESCRIPTOR

    def __init__(
        self,
        broker: CollectionNetworkBroker,
        clock: Clock | None = None,
        catalog_version: str = "1.0.0",
    ) -> None:
        # `or utc_now` because the base class's default is bypassed the moment a
        # subclass forwards an explicit None.
        super().__init__(broker, clock or utc_now)
        self._catalog_version = catalog_version

    def collect(self, request: CollectionRequest) -> CollectionResult:
        definitions = load_port_catalog(self._catalog_version)
        by_port = {definition.port: definition for definition in definitions}
        observations = self._broker.probe_ports(request, [item.port for item in definitions])

        if not observations:
            return self.unavailable("probe_refused", {"host": request.canonical_host})

        probed = [
            {
                "port": observation.port,
                "state": observation.state,
                "service": by_port[observation.port].service,
                "exposure": by_port[observation.port].exposure,
                "severity": by_port[observation.port].severity,
                # Only ever what the service announced first, and only where it did.
                "banner": observation.banner,
            }
            for observation in observations
            if observation.port in by_port
        ]
        open_ports = [item for item in probed if item["state"] == "open"]

        # A scan where nothing answered at all is not the same as a host with nothing
        # open: the first says our probes never arrived. Reported as unavailable so it
        # reduces coverage rather than being recorded as a clean surface.
        if all(item["state"] == "error" for item in probed):
            return self.unavailable(
                "probe_refused", {"host": request.canonical_host, "ports": probed}
            )

        payload: dict[str, Any] = {
            "host": request.canonical_host,
            "ports": probed,
            "probed_count": len(probed),
            "open_count": len(open_ports),
            "open_by_exposure": {
                exposure: sum(1 for item in open_ports if item["exposure"] == exposure)
                for exposure in EXPOSURE_ORDER
            },
            # The worst class with anything open, so a host can be summarised in one word
            # without the reader having to rank the list themselves.
            "worst_exposure": next(
                (
                    exposure
                    for exposure in EXPOSURE_ORDER
                    if any(item["exposure"] == exposure for item in open_ports)
                ),
                None,
            ),
        }
        filtered = [item for item in probed if item["state"] == "filtered"]
        if filtered:
            # Worth carrying separately: a filtered port is a firewall doing its job, and
            # reporting it as "not open" alongside a host that simply has no such service
            # would lose the difference between protected and absent.
            payload["filtered_count"] = len(filtered)
        return self.ok(payload, source=request.canonical_host)
