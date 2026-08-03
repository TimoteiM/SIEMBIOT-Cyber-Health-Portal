from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol, cast

from siembiot_worker.collection.fixtures import (
    FixtureIntegrityError,
    FixtureScenario,
    FixtureScenarioPack,
)
from siembiot_worker.network_safety.address_policy import authorize_resolved_addresses
from siembiot_worker.network_safety.url_policy import (
    CollectionDestination,
    DestinationPolicyError,
    authorize_collection_redirect,
    canonical_host,
)


class BrokerRequestError(ValueError):
    pass


@dataclass(frozen=True)
class BrokerBudget:
    max_header_bytes: int = 8_192
    max_body_bytes: int = 4_096
    max_redirects: int = 2


@dataclass(frozen=True)
class HTTPFixtureRequest:
    destination: CollectionDestination
    method: Literal["HEAD", "GET"] = "HEAD"
    authorized_redirect_hosts: tuple[str, ...] = ()

    @classmethod
    def https(
        cls,
        host: str,
        *,
        path: str = "/",
        method: Literal["HEAD", "GET"] = "HEAD",
        authorized_redirect_hosts: tuple[str, ...] = (),
    ) -> HTTPFixtureRequest:
        if method not in {"HEAD", "GET"}:
            raise BrokerRequestError("method_not_allowed")
        try:
            destination = CollectionDestination("https", host, path)
            authorized = tuple(canonical_host(value) for value in authorized_redirect_hosts)
        except DestinationPolicyError as exc:
            raise BrokerRequestError(exc.reason) from exc
        return cls(destination, method, authorized)


@dataclass(frozen=True)
class FixtureBrokerResult:
    allowed: bool
    reason_code: str
    fixture_timestamp: datetime
    data: Mapping[str, Any] = field(default_factory=dict)
    redirect_count: int = 0


class CollectorBroker(Protocol):
    def resolve_dns(
        self,
        scenario_id: str,
        host: str,
        record_type: str,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> FixtureBrokerResult: ...

    def fetch_http(
        self,
        scenario_id: str,
        request: HTTPFixtureRequest,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> FixtureBrokerResult: ...

    def handshake_tls(
        self, scenario_id: str, host: str, *, cancelled: Callable[[], bool] | None = None
    ) -> FixtureBrokerResult: ...

    def query_rdap(
        self, scenario_id: str, domain: str, *, cancelled: Callable[[], bool] | None = None
    ) -> FixtureBrokerResult: ...

    def query_ct(
        self, scenario_id: str, domain: str, *, cancelled: Callable[[], bool] | None = None
    ) -> FixtureBrokerResult: ...


class FixtureInternetBroker:
    """In-memory fake internet. This class has no transport or socket capability."""

    def __init__(self, pack: FixtureScenarioPack, budget: BrokerBudget | None = None) -> None:
        self._pack = pack
        self._budget = budget or BrokerBudget()

    def _scenario(self, scenario_id: str) -> FixtureScenario | None:
        try:
            return self._pack.scenario(scenario_id)
        except FixtureIntegrityError:
            return None

    @staticmethod
    def _missing() -> FixtureBrokerResult:
        return FixtureBrokerResult(False, "scenario_not_found", datetime.fromtimestamp(0, UTC))

    @staticmethod
    def _cancelled(scenario: FixtureScenario) -> FixtureBrokerResult:
        return FixtureBrokerResult(False, "cancelled", scenario.timestamp)

    @staticmethod
    def _is_cancelled(cancelled: Callable[[], bool] | None) -> bool:
        return cancelled is not None and cancelled()

    @staticmethod
    def _section(scenario: FixtureScenario, name: str) -> Mapping[str, Any]:
        value = scenario.data.get(name, {})
        return cast(Mapping[str, Any], value) if isinstance(value, dict) else {}

    def resolve_dns(
        self,
        scenario_id: str,
        host: str,
        record_type: str,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> FixtureBrokerResult:
        scenario = self._scenario(scenario_id)
        if scenario is None:
            return self._missing()
        if self._is_cancelled(cancelled):
            return self._cancelled(scenario)
        try:
            canonical_host(host)
        except DestinationPolicyError as exc:
            raise BrokerRequestError(exc.reason) from exc
        if record_type not in {
            "A",
            "AAAA",
            "CAA",
            "DS",
            "DNSKEY",
            "MX",
            "NS",
            "SOA",
            "TXT",
            "TLSA",
        }:
            raise BrokerRequestError("record_type_not_allowed")
        host_data = self._section(scenario, "dns").get(host, {})
        records = cast(Mapping[str, Any], host_data) if isinstance(host_data, dict) else {}
        value = records.get(record_type)
        if value is None:
            return FixtureBrokerResult(False, "fixture_unavailable", scenario.timestamp)
        if isinstance(value, dict) and "error" in value:
            return FixtureBrokerResult(False, str(value["error"]), scenario.timestamp)
        return FixtureBrokerResult(True, "fixture", scenario.timestamp, {"records": value})

    def _addresses(self, scenario: FixtureScenario, host: str, visit: int) -> tuple[str, ...]:
        host_data = self._section(scenario, "dns").get(host, {})
        records = cast(Mapping[str, Any], host_data) if isinstance(host_data, dict) else {}
        sequences = records.get("A_sequences")
        if isinstance(sequences, list) and sequences:
            selected = sequences[min(visit, len(sequences) - 1)]
            return tuple(str(item) for item in selected) if isinstance(selected, list) else ()
        addresses = records.get("A", [])
        return tuple(str(item) for item in addresses) if isinstance(addresses, list) else ()

    def fetch_http(
        self,
        scenario_id: str,
        request: HTTPFixtureRequest,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> FixtureBrokerResult:
        scenario = self._scenario(scenario_id)
        if scenario is None:
            return self._missing()
        destination = request.destination
        redirects = 0
        visits: dict[str, int] = {}
        while True:
            if self._is_cancelled(cancelled):
                return self._cancelled(scenario)
            visit = visits.get(destination.host, 0)
            visits[destination.host] = visit + 1
            decision = authorize_resolved_addresses(
                self._addresses(scenario, destination.host, visit)
            )
            if not decision.allowed:
                return FixtureBrokerResult(
                    False, decision.reason_code, scenario.timestamp, redirect_count=redirects
                )
            if self._is_cancelled(cancelled):
                return self._cancelled(scenario)
            raw = self._section(scenario, "http").get(destination.url)
            response = cast(Mapping[str, Any], raw) if isinstance(raw, dict) else {}
            if not response:
                return FixtureBrokerResult(
                    False, "fixture_unavailable", scenario.timestamp, redirect_count=redirects
                )
            if "error" in response:
                return FixtureBrokerResult(
                    False, str(response["error"]), scenario.timestamp, redirect_count=redirects
                )
            if response.get("malformed") is True:
                return FixtureBrokerResult(
                    False, "malformed_response", scenario.timestamp, redirect_count=redirects
                )
            headers_value = response.get("headers", {})
            headers = cast(dict[str, str], headers_value) if isinstance(headers_value, dict) else {}
            if (
                sum(len(str(k)) + len(str(v)) + 4 for k, v in headers.items())
                > self._budget.max_header_bytes
            ):
                return FixtureBrokerResult(
                    False, "headers_too_large", scenario.timestamp, redirect_count=redirects
                )
            body = str(response.get("body", ""))
            if len(body.encode()) > self._budget.max_body_bytes:
                return FixtureBrokerResult(
                    False, "response_too_large", scenario.timestamp, redirect_count=redirects
                )
            status = response.get("status")
            if not isinstance(status, int) or not 100 <= status <= 599:
                return FixtureBrokerResult(
                    False, "malformed_response", scenario.timestamp, redirect_count=redirects
                )
            if status not in {301, 302, 303, 307, 308}:
                data: dict[str, Any] = {"status": status, "headers": headers}
                if request.method == "GET":
                    data["body"] = body
                return FixtureBrokerResult(True, "fixture", scenario.timestamp, data, redirects)
            if redirects >= self._budget.max_redirects:
                return FixtureBrokerResult(
                    False, "redirect_limit", scenario.timestamp, redirect_count=redirects
                )
            location = headers.get("location")
            if location is None:
                return FixtureBrokerResult(
                    False, "malformed_response", scenario.timestamp, redirect_count=redirects
                )
            try:
                destination = authorize_collection_redirect(
                    destination,
                    location,
                    authorized_hosts={request.destination.host, *request.authorized_redirect_hosts},
                )
            except DestinationPolicyError as exc:
                return FixtureBrokerResult(
                    False, exc.reason, scenario.timestamp, redirect_count=redirects
                )
            redirects += 1

    def handshake_tls(
        self,
        scenario_id: str,
        host: str,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> FixtureBrokerResult:
        scenario = self._scenario(scenario_id)
        if scenario is None:
            return self._missing()
        if self._is_cancelled(cancelled):
            return self._cancelled(scenario)
        try:
            canonical_host(host)
        except DestinationPolicyError as exc:
            raise BrokerRequestError(exc.reason) from exc
        decision = authorize_resolved_addresses(self._addresses(scenario, host, 0))
        if not decision.allowed:
            return FixtureBrokerResult(False, decision.reason_code, scenario.timestamp)
        raw = self._section(scenario, "tls").get(host)
        if not isinstance(raw, dict):
            return FixtureBrokerResult(False, "fixture_unavailable", scenario.timestamp)
        if "error" in raw:
            return FixtureBrokerResult(False, str(raw["error"]), scenario.timestamp)
        return FixtureBrokerResult(True, "fixture", scenario.timestamp, raw)

    def _query(
        self,
        scenario_id: str,
        section: str,
        domain: str,
        cancelled: Callable[[], bool] | None,
    ) -> FixtureBrokerResult:
        scenario = self._scenario(scenario_id)
        if scenario is None:
            return self._missing()
        if self._is_cancelled(cancelled):
            return self._cancelled(scenario)
        try:
            canonical_host(domain)
        except DestinationPolicyError as exc:
            raise BrokerRequestError(exc.reason) from exc
        raw = self._section(scenario, section).get(domain)
        if not isinstance(raw, dict):
            return FixtureBrokerResult(False, "fixture_unavailable", scenario.timestamp)
        if "error" in raw:
            return FixtureBrokerResult(False, str(raw["error"]), scenario.timestamp)
        return FixtureBrokerResult(True, "fixture", scenario.timestamp, raw)

    def query_rdap(
        self, scenario_id: str, domain: str, *, cancelled: Callable[[], bool] | None = None
    ) -> FixtureBrokerResult:
        return self._query(scenario_id, "rdap", domain, cancelled)

    def query_ct(
        self, scenario_id: str, domain: str, *, cancelled: Callable[[], bool] | None = None
    ) -> FixtureBrokerResult:
        return self._query(scenario_id, "ct", domain, cancelled)
