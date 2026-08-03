from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from siembiot_worker.collection.broker import FixtureBrokerResult, HTTPFixtureRequest
from siembiot_worker.collection.models import (
    CollectionObservation,
    ObservationOutcome,
    build_fixture_observation,
)
from siembiot_worker.collectors.common import FixtureCollectorContext, HTTPBroker


class HTTPCollector:
    def __init__(self, broker: HTTPBroker) -> None:
        self._broker = broker

    @staticmethod
    def _observation(
        context: FixtureCollectorContext,
        host: str,
        check: str,
        result: FixtureBrokerResult,
    ) -> CollectionObservation:
        payload: dict[str, Any] = {
            "fixture_only": True,
            "host": host,
            "check": check,
            "reason_code": result.reason_code,
        }
        if result.allowed:
            status = result.data.get("status")
            raw_headers = result.data.get("headers")
            valid_headers = (
                isinstance(raw_headers, Mapping)
                and len(raw_headers) <= 64
                and all(
                    isinstance(key, str)
                    and isinstance(value, str)
                    and len(key) <= 128
                    and len(value) <= 2_048
                    for key, value in raw_headers.items()
                )
            )
            if not isinstance(status, int) or not valid_headers:
                outcome = ObservationOutcome.ERROR
                payload["reason_code"] = "malformed_fixture_data"
            else:
                headers_source = cast(Mapping[object, object], raw_headers)
                headers = {str(key).lower(): str(value) for key, value in headers_source.items()}
                outcome = (
                    ObservationOutcome.PASS if 200 <= status < 400 else ObservationOutcome.WARNING
                )
                payload["status"] = status
                if check == "head":
                    payload["headers"] = {
                        "hsts": "strict-transport-security" in headers,
                        "content_security_policy": "content-security-policy" in headers,
                        "frame_protection": "x-frame-options" in headers,
                        "referrer_policy": "referrer-policy" in headers,
                        "permissions_policy": "permissions-policy" in headers,
                    }
                    cookie = headers.get("set-cookie", "").lower()
                    payload["public_cookie_secure"] = "secure" in cookie
                    payload["public_cookie_httponly"] = "httponly" in cookie
                else:
                    body = result.data.get("body")
                    if not isinstance(body, str):
                        outcome = ObservationOutcome.ERROR
                        payload["reason_code"] = "malformed_fixture_data"
                    else:
                        payload["body_present"] = bool(body)
                        payload["body_bytes"] = len(body.encode())
        elif result.reason_code in {"fixture_unavailable", "scenario_not_found"}:
            outcome = ObservationOutcome.UNKNOWN
        else:
            outcome = ObservationOutcome.ERROR
        return build_fixture_observation(
            scope_reference=context.scope_reference,
            collector_id="http",
            collector_version="1.0.0",
            adapter_id="fixture-internet",
            adapter_version="1.0.0",
            collected_at=result.fixture_timestamp,
            scenario_id=context.scenario_id,
            scenario_sha256=context.scenario_sha256,
            outcome=outcome,
            payload=payload,
        )

    def collect(
        self, context: FixtureCollectorContext, host: str
    ) -> tuple[CollectionObservation, CollectionObservation]:
        head = self._broker.fetch_http(
            context.scenario_id,
            HTTPFixtureRequest.https(host, method="HEAD"),
            cancelled=context.cancelled,
        )
        security_text = self._broker.fetch_http(
            context.scenario_id,
            HTTPFixtureRequest.https(host, path="/.well-known/security.txt", method="GET"),
            cancelled=context.cancelled,
        )
        return (
            self._observation(context, host, "head", head),
            self._observation(context, host, "security_text", security_text),
        )
