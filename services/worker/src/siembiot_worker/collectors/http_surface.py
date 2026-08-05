"""Web surface collection (pillar C).

One unauthenticated GET of the site root over each scheme. No forms are submitted,
no links are followed, no payload is injected, and no authenticated view is crawled.
"""

from __future__ import annotations

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
from siembiot_worker.collectors.base import Collector
from siembiot_worker.network_safety.collection_broker import (
    CollectionRequest,
    HTTPCollectionResult,
)
from siembiot_worker.network_safety.collection_policy import (
    OperationClass,
    http_destination,
    https_destination,
)

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
)
DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator", "via")

HTTP_DESCRIPTOR = AdapterDescriptor(
    adapter_id="http_surface",
    version="1.0.0",
    group=AdapterGroup.TLS_HTTP,
    title="Web surface collector",
    capabilities=frozenset({"http.redirect", "http.headers", "http.cookies", "http.availability"}),
    data_classification=DataClassification.PUBLIC_OBSERVATION,
    terms_notes="Single unauthenticated GET of the public site root over each scheme.",
    terms_url=None,
    required_secrets=frozenset(),
    timeout_seconds=10.0,
    rate_limit=RateLimitPolicy(5, 1.0, burst=2, minimum_interval_seconds=0.1),
    cost_unit=CostUnit.NONE,
    cache=CachePolicy(600),
    supports_fixtures=True,
)


def parse_hsts(value: str) -> dict[str, Any]:
    directives = [item.strip().lower() for item in value.split(";") if item.strip()]
    max_age: int | None = None
    for directive in directives:
        if directive.startswith("max-age="):
            try:
                max_age = int(directive.split("=", 1)[1])
            except ValueError:
                max_age = None
    return {
        "max_age_seconds": max_age,
        "include_subdomains": "includesubdomains" in directives,
        "preload": "preload" in directives,
    }


def parse_cookie(header_value: str) -> dict[str, Any]:
    """Describe a Set-Cookie header from a public page; the value itself is discarded."""
    parts = [item.strip() for item in header_value.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts and "=" in parts[0] else parts[0].strip()
    attributes = {item.split("=", 1)[0].strip().lower() for item in parts[1:] if item}
    same_site: str | None = None
    domain: str | None = None
    path: str | None = None
    for item in parts[1:]:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip().lower()
        if key == "samesite":
            same_site = value.strip().lower()
        elif key == "domain":
            domain = value.strip().lower()
        elif key == "path":
            path = value.strip()
    return {
        "name": name,
        "secure": "secure" in attributes,
        "http_only": "httponly" in attributes,
        "same_site": same_site,
        "domain": domain,
        "path": path,
        "host_only": domain is None,
    }


class HTTPSurfaceCollector(Collector):
    descriptor = HTTP_DESCRIPTOR

    def collect(self, request: CollectionRequest) -> CollectionResult:
        host = request.canonical_host
        surface_request = CollectionRequest(
            request.organization_id,
            request.domain_id,
            request.assessment_id,
            OperationClass.HTTP_SURFACE,
            host,
            request.authorized_hosts or (host,),
        )
        plaintext = self._broker.fetch(
            surface_request, http_destination(OperationClass.HTTP_SURFACE, host)
        )
        secure = self._broker.fetch(
            surface_request, https_destination(OperationClass.HTTP_SURFACE, host)
        )

        payload: dict[str, Any] = {
            "host": host,
            "http": self._observation(plaintext),
            "https": self._observation(secure),
            "redirects_http_to_https": self._redirects_to_https(plaintext),
        }
        if secure.allowed:
            payload["security_headers"] = self._security_headers(secure)
            payload["disclosure_headers"] = {
                name: secure.headers[name] for name in DISCLOSURE_HEADERS if name in secure.headers
            }
            payload["cookies"] = [
                parse_cookie(value) for name, value in secure.raw_headers if name == "set-cookie"
            ]
        else:
            payload["security_headers"] = None
            payload["disclosure_headers"] = None
            payload["cookies"] = None

        if not secure.allowed and not plaintext.allowed:
            return self.unavailable("site_unreachable", payload)
        reasons: list[str] = []
        if not secure.allowed:
            reasons.append(f"https_{secure.reason_code}")
        if not plaintext.allowed:
            reasons.append(f"http_{plaintext.reason_code}")
        if reasons:
            return self.partial(payload, tuple(reasons), source=host)
        return self.ok(payload, source=host)

    @staticmethod
    def _observation(result: HTTPCollectionResult) -> dict[str, Any]:
        return {
            "reachable": result.allowed,
            "reason_code": result.reason_code,
            "status_code": result.status_code,
            "redirect_count": result.redirect_count,
            "redirect_chain": list(result.redirect_chain),
            "final_url": result.final_url,
        }

    @staticmethod
    def _redirects_to_https(plaintext: HTTPCollectionResult) -> dict[str, Any]:
        final = plaintext.final_url
        return {
            "observed": plaintext.allowed,
            "redirects": bool(final and final.startswith("https://")),
            "final_url": final,
            "reason_code": plaintext.reason_code,
        }

    @staticmethod
    def _security_headers(result: HTTPCollectionResult) -> dict[str, Any]:
        present = {
            name: result.headers[name] for name in SECURITY_HEADERS if name in result.headers
        }
        section: dict[str, Any] = {
            "present": present,
            "missing": [name for name in SECURITY_HEADERS if name not in result.headers],
        }
        if "strict-transport-security" in present:
            section["hsts"] = parse_hsts(present["strict-transport-security"])
        else:
            section["hsts"] = None
        return section
