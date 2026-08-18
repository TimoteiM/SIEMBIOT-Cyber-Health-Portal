from __future__ import annotations

from collector_support import (
    build_broker,
    frozen_clock,
    multi_header_response,
    request_for,
    response,
)
from siembiot_worker.adapters.contract import CollectionResult, CollectionStatus
from siembiot_worker.collectors.http_surface import (
    HTTPSurfaceCollector,
    parse_cookie,
    parse_hsts,
)
from siembiot_worker.network_safety.collection_policy import OperationClass
from siembiot_worker.network_safety.models import TransportResponse

HOST = "strong.example.test"
HTTP_ROOT = f"http://{HOST}/"
HTTPS_ROOT = f"https://{HOST}/"

HARDENED_HEADERS = {
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "cross-origin-embedder-policy": "require-corp",
}


def collect(routes: dict[str, TransportResponse]) -> CollectionResult:
    collector = HTTPSurfaceCollector(build_broker(routes=routes), frozen_clock)
    return collector.collect(request_for(HOST, OperationClass.HTTP_SURFACE))


def test_hardened_site_is_collected_completely() -> None:
    result = collect(
        {
            HTTP_ROOT: response(301, {"location": HTTPS_ROOT}),
            HTTPS_ROOT: response(200, HARDENED_HEADERS, b"<html></html>"),
        },
    )
    assert result.status is CollectionStatus.OK
    payload = result.payload
    assert payload["redirects_http_to_https"]["redirects"] is True
    assert payload["security_headers"]["missing"] == []
    assert payload["security_headers"]["hsts"]["max_age_seconds"] == 63072000
    assert payload["security_headers"]["hsts"]["preload"] is True
    assert payload["disclosure_headers"] == {}


def test_missing_security_headers_are_listed_individually() -> None:
    result = collect(
        {
            HTTP_ROOT: response(200, {"server": "nginx/1.2.3"}, b"plain"),
            HTTPS_ROOT: response(200, {"server": "nginx/1.2.3", "x-powered-by": "PHP/5.4"}, b"x"),
        },
    )
    missing = result.payload["security_headers"]["missing"]
    assert "content-security-policy" in missing
    assert "strict-transport-security" in missing
    assert result.payload["security_headers"]["hsts"] is None
    assert result.payload["disclosure_headers"]["x-powered-by"] == "PHP/5.4"


def test_plaintext_site_without_redirect_is_recorded_as_not_redirecting() -> None:
    result = collect(
        {HTTP_ROOT: response(200, {}, b"plain"), HTTPS_ROOT: response(200, {}, b"secure")},
    )
    assert result.payload["redirects_http_to_https"]["redirects"] is False
    assert result.payload["redirects_http_to_https"]["observed"] is True


def test_every_set_cookie_header_is_described() -> None:
    result = collect(
        {
            HTTP_ROOT: response(301, {"location": HTTPS_ROOT}),
            HTTPS_ROOT: multi_header_response(
                200,
                (
                    ("set-cookie", "session=abc; Secure; HttpOnly; SameSite=Lax; Path=/"),
                    ("set-cookie", "tracking=xyz; Domain=.strong.example.test"),
                ),
                b"x",
            ),
        },
    )
    cookies = result.payload["cookies"]
    assert len(cookies) == 2
    assert cookies[0] == {
        "name": "session",
        "secure": True,
        "http_only": True,
        "same_site": "lax",
        "domain": None,
        "path": "/",
        "host_only": True,
    }
    assert cookies[1]["secure"] is False
    assert cookies[1]["host_only"] is False


def test_unreachable_https_yields_partial_collection() -> None:
    collector = HTTPSurfaceCollector(
        build_broker(routes={HTTP_ROOT: response(200, {}, b"plain")}), frozen_clock
    )
    result = collector.collect(request_for(HOST, OperationClass.HTTP_SURFACE))
    assert result.status is CollectionStatus.OK
    assert result.payload["https"]["status_code"] == 404
    assert result.payload["cookies"] == []


def test_completely_unreachable_site_is_unavailable() -> None:
    class RefusingResolver:
        def resolve(self, host: str) -> tuple[str, ...]:
            raise OSError("no such host")

    collector = HTTPSurfaceCollector(
        build_broker(resolver=RefusingResolver()),
        frozen_clock,
    )
    result = collector.collect(request_for(HOST, OperationClass.HTTP_SURFACE))
    assert result.status is CollectionStatus.UNAVAILABLE
    assert result.reason_code == "site_unreachable"
    assert result.payload["security_headers"] is None


# -- pure parsers ------------------------------------------------------------


def test_hsts_parser_reads_directives_case_insensitively() -> None:
    parsed = parse_hsts("MAX-AGE=31536000; IncludeSubDomains")
    assert parsed["max_age_seconds"] == 31536000
    assert parsed["include_subdomains"] is True
    assert parsed["preload"] is False


def test_hsts_with_unparsable_max_age_reports_none_not_zero() -> None:
    assert parse_hsts("max-age=forever")["max_age_seconds"] is None


def test_cookie_parser_discards_the_value() -> None:
    parsed = parse_cookie("secret=super-sensitive-token; Secure")
    assert parsed["name"] == "secret"
    assert "super-sensitive-token" not in str(parsed)


def test_cookie_without_attributes_defaults_to_insecure() -> None:
    parsed = parse_cookie("plain=1")
    assert parsed["secure"] is False
    assert parsed["http_only"] is False
    assert parsed["same_site"] is None


def test_a_refusal_of_ours_is_not_reported_as_their_site_being_down() -> None:
    """`site_unreachable` used to be the answer whichever way both attempts failed.

    Both reason codes were discarded, so a response we declined to read looked exactly
    like a host that never answered -- and an institution was told nobody could reach a
    site that was up. That is the report accusing them of a fault that is ours.
    """
    from siembiot_worker.collectors.http_surface import _combined_reason

    assert _combined_reason("response_too_large", "response_too_large") == "response_too_large"
    assert (
        _combined_reason("redirect_not_authorized", "no_addresses")
        == "https_redirect_not_authorized"
    )


def test_a_site_that_really_did_not_answer_still_says_so() -> None:
    """The phrase the policy catalogue and the report already understand is kept for the
    case it describes, rather than being replaced with something more precise and less
    recognised."""
    from siembiot_worker.collectors.http_surface import _combined_reason

    assert _combined_reason("no_addresses", "no_addresses") == "site_unreachable"
    assert _combined_reason("timeout", "transport_error") == "site_unreachable"


def test_the_collector_reports_the_reason_it_was_given() -> None:
    """The helper being right is not the same as the collector using it.

    Both fetches here fail because the site redirects somewhere this run is not permitted
    to follow. That is a refusal of ours about a site that answered, and calling it
    `site_unreachable` tells an institution their website is down when it is not -- which
    is the report accusing them of a fault that belongs to us.
    """
    elsewhere = "https://somewhere-else.example/"
    collector = HTTPSurfaceCollector(
        build_broker(
            routes={
                HTTP_ROOT: response(301, {"location": elsewhere}),
                HTTPS_ROOT: response(301, {"location": elsewhere}),
            }
        ),
        frozen_clock,
    )
    result = collector.collect(request_for(HOST, OperationClass.HTTP_SURFACE))
    assert result.status is CollectionStatus.UNAVAILABLE
    assert result.reason_code is not None
    assert result.reason_code != "site_unreachable"
    assert "redirect" in result.reason_code
