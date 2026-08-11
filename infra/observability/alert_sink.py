"""A receiver that writes down the alerts it is sent.

Alertmanager's webhooks point somewhere. In a deployment that is a paging provider; in
this stack it is here, because "the routing is configured" and "an alert reaches a
receiver" are different claims and only the second one can be demonstrated.

It exists so the last hop is testable. Without it the chain could be verified as far as
Alertmanager and no further, which is precisely where the previous version of this stack
stopped: rules that nothing evaluated, routing to nowhere.

Deliberately tiny and dependency-free -- the standard library only, so it needs no image
of its own beyond a Python base, and nothing here has to be kept in step with a
framework. It is not a paging system and must not grow into one.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 9095

#: Kept in memory so a test can ask what arrived. Bounded, because an alert storm should
#: not become a memory leak in the thing watching for alert storms.
MAX_RECEIVED = 200
received: list[dict[str, object]] = []


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 - name fixed by BaseHTTPRequestHandler
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"unparsed": raw.decode("utf-8", errors="replace")[:500]}

        route = self.path.lstrip("/") or "unrouted"
        for alert in payload.get("alerts", [{}]):
            entry = {
                "route": route,
                "status": alert.get("status", payload.get("status")),
                "alertname": alert.get("labels", {}).get("alertname"),
                "severity": alert.get("labels", {}).get("severity"),
                "summary": alert.get("annotations", {}).get("summary"),
            }
            received.append(entry)
            # One line per alert on stdout, so `docker logs` is a usable record of what
            # was delivered and when.
            print(json.dumps(entry), flush=True)
        del received[:-MAX_RECEIVED]

        self.send_response(200)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        """What has arrived. The only reason this is queryable rather than log-only."""
        body = json.dumps(received).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        # The default logger writes a line per request to stderr, which drowns the
        # alerts themselves in scrape noise.
        del format, args


def main() -> int:
    print(f"alert sink listening on {PORT}", file=sys.stderr, flush=True)
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()  # noqa: S104
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
