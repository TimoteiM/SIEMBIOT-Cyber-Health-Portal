from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB_SOURCE = ROOT / "apps" / "web" / "src"


def source_text() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(WEB_SOURCE.rglob("*"))
        if path.suffix in {".ts", ".tsx"} and not path.name.endswith(".test.ts")
    )


def test_web_never_uses_browser_token_storage() -> None:
    source = source_text()
    assert "localStorage" not in source
    assert "sessionStorage" not in source
    assert "access_token" not in source
    assert "refresh_token" not in source


def test_web_uses_same_origin_cookie_transport_and_memory_csrf() -> None:
    client = (WEB_SOURCE / "lib" / "secure-client.ts").read_text(encoding="utf-8")
    assert 'credentials: "same-origin"' in client
    assert 'cache: "no-store"' in client
    assert 'headers.set("X-CSRF-Token", csrfToken)' in client
    assert "let csrfToken" in client
