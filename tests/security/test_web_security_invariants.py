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


def test_web_uses_same_origin_transport_and_holds_no_credential() -> None:
    """Authentication terminates upstream, so this client must carry no credential.

    It sends same-origin requests and never caches a private response; anything that
    authenticates the request is attached by the layer in front of the application.
    """
    client = (WEB_SOURCE / "lib" / "secure-client.ts").read_text(encoding="utf-8")
    assert 'credentials: "same-origin"' in client
    assert 'cache: "no-store"' in client
    assert "csrfToken" not in client
    assert "Authorization" not in client


def test_domain_ui_does_not_persist_tokens_or_make_authorization_decisions() -> None:
    sources = source_text()
    assert "localStorage" not in sources
    assert "sessionStorage" not in sources
    assert "crypto.subtle.sign" not in sources
    assert "BEGIN PRIVATE KEY" not in sources


def test_domain_ui_uses_only_typed_same_origin_client_for_api_access() -> None:
    domain_sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (WEB_SOURCE / "app" / "organizations").rglob("*domain*.tsx")
    )
    assert "apiRequest" in domain_sources
    assert "fetch(" not in domain_sources
