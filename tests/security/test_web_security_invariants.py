from __future__ import annotations

import re
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


def test_development_identity_injection_cannot_reach_a_deployed_build() -> None:
    """The local identity middleware is a development convenience, not a bypass.

    Authentication terminates upstream, so locally there is no gateway to inject the
    identity headers a browser cannot set itself. The middleware fills that gap, and
    these are the guards that stop it ever mattering in a real deployment.
    """
    middleware = (WEB_SOURCE / "middleware.ts").read_text(encoding="utf-8")

    # Gated on the build mode, so a production build never takes the path at all.
    assert 'process.env.NODE_ENV === "development"' in middleware

    # Gated on explicit opt-in, so an unconfigured development build injects nothing.
    assert "SIEMBIOT_DEV_IDENTITY_SUBJECT" in middleware

    # Never overwrites an identity that is already present, so a real gateway wins.
    assert "!headers.has(name)" in middleware

    # Injects no gateway proof, so the API's production resolver rejects these headers
    # regardless. The bypass cannot survive a deployment even if it were reached.
    assert "gateway-secret" not in middleware.lower()
    assert "gateway_secret" not in middleware.lower()


def test_no_page_offers_a_login_flow_this_service_does_not_implement() -> None:
    """Authentication is upstream, so the UI must not imply a login it cannot perform."""
    sources = source_text()
    assert "/api/v1/auth/login" not in sources
    assert "/api/v1/auth/callback" not in sources
    assert "Autentifică-te din nou" not in sources


def test_the_local_sign_in_page_cannot_be_mistaken_for_authentication() -> None:
    """A form with a username and a password is the easiest thing in this product to
    mistake for a login, and it is not one.

    Identity terminates at a gateway upstream; this page only chooses which identity the
    development resolver asserts, in place of editing environment variables. The
    credentials are in the repository. So the page has to be gated on the build mode and
    has to say what it is, on itself, where somebody deciding whether to trust it will
    read it.
    """
    accounts = (WEB_SOURCE / "lib" / "dev-accounts.ts").read_text(encoding="utf-8")
    page = (WEB_SOURCE / "app" / "sign-in" / "page.tsx").read_text(encoding="utf-8")

    assert 'process.env.NODE_ENV === "development"' in accounts

    # The disclaimer is rendered, not merely written in a comment somebody has to open
    # the file to find.
    assert "signIn.notRealAuthentication" in page

    # It selects an account defined in the repository rather than carrying an identity
    # of its own, so a forged cookie can only pick between accounts that already exist.
    middleware = (WEB_SOURCE / "middleware.ts").read_text(encoding="utf-8")
    assert "accountBySubject" in middleware

    # And it still injects no gateway proof, so the API's production resolver refuses
    # these headers however the identity was chosen.
    assert "gateway-secret" not in (page + accounts).lower()


def test_the_local_accounts_carry_no_credential_worth_protecting() -> None:
    """The passwords are the account names, and that is the safeguard.

    A credential that looked plausible in production would eventually be used there.
    These cannot be, which is why they are allowed to sit in the repository at all.
    """
    accounts = (WEB_SOURCE / "lib" / "dev-accounts.ts").read_text(encoding="utf-8")
    pairs = re.findall(r'username: "([^"]+)",\s+password: "([^"]+)"', accounts)
    assert pairs, "no accounts found; this test would otherwise pass vacuously"
    for username, password in pairs:
        assert username == password, f"{username} has a password worth protecting"
