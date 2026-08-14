from __future__ import annotations

import hashlib
import secrets
from hmac import compare_digest


def new_challenge_token() -> tuple[str, bytes]:
    token = f"siembiot-v1={secrets.token_urlsafe(32)}"
    return token, hashlib.sha256(token.encode("utf-8")).digest()


def token_matches_digest(token: str, expected_digest: bytes) -> bool:
    actual = hashlib.sha256(token.encode("utf-8")).digest()
    return compare_digest(actual, expected_digest)


def challenge_location(canonical_name: str, method: str) -> str:
    if method == "dns_txt":
        return f"_siembiot-verify.{canonical_name}"
    if method == "https_file":
        return f"https://{canonical_name}/.well-known/siembiot-verification.txt"
    raise ValueError("unsupported challenge method")
