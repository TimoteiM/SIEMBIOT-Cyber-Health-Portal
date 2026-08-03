from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class ManifestSigner(Protocol):
    key_id: str
    algorithm: str
    development_only: bool

    def sign(self, payload: bytes) -> bytes: ...


@dataclass(frozen=True)
class ManifestPublicKey:
    key_id: str
    algorithm: str
    key: Ed25519PublicKey


class Ed25519ManifestSigner:
    algorithm = "EdDSA"

    def __init__(self, key_id: str, key: Ed25519PrivateKey, *, development_only: bool) -> None:
        self.key_id = key_id
        self._key = key
        self.development_only = development_only

    @classmethod
    def generate(cls, key_id: str, *, development_only: bool) -> Ed25519ManifestSigner:
        return cls(key_id, Ed25519PrivateKey.generate(), development_only=development_only)

    def sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload)

    def public_key(self) -> ManifestPublicKey:
        return ManifestPublicKey(self.key_id, self.algorithm, self._key.public_key())


class ManifestKeySet:
    def __init__(self, keys: list[ManifestPublicKey]) -> None:
        self._keys = {key.key_id: key for key in keys}

    def verify(self, key_id: str, algorithm: str, payload: bytes, signature: bytes) -> bool:
        key = self._keys.get(key_id)
        if key is None or key.algorithm != algorithm or algorithm != "EdDSA":
            return False
        try:
            key.key.verify(signature, payload)
        except (InvalidSignature, ValueError):
            return False
        return True


def ensure_signer_allowed(environment: str, signer: ManifestSigner) -> None:
    if environment.lower() in {"production", "prod"} and signer.development_only:
        raise RuntimeError("a development-only manifest signing key is forbidden in production")
