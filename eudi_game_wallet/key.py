"""Keys and signers: HS256 (the dependency-free prototype algorithm) plus
optional ES256 (the production path, when the ``cryptography`` package is
installed).

SPDX-License-Identifier: CC-BY-4.0
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from . import json as gdwjson
from .errors import ERR_MALFORMED, GdwError
from .primitives import (
    b64url_decode,
    b64url_encode,
    b64url_utf8,
    constant_time_eq,
    hmac_sha256,
)


@dataclass
class GdwKey:
    """A GDW key. HS256 uses ``k``; ES256 uses ``d`` / ``x`` / ``y``."""

    alg: str = ""
    k: Optional[str] = None
    crv: Optional[str] = None
    x: Optional[str] = None
    y: Optional[str] = None
    d: Optional[str] = None

    @staticmethod
    def hs256(raw_secret: str) -> "GdwKey":
        """HS256 key from a raw secret string (UTF-8 bytes become key material)."""
        return GdwKey(alg="HS256", k=b64url_utf8(raw_secret))

    @staticmethod
    def hs256_from_bytes(raw: bytes) -> "GdwKey":
        """HS256 key from raw bytes."""
        return GdwKey(alg="HS256", k=b64url_encode(raw))

    def to_json(self) -> dict:
        out: dict[str, Any] = {"alg": self.alg}
        if self.alg == "HS256":
            out["k"] = self.k or ""
        else:
            out["crv"] = self.crv or "P-256"
            out["x"] = self.x or ""
            out["y"] = self.y or ""
            # PROTOTYPE ONLY: mirrors the C++/C#/Rust frameworks, which embed
            # the private scalar in `cnf` so the toy holder-binding check is
            # self-contained. NEVER do this in production — a real `cnf` must
            # carry only the public key and the holder must hold the private
            # half. See SPEC.md §2.4.
            if self.d is not None:
                out["d"] = self.d
        return out

    @staticmethod
    def from_json(j: Any) -> "GdwKey":
        def get(name: str) -> Optional[str]:
            value = gdwjson.get(j, name)
            return value if isinstance(value, str) else None

        return GdwKey(
            alg=get("alg") or "HS256",
            k=get("k"),
            crv=get("crv"),
            x=get("x"),
            y=get("y"),
            d=get("d"),
        )

    def same_secret(self, other: "GdwKey") -> bool:
        """True if both keys carry the same secret material (prototype check)."""
        if self.alg == "HS256":
            return self.k == other.k
        return self.d is not None and self.d == other.d


class Signer:
    """Signing/verifying abstraction, so the HS256 prototype and the ES256
    production path are interchangeable."""

    alg: str = ""

    def sign(self, signing_input: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def verify(self, signing_input: str, signature: str) -> bool:  # pragma: no cover
        raise NotImplementedError


class Hs256Signer(Signer):
    alg = "HS256"

    def __init__(self, key: GdwKey) -> None:
        if key.alg != "HS256":
            raise GdwError(ERR_MALFORMED)
        self._secret = b64url_decode(key.k or "")

    def sign(self, signing_input: str) -> str:
        return b64url_encode(hmac_sha256(self._secret, signing_input.encode("ascii")))

    def verify(self, signing_input: str, signature: str) -> bool:
        expected = hmac_sha256(self._secret, signing_input.encode("ascii"))
        try:
            actual = b64url_decode(signature)
        except GdwError:
            return False
        return constant_time_eq(expected, actual)


def signer_for(key: GdwKey) -> Signer:
    """Build the appropriate signer for a key."""
    if key.alg == "HS256":
        return Hs256Signer(key)
    if key.alg == "ES256":
        # Imported lazily so the core stays dependency-free.
        from .es256 import EcdsaP256Signer

        return EcdsaP256Signer(key)
    raise GdwError(ERR_MALFORMED)
