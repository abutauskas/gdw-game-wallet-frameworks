"""Optional ES256 (ECDSA P-256) support, backed by the ``cryptography``
package. The core framework does not import this module unless a key uses
``alg == "ES256"``, so a default install needs no third-party dependency.

Signatures are emitted as raw ``r || s`` (IEEE-P1363 fixed-field
concatenation), which is what JWS ES256 requires — *not* the ASN.1/DER form
``cryptography`` produces by default.

SPDX-License-Identifier: CC-BY-4.0
"""

from __future__ import annotations

from typing import Optional

from . import json as gdwjson
from .errors import ERR_MALFORMED, GdwError
from .key import GdwKey, Signer
from .primitives import b64url_decode, b64url_encode, constant_time_eq

try:  # pragma: no cover - import guard
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA,
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
    )

    _HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTOGRAPHY = False

_FIELD_SIZE = 32  # P-256 coordinates / r / s are 32 bytes


def have_cryptography() -> bool:
    """True if the optional ``cryptography`` package is importable."""
    return _HAVE_CRYPTOGRAPHY


def _require_cryptography() -> None:
    if not _HAVE_CRYPTOGRAPHY:
        raise GdwError(ERR_MALFORMED)


def _b64_to_int(text: Optional[str]) -> int:
    return int.from_bytes(b64url_decode(text or ""), "big")


def _int_to_b64(value: int, size: int = _FIELD_SIZE) -> str:
    return b64url_encode(value.to_bytes(size, "big"))


def _raw_to_der(raw: bytes) -> bytes:
    if len(raw) != 2 * _FIELD_SIZE:
        raise GdwError(ERR_MALFORMED)
    r = int.from_bytes(raw[:_FIELD_SIZE], "big")
    s = int.from_bytes(raw[_FIELD_SIZE:], "big")
    return utils.encode_dss_signature(r, s)


def _der_to_raw(der: bytes) -> bytes:
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(_FIELD_SIZE, "big") + s.to_bytes(_FIELD_SIZE, "big")


class EcdsaP256Signer(Signer):
    alg = "ES256"

    def __init__(self, key: GdwKey) -> None:
        _require_cryptography()
        if key.alg != "ES256":
            raise GdwError(ERR_MALFORMED)
        self._private: Optional[EllipticCurvePrivateKey] = None
        self._public: EllipticCurvePublicKey

        if key.d is not None:
            d = _b64_to_int(key.d)
            if d <= 0:
                raise GdwError(ERR_MALFORMED)
            private = ec.derive_private_key(d, ec.SECP256R1())
            self._private = private
            self._public = private.public_key()
            if key.x is not None and key.y is not None:
                derived = private.public_key().public_numbers()
                if derived.x != _b64_to_int(key.x) or derived.y != _b64_to_int(key.y):
                    raise GdwError(ERR_MALFORMED)
        elif key.x is not None and key.y is not None:
            numbers = ec.EllipticCurvePublicNumbers(
                _b64_to_int(key.x), _b64_to_int(key.y), ec.SECP256R1()
            )
            try:
                self._public = numbers.public_key()
            except ValueError:
                raise GdwError(ERR_MALFORMED)
        else:
            raise GdwError(ERR_MALFORMED)

    def sign(self, signing_input: str) -> str:
        if self._private is None:
            # A verify-only (public) key cannot sign: emit nothing rather than
            # raising, matching the Rust framework's behaviour.
            return ""
        der = self._private.sign(signing_input.encode("ascii"), ECDSA(hashes.SHA256()))
        return b64url_encode(_der_to_raw(der))

    def verify(self, signing_input: str, signature: str) -> bool:
        try:
            der = _raw_to_der(b64url_decode(signature))
        except GdwError:
            return False
        try:
            self._public.verify(der, signing_input.encode("ascii"), ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def generate() -> "tuple[GdwKey, GdwKey]":
        """Return ``(private_key, public_key)`` as :class:`GdwKey` values."""
        _require_cryptography()
        private = ec.generate_private_key(ec.SECP256R1())
        numbers = private.public_key().public_numbers()
        private_key = GdwKey(
            alg="ES256",
            crv="P-256",
            x=_int_to_b64(numbers.x),
            y=_int_to_b64(numbers.y),
            d=_int_to_b64(private.private_numbers().private_value),
        )
        public_key = GdwKey(
            alg="ES256",
            crv="P-256",
            x=_int_to_b64(numbers.x),
            y=_int_to_b64(numbers.y),
        )
        return private_key, public_key
