"""Shared primitives: base64url, canonical JSON segments, disclosure
construction/parsing, random salting, claim-name rules (SPEC.md §2, §3).

SHA-256 and HMAC-SHA256 come from the standard library (:mod:`hashlib` and
:mod:`hmac`), so the package needs no third-party dependency and no crypto
backend, while staying byte-for-byte identical to the other frameworks.

SPDX-License-Identifier: CC-BY-4.0
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Any

from . import json as gdwjson
from .errors import ERR_MALFORMED, GdwError

_STD_TO_URL = bytes.maketrans(b"+/", b"-_")
_URL_TO_STD = bytes.maketrans(b"-_", b"+/")
_RESERVED = frozenset({"_sd", "_sd_alg", "cnf", "iss", "sub", "iat", "exp", "vct"})


def b64url_encode(data: bytes) -> str:
    """base64url (RFC 4648 §5) without padding."""
    return base64.b64encode(data).translate(_STD_TO_URL).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode base64url without padding."""
    if not isinstance(text, str):
        raise GdwError(ERR_MALFORMED)
    remainder = len(text) % 4
    if remainder == 1:
        raise GdwError(ERR_MALFORMED)
    try:
        raw = text.encode("ascii")
    except UnicodeEncodeError:
        raise GdwError(ERR_MALFORMED)
    translated = raw.translate(_URL_TO_STD)
    padded = translated + b"=" * (-len(translated) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (ValueError, binascii.Error):
        raise GdwError(ERR_MALFORMED)


def b64url_utf8(text: str) -> str:
    return b64url_encode(text.encode("utf-8"))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(secret: bytes, data: bytes) -> bytes:
    return hmac.new(secret, data, hashlib.sha256).digest()


def constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def json_segment(value: Any) -> str:
    """Canonicalise a JSON value and base64url-encode the UTF-8 bytes."""
    return b64url_encode(gdwjson.canonical(value).encode("utf-8"))


def parse_segment(segment: str) -> Any:
    """Decode a base64url segment and parse it as JSON."""
    try:
        text = b64url_decode(segment).decode("utf-8")
    except UnicodeDecodeError:
        raise GdwError(ERR_MALFORMED)
    return gdwjson.parse(text)


# ---- claim names ----------------------------------------------------------


def is_valid_claim_name(name: str) -> bool:
    """A valid disclosure claim name: ``^[A-Za-z0-9_-]{1,64}$``, not leading `_`."""
    if not name or len(name) > 64 or name[0] == "_":
        return False
    return all(c.isascii() and (c.isalnum() or c in "_-") for c in name)


def is_reserved(name: str) -> bool:
    return name in _RESERVED


# ---- disclosures ----------------------------------------------------------


def make_disclosure(salt_b64: str, name: str, value: Any) -> str:
    """Build a disclosure segment from a salt, claim name and value."""
    if not is_valid_claim_name(name):
        raise GdwError(ERR_MALFORMED)
    if len(b64url_decode(salt_b64)) < 16:
        raise GdwError(ERR_MALFORMED)
    return json_segment([salt_b64, name, value])


@dataclass
class ParsedDisclosure:
    salt: str
    name: str
    value: Any


def parse_disclosure(segment: str) -> ParsedDisclosure:
    arr = parse_segment(segment)
    if not isinstance(arr, list) or len(arr) != 3:
        raise GdwError(ERR_MALFORMED)
    if not isinstance(arr[0], str) or not isinstance(arr[1], str):
        raise GdwError(ERR_MALFORMED)
    salt, name, value = arr
    if not is_valid_claim_name(name):
        raise GdwError(ERR_MALFORMED)
    if len(b64url_decode(salt)) < 16:
        raise GdwError(ERR_MALFORMED)
    return ParsedDisclosure(salt=salt, name=name, value=value)


def disclosure_digest(segment: str) -> str:
    """SHA-256 digest of the disclosure *segment*, base64url-encoded."""
    return b64url_encode(sha256(segment.encode("ascii")))


def sd_hash(base_text: str) -> str:
    """SHA-256 digest of a presentation base string, base64url-encoded."""
    return b64url_encode(sha256(base_text.encode("ascii")))


# ---- random salts ---------------------------------------------------------


def random_base64url(num_bytes: int) -> str:
    """Cryptographically-random base64url string of ``num_bytes`` bytes.

    Uses :func:`os.urandom` (the OS CSPRNG). Salts must be unpredictable in
    production — see SPEC.md §3.
    """
    return b64url_encode(os.urandom(num_bytes))


def split_tilde(text: str) -> list[str]:
    return text.split("~")


def split_dot(text: str) -> list[str]:
    return text.split(".")
