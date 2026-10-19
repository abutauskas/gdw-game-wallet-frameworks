"""Stable GDW error codes (SPEC.md §8).

Every failure path in the framework maps to one of these; they are part of the
wire contract and must match the specification and the other language
frameworks byte-for-byte.

SPDX-License-Identifier: CC-BY-4.0
"""

from __future__ import annotations


class GdwError(Exception):
    """A GDW failure carrying one of the stable error codes."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


ERR_MALFORMED = "ERR_MALFORMED"
ERR_SIGNATURE_INVALID = "ERR_SIGNATURE_INVALID"
ERR_ISSUER_UNKNOWN = "ERR_ISSUER_UNKNOWN"
ERR_VCT_NOT_ALLOWED = "ERR_VCT_NOT_ALLOWED"
ERR_EXPIRED = "ERR_EXPIRED"
ERR_NOT_YET_VALID = "ERR_NOT_YET_VALID"
ERR_DISCLOSURE_UNKNOWN = "ERR_DISCLOSURE_UNKNOWN"
ERR_CLAIM_MISSING = "ERR_CLAIM_MISSING"
ERR_DUPLICATE_CLAIM = "ERR_DUPLICATE_CLAIM"
ERR_KB_MISSING = "ERR_KB_MISSING"
ERR_KB_INVALID = "ERR_KB_INVALID"
ERR_AUD_MISMATCH = "ERR_AUD_MISMATCH"
ERR_NONCE_MISMATCH = "ERR_NONCE_MISMATCH"
ERR_SD_HASH_MISMATCH = "ERR_SD_HASH_MISMATCH"
ERR_REPLAY = "ERR_REPLAY"
