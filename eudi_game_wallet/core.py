"""Token decoding + Issuer + Wallet + Verifier (SPEC.md §4–§7).

Mirrors the C++ / C# / GDScript / Rust frameworks exactly, so the same
credentials and presentations verify across all of them.

SPDX-License-Identifier: CC-BY-4.0
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from . import json as gdwjson
from .errors import (
    ERR_AUD_MISMATCH,
    ERR_CLAIM_MISSING,
    ERR_DISCLOSURE_UNKNOWN,
    ERR_DUPLICATE_CLAIM,
    ERR_EXPIRED,
    ERR_ISSUER_UNKNOWN,
    ERR_KB_INVALID,
    ERR_KB_MISSING,
    ERR_MALFORMED,
    ERR_NONCE_MISMATCH,
    ERR_NOT_YET_VALID,
    ERR_REPLAY,
    ERR_SD_HASH_MISMATCH,
    ERR_SIGNATURE_INVALID,
    ERR_VCT_NOT_ALLOWED,
    GdwError,
)
from .key import GdwKey, signer_for
from .primitives import (
    disclosure_digest,
    is_reserved,
    json_segment,
    make_disclosure,
    parse_disclosure,
    parse_segment,
    random_base64url,
    sd_hash,
    split_dot,
    split_tilde,
)


@dataclass
class DecodedToken:
    header: Any
    payload: Any
    signing_input: str
    signature: str
    header_segment: str


def decode_token(token: str) -> DecodedToken:
    parts = split_dot(token)
    if len(parts) != 3:
        raise GdwError(ERR_MALFORMED)
    header = parse_segment(parts[0])
    payload = parse_segment(parts[1])
    if not gdwjson.is_object(header) or not gdwjson.is_object(payload):
        raise GdwError(ERR_MALFORMED)
    return DecodedToken(
        header=header,
        payload=payload,
        signing_input=f"{parts[0]}.{parts[1]}",
        signature=parts[2],
        header_segment=parts[0],
    )


@dataclass
class ParsedCredential:
    token: DecodedToken
    disclosures: list[str]


def parse_credential(credential: str) -> ParsedCredential:
    """Parse a ``gw+jwt ~ disclosure ~ … ~`` credential string."""
    if not credential or not credential.endswith("~"):
        raise GdwError(ERR_MALFORMED)
    parts = split_tilde(credential)
    if len(parts) < 2:
        raise GdwError(ERR_MALFORMED)
    token = decode_token(parts[0])
    if gdwjson.get(token.header, "typ") != "gw+jwt":
        raise GdwError(ERR_MALFORMED)
    disclosures = [p for p in parts[1:] if p]
    return ParsedCredential(token=token, disclosures=disclosures)


# ===========================================================================
# Issuer
# ===========================================================================


@dataclass
class IssueOptions:
    vct: str = ""
    claims: dict[str, Any] = field(default_factory=dict)
    disclosable: list[str] = field(default_factory=list)
    iat: int = 0
    exp: int = 0
    sub: str = ""
    holder_key: GdwKey = field(default_factory=GdwKey)
    salts: list[str] = field(default_factory=list)
    extra_payload: dict[str, Any] = field(default_factory=dict)


class Issuer:
    def __init__(self, iss: str, issuer_key: GdwKey) -> None:
        self._signer = signer_for(issuer_key)
        self._iss = iss
        self._alg = issuer_key.alg

    @property
    def id(self) -> str:
        return self._iss

    def issue(self, options: IssueOptions) -> str:
        if options.iat == 0 or options.exp == 0 or not options.vct:
            raise GdwError(ERR_MALFORMED)
        for name in options.disclosable:
            if name not in options.claims or is_reserved(name):
                raise GdwError(ERR_MALFORMED)

        disclosures: list[str] = []
        sd: list[str] = []
        for i, name in enumerate(options.disclosable):
            salt = options.salts[i] if i < len(options.salts) else random_base64url(16)
            if name not in options.claims:
                raise GdwError(ERR_MALFORMED)
            value = options.claims[name]
            segment = make_disclosure(salt, name, value)
            disclosures.append(segment)
            sd.append(disclosure_digest(segment))

        payload: dict[str, Any] = {
            "_sd": sd,
            "_sd_alg": "sha-256",
            "cnf": options.holder_key.to_json(),
            "exp": options.exp,
            "iat": options.iat,
            "iss": self._iss,
            "vct": options.vct,
        }
        if options.sub:
            payload["sub"] = options.sub

        for key, value in options.claims.items():
            if key in options.disclosable:
                continue
            if key in payload:
                raise GdwError(ERR_MALFORMED)
            payload[key] = value
        for key, value in options.extra_payload.items():
            if key in payload:
                raise GdwError(ERR_MALFORMED)
            payload[key] = value

        header = {"alg": self._alg, "typ": "gw+jwt"}
        signing_input = f"{json_segment(header)}.{json_segment(payload)}"
        jwt = f"{signing_input}.{self._signer.sign(signing_input)}"

        return jwt + "".join("~" + d for d in disclosures) + "~"


# ===========================================================================
# Wallet (holder)
# ===========================================================================


class Wallet:
    def __init__(self, holder_key: GdwKey) -> None:
        self._key = holder_key
        self._signer = signer_for(holder_key)
        self._credentials: list[str] = []

    @property
    def credentials(self) -> list[str]:
        return self._credentials

    def store(self, credential: str) -> None:
        parse_credential(credential)
        self._credentials.append(credential)

    def claims_of(self, credential: str) -> list[str]:
        """Names of the claims a credential carries (plaintext + disclosable)."""
        parsed = parse_credential(credential)
        names: list[str] = []
        for key, _ in gdwjson.entries(parsed.token.payload):
            if not is_reserved(key):
                names.append(key)
        for segment in parsed.disclosures:
            names.append(parse_disclosure(segment).name)
        return names

    def present(
        self,
        credential: str,
        requested_claims: list[str],
        aud: str,
        nonce: str,
        issued_at: int,
    ) -> str:
        """Build a presentation revealing only ``requested_claims``, with a key
        binding."""
        parsed = parse_credential(credential)

        by_digest: dict[str, str] = {
            disclosure_digest(segment): segment for segment in parsed.disclosures
        }

        selected: list[str] = []
        sd = gdwjson.get(parsed.token.payload, "_sd")
        for name in requested_claims:
            if not is_reserved(name) and gdwjson.has(parsed.token.payload, name):
                continue  # plaintext claim is always revealed
            found = False
            if gdwjson.is_array(sd):
                for digest in sd:
                    if not isinstance(digest, str):
                        continue
                    segment = by_digest.get(digest)
                    if segment is not None and parse_disclosure(segment).name == name:
                        selected.append(segment)
                        found = True
                        break
            if not found:
                raise GdwError(ERR_CLAIM_MISSING)

        base_text = parsed.token.signing_input + "." + parsed.token.signature
        for segment in selected:
            base_text += "~" + segment

        cnf = gdwjson.get(parsed.token.payload, "cnf")
        if gdwjson.is_object(cnf):
            cnf_key = GdwKey.from_json(cnf)
            if not cnf_key.same_secret(self._key):
                raise GdwError(ERR_KB_INVALID)

        kb = {
            "aud": aud,
            "iat": issued_at,
            "nonce": nonce,
            "sd_hash": sd_hash(base_text),
        }
        header = {"alg": self._signer.alg, "typ": "kb+jwt"}
        signing_input = f"{json_segment(header)}.{json_segment(kb)}"
        kb_jwt = f"{signing_input}.{self._signer.sign(signing_input)}"
        return f"{base_text}~{kb_jwt}"


# ===========================================================================
# Verifier (relying party)
# ===========================================================================


@dataclass
class VerifyResult:
    ok: bool
    claims: Any
    errors: list[str]


class Verifier:
    def __init__(self, aud: str) -> None:
        self._aud = aud
        self._trust: dict[str, GdwKey] = {}
        self._used_nonces: set[str] = set()
        self._clock_skew = 300

    def set_clock_skew(self, skew: int) -> None:
        self._clock_skew = skew

    def trust(self, issuer: str, key: GdwKey) -> None:
        self._trust[issuer] = key

    def mark_nonce_used(self, iss: str, nonce: str) -> None:
        self._used_nonces.add(f"{iss}|{nonce}")

    def create_request(self, vct: list[str], claims: list[str], ttl_seconds: int) -> dict:
        current = now()
        return {
            "aud": self._aud,
            "nonce": random_base64url(16),
            "vct": list(vct),
            "claims": list(claims),
            "iat": current,
            "expires_at": current + ttl_seconds,
        }

    def verify(self, request: Any, presentation: str, current_time: int) -> VerifyResult:
        """Verify a presentation. Never raises for bad input; returns
        ``ok=False`` with a single error code."""
        try:
            claims = self._verify_internal(request, presentation, current_time)
            return VerifyResult(ok=True, claims=claims, errors=[])
        except GdwError as error:
            return VerifyResult(ok=False, claims={}, errors=[error.code])

    def _verify_internal(self, request: Any, presentation: str, current_time: int) -> dict:
        parts = split_tilde(presentation)
        if len(parts) < 2:
            raise GdwError(ERR_MALFORMED)

        jwt = parts[0]
        has_kb = bool(parts[-1])
        kb_jwt = parts[-1] if has_kb else ""
        end = len(parts) - 1 if has_kb else len(parts)
        disclosures = [p for p in parts[1:end] if p]

        token = decode_token(jwt)
        if gdwjson.get(token.header, "typ") != "gw+jwt":
            raise GdwError(ERR_MALFORMED)

        iss = gdwjson.get(token.payload, "iss")
        if not isinstance(iss, str) or not iss:
            raise GdwError(ERR_MALFORMED)
        trusted = self._trust.get(iss)
        if trusted is None:
            raise GdwError(ERR_ISSUER_UNKNOWN)
        if gdwjson.get(token.header, "alg") != trusted.alg:
            raise GdwError(ERR_MALFORMED)
        issuer_signer = signer_for(trusted)
        if not issuer_signer.verify(token.signing_input, token.signature):
            raise GdwError(ERR_SIGNATURE_INVALID)

        exp = gdwjson.as_int(gdwjson.get(token.payload, "exp"))
        iat = gdwjson.as_int(gdwjson.get(token.payload, "iat"))
        if exp is None or iat is None or exp < 0 or iat < 0:
            raise GdwError(ERR_MALFORMED)
        if current_time > exp + self._clock_skew:
            raise GdwError(ERR_EXPIRED)
        if current_time < iat - self._clock_skew:
            raise GdwError(ERR_NOT_YET_VALID)

        vct = gdwjson.get(token.payload, "vct") or ""
        allowed = gdwjson.get(request, "vct")
        vct_allowed = gdwjson.is_array(allowed) and any(v == vct for v in allowed)
        if not vct_allowed:
            raise GdwError(ERR_VCT_NOT_ALLOWED)

        if gdwjson.get(token.payload, "_sd_alg") != "sha-256":
            raise GdwError(ERR_MALFORMED)
        sd = gdwjson.get(token.payload, "_sd")
        if not gdwjson.is_array(sd):
            raise GdwError(ERR_MALFORMED)

        claims: dict[str, Any] = {}
        for key, value in gdwjson.entries(token.payload):
            if not is_reserved(key):
                claims[key] = value

        covered = [d for d in sd if isinstance(d, str)]
        seen: set[str] = set()
        for segment in disclosures:
            digest = disclosure_digest(segment)
            if digest not in covered or digest in seen:
                raise GdwError(ERR_DISCLOSURE_UNKNOWN)
            seen.add(digest)
            parsed = parse_disclosure(segment)
            if parsed.name in claims:
                raise GdwError(ERR_DUPLICATE_CLAIM)
            claims[parsed.name] = parsed.value

        required = gdwjson.get(request, "claims")
        if gdwjson.is_array(required):
            for name in required:
                if isinstance(name, str) and name not in claims:
                    raise GdwError(ERR_CLAIM_MISSING)

        # ---- key binding ----
        if not kb_jwt:
            raise GdwError(ERR_KB_MISSING)
        kb_token = decode_token(kb_jwt)
        if gdwjson.get(kb_token.header, "typ") != "kb+jwt":
            raise GdwError(ERR_KB_INVALID)
        cnf = gdwjson.get(token.payload, "cnf")
        if not gdwjson.is_object(cnf):
            raise GdwError(ERR_KB_INVALID)
        cnf_key = GdwKey.from_json(cnf)
        if gdwjson.get(kb_token.header, "alg") != cnf_key.alg:
            raise GdwError(ERR_KB_INVALID)
        kb_signer = signer_for(cnf_key)
        if not kb_signer.verify(kb_token.signing_input, kb_token.signature):
            raise GdwError(ERR_KB_INVALID)

        base_text = jwt
        for segment in disclosures:
            base_text += "~" + segment
        if gdwjson.get(kb_token.payload, "sd_hash") != sd_hash(base_text):
            raise GdwError(ERR_SD_HASH_MISMATCH)
        if gdwjson.get(kb_token.payload, "aud") != gdwjson.get(request, "aud"):
            raise GdwError(ERR_AUD_MISMATCH)
        if gdwjson.get(kb_token.payload, "nonce") != gdwjson.get(request, "nonce"):
            raise GdwError(ERR_NONCE_MISMATCH)

        kb_iat = gdwjson.as_int(gdwjson.get(kb_token.payload, "iat"))
        if (
            kb_iat is None
            or kb_iat < 0
            or current_time > kb_iat + self._clock_skew
            or current_time < kb_iat - self._clock_skew
        ):
            raise GdwError(ERR_KB_INVALID)

        nonce_key = f"{iss}|{gdwjson.get(request, 'nonce') or ''}"
        if nonce_key in self._used_nonces:
            raise GdwError(ERR_REPLAY)
        self._used_nonces.add(nonce_key)

        return claims


def now() -> int:
    """Current unix time in seconds."""
    return int(time.time())
