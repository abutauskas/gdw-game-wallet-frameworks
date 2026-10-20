#!/usr/bin/env python3
"""Reference implementation + test-vector generator for the Game Digital Wallet (GDW) token.

This script is the executable specification for the three language frameworks
(C++, C#, GDScript). It implements the wire format described in ../SPEC.md and
emits vectors.json, which every framework must pass byte-for-byte.

Usage:
    python3 generate_vectors.py            # writes vectors.json next to this file
    python3 generate_vectors.py --check    # regenerate and diff against existing file
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import sys

# ---------------------------------------------------------------------------
# Base64url (RFC 4648 section 5, no padding)
# ---------------------------------------------------------------------------


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


# ---------------------------------------------------------------------------
# Canonical JSON (JCS-lite subset - see SPEC.md section 2)
#   * object keys sorted by code point (all keys are ASCII in this spec)
#   * integers only, no floats, no exponents
#   * no whitespace
#   * minimal string escaping
# ---------------------------------------------------------------------------

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}

_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def canonical_json(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if not -(2**53) < value < 2**53:
            raise ValueError("integer out of safe range")
        return str(value)
    if isinstance(value, str):
        out = []
        for ch in value:
            if ch in _ESCAPES:
                out.append(_ESCAPES[ch])
            elif ord(ch) < 0x20:
                out.append("\\u%04x" % ord(ch))
            else:
                out.append(ch)
        return '"' + "".join(out) + '"'
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys())
        for k in keys:
            if not isinstance(k, str) or not _NAME_RE.match(k):
                raise ValueError("invalid object key: %r" % (k,))
        parts = [canonical_json(k) + ":" + canonical_json(value[k]) for k in keys]
        return "{" + ",".join(parts) + "}"
    raise TypeError("unsupported JSON value: %s" % type(value))


def _validate(value) -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if not -(2**53) < value < 2**53:
            raise ValueError("integer out of safe range")
        return
    if isinstance(value, float):
        raise ValueError("floats are not allowed in GDW tokens")
    if isinstance(value, list):
        for v in value:
            _validate(v)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str) or not _NAME_RE.match(k):
                raise ValueError("invalid object key: %r" % (k,))
            _validate(v)
        return
    raise TypeError("unsupported JSON value: %s" % type(value))


def json_loads(text: str):
    value = json.loads(text)
    _validate(value)
    return value


def b64u_json(value) -> str:
    return b64u(canonical_json(value).encode("utf-8"))


def b64u_json_decode(text: str):
    return json_loads(b64u_decode(text).decode("utf-8"))


# ---------------------------------------------------------------------------
# HS256 (HMAC-SHA256) - the prototype signature algorithm (SPEC.md section 3)
# ---------------------------------------------------------------------------


def hs256_sign(key_raw: bytes, signing_input: str) -> str:
    return b64u(hmac.new(key_raw, signing_input.encode("ascii"), hashlib.sha256).digest())


def hs256_verify(key_raw: bytes, signing_input: str, signature_b64: str) -> bool:
    expected = hs256_sign(key_raw, signing_input)
    return hmac.compare_digest(expected, signature_b64)


def key_raw(key_obj) -> bytes:
    if key_obj.get("alg") != "HS256":
        raise ValueError("only HS256 keys are supported by the reference generator")
    raw = b64u_decode(key_obj["k"])
    if len(raw) < 32:
        raise ValueError("HS256 keys must be at least 32 bytes")
    return raw


# ---------------------------------------------------------------------------
# JWT-style tokens (SPEC.md section 4)
# ---------------------------------------------------------------------------

ALG = "HS256"
JWT_TYP = "gw+jwt"
KB_TYP = "kb+jwt"
SD_ALG = "sha-256"


def sign_token(key_obj, payload, typ) -> str:
    header = {"alg": ALG, "typ": typ}
    signing_input = b64u_json(header) + "." + b64u_json(payload)
    signature = hs256_sign(key_raw(key_obj), signing_input)
    return signing_input + "." + signature


# ---------------------------------------------------------------------------
# Disclosures (SPEC.md section 5)
# ---------------------------------------------------------------------------


def make_disclosure(salt_b64: str, name: str, value):
    if not _NAME_RE.match(name) or name.startswith("_"):
        raise ValueError("invalid claim name: %r" % (name,))
    if len(b64u_decode(salt_b64)) < 16:
        raise ValueError("salt must decode to at least 16 bytes")
    segment = b64u_json([salt_b64, name, value])
    digest = b64u(hashlib.sha256(segment.encode("ascii")).digest())
    return segment, digest


def parse_disclosure(segment: str):
    arr = b64u_json_decode(segment)
    if (
        not isinstance(arr, list)
        or len(arr) != 3
        or not isinstance(arr[0], str)
        or not isinstance(arr[1], str)
    ):
        raise ValueError("malformed disclosure")
    salt, name, value = arr
    if not _NAME_RE.match(name) or name.startswith("_"):
        raise ValueError("invalid claim name: %r" % (name,))
    if len(b64u_decode(salt)) < 16:
        raise ValueError("salt must decode to at least 16 bytes")
    return salt, name, value


def disclosure_digest(segment: str) -> str:
    return b64u(hashlib.sha256(segment.encode("ascii")).digest())


RESERVED = {"_sd", "_sd_alg", "cnf", "iss", "sub", "iat", "exp", "vct"}


# ---------------------------------------------------------------------------
# Issuance (SPEC.md section 6)
# ---------------------------------------------------------------------------


def issue(
    issuer_key,
    holder_key,
    iss,
    vct,
    claims,
    disclosable,
    iat,
    exp,
    sub=None,
    salts=None,
):
    for name in disclosable:
        if name not in claims:
            raise ValueError("disclosable claim missing from claims: %s" % name)
        if name in RESERVED:
            raise ValueError("cannot make reserved claim disclosable: %s" % name)
    plain = {k: v for k, v in claims.items() if k not in disclosable}

    disclosures = []
    digests = []
    for idx, name in enumerate(disclosable):
        salt = salts[idx] if salts else b64u(_secure_random(16))
        segment, digest = make_disclosure(salt, name, claims[name])
        disclosures.append(segment)
        digests.append(digest)

    payload = {
        "_sd": digests,
        "_sd_alg": SD_ALG,
        "cnf": holder_key,
        "exp": exp,
        "iat": iat,
        "iss": iss,
        "vct": vct,
    }
    if sub is not None:
        payload["sub"] = sub
    payload.update(plain)

    jwt = sign_token(issuer_key, payload, JWT_TYP)
    return "~".join([jwt] + disclosures) + "~"


def parse_credential(credential: str):
    if not credential.endswith("~"):
        raise ValueError("credential string must end with '~'")
    parts = credential.split("~")
    jwt = parts[0]
    disclosures = [p for p in parts[1:-1] if p]
    header = b64u_json_decode(jwt.split(".")[0])
    if header.get("alg") != ALG or header.get("typ") != JWT_TYP:
        raise ValueError("unexpected credential header")
    payload = b64u_json_decode(jwt.split(".")[1])
    return jwt, payload, disclosures


# ---------------------------------------------------------------------------
# Presentation (SPEC.md section 7)
# ---------------------------------------------------------------------------


def presentation_base(credential: str, requested_claims):
    jwt, payload, disclosures = parse_credential(credential)
    by_digest = {}
    for segment in disclosures:
        by_digest[disclosure_digest(segment)] = segment
    selected = []
    derived = {k: v for k, v in payload.items() if k not in RESERVED}
    for name in requested_claims:
        found = None
        for digest in payload.get("_sd", []):
            segment = by_digest.get(digest)
            if segment is None:
                continue
            _, d_name, d_value = parse_disclosure(segment)
            if d_name == name:
                found = (segment, d_value)
                break
        if found is None:
            if name in derived:
                continue  # requestable as a plain (non-disclosable) claim
            raise ValueError("claim not available: %s" % name)
        selected.append(found[0])
        derived[name] = found[1]
    base = "~".join([jwt] + selected)
    return base, payload, selected


def sd_hash_of(base: str) -> str:
    return b64u(hashlib.sha256(base.encode("ascii")).digest())


def present(credential, holder_key, requested_claims, aud, nonce, iat):
    base, payload, _ = presentation_base(credential, requested_claims)
    cnf = payload.get("cnf")
    if not isinstance(cnf, dict):
        raise ValueError("credential has no holder key confirmation (cnf)")
    if cnf.get("k") != holder_key.get("k"):
        raise ValueError("holder key does not match credential cnf")
    kb_payload = {"aud": aud, "iat": iat, "nonce": nonce, "sd_hash": sd_hash_of(base)}
    kb = sign_token(holder_key, kb_payload, KB_TYP)
    return base + "~" + kb


# ---------------------------------------------------------------------------
# Verification (SPEC.md section 8)
# ---------------------------------------------------------------------------

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


class VerifyError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def verify(trust, request, presentation, now, clock_skew=300, require_kb=True, used_nonces=None):
    """Verify a presentation and return {"ok", "claims", "errors"}.

    If `used_nonces` is a set, it is updated on success so the verifier can
    reject replays on the next call.
    """
    try:
        claims = _verify(
            trust=trust,
            request=request,
            presentation=presentation,
            now=now,
            clock_skew=clock_skew,
            require_kb=require_kb,
            used_nonces=used_nonces,
        )
    except VerifyError as err:
        return {"ok": False, "claims": {}, "errors": [err.code]}
    return {"ok": True, "claims": claims, "errors": []}


def _verify(trust, request, presentation, now, clock_skew, require_kb, used_nonces):
    parts = presentation.split("~")
    if len(parts) < 2:
        raise VerifyError(ERR_MALFORMED)
    jwt = parts[0]
    kb = parts[-1] if parts[-1] else None
    disclosures = parts[1:-1] if parts[-1] else parts[1:]

    # 1. Issuer signature
    jwt_parts = jwt.split(".")
    if len(jwt_parts) != 3:
        raise VerifyError(ERR_MALFORMED)
    try:
        header = b64u_json_decode(jwt_parts[0])
        payload = b64u_json_decode(jwt_parts[1])
    except (ValueError, UnicodeDecodeError):
        raise VerifyError(ERR_MALFORMED)
    if header.get("alg") != ALG or header.get("typ") != JWT_TYP:
        raise VerifyError(ERR_MALFORMED)
    if not isinstance(payload, dict):
        raise VerifyError(ERR_MALFORMED)

    iss = payload.get("iss")
    if not isinstance(iss, str) or iss not in trust:
        raise VerifyError(ERR_ISSUER_UNKNOWN)
    if not hs256_verify(key_raw(trust[iss]), jwt_parts[0] + "." + jwt_parts[1], jwt_parts[2]):
        raise VerifyError(ERR_SIGNATURE_INVALID)

    # 2. Validity window + type
    exp = payload.get("exp")
    iat = payload.get("iat")
    if not isinstance(exp, int) or not isinstance(iat, int):
        raise VerifyError(ERR_MALFORMED)
    if now > exp + clock_skew:
        raise VerifyError(ERR_EXPIRED)
    if now < iat - clock_skew:
        raise VerifyError(ERR_NOT_YET_VALID)
    if payload.get("vct") not in request.get("vct", []):
        raise VerifyError(ERR_VCT_NOT_ALLOWED)
    if payload.get("_sd_alg") != SD_ALG or not isinstance(payload.get("_sd"), list):
        raise VerifyError(ERR_MALFORMED)

    # 3. Disclosures -> claims
    claims = {}
    for key, value in payload.items():
        if key not in RESERVED:
            if not _NAME_RE.match(key):
                raise VerifyError(ERR_MALFORMED)
            claims[key] = value

    covered = set(payload["_sd"])
    seen_digests = set()
    for segment in disclosures:
        digest = disclosure_digest(segment)
        if digest not in covered or digest in seen_digests:
            raise VerifyError(ERR_DISCLOSURE_UNKNOWN)
        seen_digests.add(digest)
        try:
            _, name, value = parse_disclosure(segment)
        except (ValueError, UnicodeDecodeError):
            raise VerifyError(ERR_MALFORMED)
        if name in claims:
            raise VerifyError(ERR_DUPLICATE_CLAIM)
        claims[name] = value

    # 4. Requested claims
    for name in request.get("claims", []):
        if name not in claims:
            raise VerifyError(ERR_CLAIM_MISSING)

    # 5. Holder binding (KB-JWT)
    if require_kb:
        if kb is None:
            raise VerifyError(ERR_KB_MISSING)
        kb_parts = kb.split(".")
        if len(kb_parts) != 3:
            raise VerifyError(ERR_MALFORMED)
        try:
            kb_header = b64u_json_decode(kb_parts[0])
            kb_payload = b64u_json_decode(kb_parts[1])
        except (ValueError, UnicodeDecodeError):
            raise VerifyError(ERR_MALFORMED)
        if kb_header.get("alg") != ALG or kb_header.get("typ") != KB_TYP:
            raise VerifyError(ERR_KB_INVALID)
        cnf = payload.get("cnf")
        if not isinstance(cnf, dict) or cnf.get("alg") != ALG or "k" not in cnf:
            raise VerifyError(ERR_KB_INVALID)
        if not hs256_verify(key_raw(cnf), kb_parts[0] + "." + kb_parts[1], kb_parts[2]):
            raise VerifyError(ERR_KB_INVALID)
        base = "~".join([jwt] + disclosures)
        if kb_payload.get("sd_hash") != sd_hash_of(base):
            raise VerifyError(ERR_SD_HASH_MISMATCH)
        if kb_payload.get("aud") != request.get("aud"):
            raise VerifyError(ERR_AUD_MISMATCH)
        if kb_payload.get("nonce") != request.get("nonce"):
            raise VerifyError(ERR_NONCE_MISMATCH)
        kb_iat = kb_payload.get("iat")
        if not isinstance(kb_iat, int) or abs(now - kb_iat) > clock_skew:
            raise VerifyError(ERR_KB_INVALID)
        if used_nonces is not None:
            key = (iss, str(request.get("nonce")))
            if key in used_nonces:
                raise VerifyError(ERR_REPLAY)
            used_nonces.add(key)

    return claims


# ---------------------------------------------------------------------------
# Deterministic entropy for test vectors
# ---------------------------------------------------------------------------

_COUNTER = [0]


def _secure_random(n):
    _COUNTER[0] += 1
    return hashlib.sha256(b"gdw-test-vector-salt:" + str(_COUNTER[0]).encode()).digest()[:n]


# ---------------------------------------------------------------------------
# Vector construction
# ---------------------------------------------------------------------------

ISSUER_URL = "https://issuer.example/age-service"
VCT_AGE = "urn:eudi:game:attestation:age-over-18"
NOW = 1700000000

ISSUER_KEY = {"alg": "HS256", "k": b64u(bytes(range(32)))}
ISSUER_KEY_2 = {"alg": "HS256", "k": b64u(bytes(range(32, 64)))}
HOLDER_KEY = {"alg": "HS256", "k": b64u(bytes(range(100, 132)))}
HOLDER_KEY_2 = {"alg": "HS256", "k": b64u(bytes(range(200, 232)))}

AGE_CLAIMS = {
    "age_over_18": True,
    "age_over_21": False,
    "display_name": "Ada Lovelace",
    "country": "NL",
}
AGE_DISCLOSABLE = ["age_over_18", "age_over_21", "display_name"]

SALT_1 = b64u(bytes(range(16)))
SALT_2 = b64u(bytes(range(16, 32)))
SALT_3 = b64u(bytes(range(32, 48)))


def build_vectors():
    vectors = {
        "version": "0.1",
        "description": "Test vectors for the Game Digital Wallet (GDW) token format.",
        "canonical_json": [
            {
                "name": "sorted-keys-nested",
                "input": {"b": 2, "a": 1, "c": {"z": [True, None, "x"], "y": "ü"}},
                "canonical": None,
            },
            {
                "name": "escapes",
                "input": {"msg": 'line1\nline2\t"quoted" \\ path'},
                "canonical": None,
            },
            {
                "name": "control-characters",
                "input": {"msg": "bell" + chr(7) + "done"},
                "canonical": None,
            },
            {
                "name": "negative-integers",
                "input": {"min": -9007199254740991, "zero": 0},
                "canonical": None,
            },
        ],
        "disclosures": [],
        "hs256": {},
        "issue_flow": {},
        "verify_flow": {},
        "negative_cases": [],
    }

    for case in vectors["canonical_json"]:
        case["canonical"] = canonical_json(case["input"])

    disclosure_cases = [
        ("bool-claim", SALT_1, "age_over_18", True),
        ("string-claim", SALT_2, "display_name", "Ada Lovelace"),
        ("nested-claim", SALT_3, "guild", {"name": "Night Owls", "rank": 3}),
    ]
    for name, salt, claim_name, value in disclosure_cases:
        segment, digest = make_disclosure(salt, claim_name, value)
        vectors["disclosures"].append(
            {
                "name": name,
                "salt_b64": salt,
                "claim_name": claim_name,
                "claim_value": value,
                "segment": segment,
                "digest": digest,
            }
        )

    token_payload = {"exp": NOW + 86400 * 30, "iat": NOW, "iss": ISSUER_URL, "vct": VCT_AGE}
    token = sign_token(ISSUER_KEY, token_payload, JWT_TYP)
    h, p, s = token.split(".")
    vectors["hs256"] = {
        "key": ISSUER_KEY,
        "payload": token_payload,
        "signing_input": h + "." + p,
        "signature": s,
        "token": token,
    }

    # --- issuance ---------------------------------------------------------
    credential = issue(
        ISSUER_KEY,
        HOLDER_KEY,
        ISSUER_URL,
        VCT_AGE,
        AGE_CLAIMS,
        AGE_DISCLOSABLE,
        NOW,
        NOW + 86400 * 30,
        sub="holder-0001",
        salts=[SALT_1, SALT_2, SALT_3],
    )
    jwt, payload, segments = parse_credential(credential)
    vectors["issue_flow"] = {
        "issuer_key": ISSUER_KEY,
        "holder_key": HOLDER_KEY,
        "iss": ISSUER_URL,
        "vct": VCT_AGE,
        "sub": "holder-0001",
        "iat": NOW,
        "exp": NOW + 86400 * 30,
        "claims": AGE_CLAIMS,
        "disclosable": AGE_DISCLOSABLE,
        "salts": [SALT_1, SALT_2, SALT_3],
        "credential": credential,
        "expected_payload": payload,
        "expected_disclosures": [
            {
                "segment": segment,
                "digest": disclosure_digest(segment),
                "claim_name": parse_disclosure(segment)[1],
                "claim_value": parse_disclosure(segment)[2],
            }
            for segment in segments
        ],
    }

    # --- successful presentation -----------------------------------------
    request = {
        "aud": "game-server-eu-1",
        "nonce": b64u(b"nonce-0001" + bytes(5)),
        "vct": [VCT_AGE],
        "claims": ["age_over_18", "display_name"],
        "purpose": "Age-gate matchmaking",
        "expires_at": NOW + 60,
    }
    presentation = present(
        credential,
        HOLDER_KEY,
        request["claims"],
        request["aud"],
        request["nonce"],
        NOW + 10,
    )
    trust = {ISSUER_URL: ISSUER_KEY}
    result = verify(trust, request, presentation, NOW + 15)
    assert result["ok"], result
    vectors["verify_flow"] = {
        "trust": trust,
        "request": request,
        "presentation": presentation,
        "holder_key": HOLDER_KEY,
        "now": NOW + 15,
        "expected": result,
    }

    # --- negative cases ---------------------------------------------------
    neg = []

    def add_case(name, presentation_, request_, now, errors, trust_=None, used=None):
        neg.append(
            {
                "name": name,
                "trust": trust_ if trust_ is not None else trust,
                "request": request_,
                "presentation": presentation_,
                "now": now,
                "used_nonces": sorted(["|".join(pair) for pair in used]) if used else [],
                "expected_errors": errors,
            }
        )

    short_request = {
        "aud": request["aud"],
        "nonce": request["nonce"],
        "vct": [VCT_AGE],
        "claims": ["age_over_18"],
    }

    # expired credential
    expired_cred = issue(
        ISSUER_KEY,
        HOLDER_KEY,
        ISSUER_URL,
        VCT_AGE,
        AGE_CLAIMS,
        AGE_DISCLOSABLE,
        NOW - 86400 * 100,
        NOW - 86400,
        sub="holder-0001",
        salts=[SALT_1, SALT_2, SALT_3],
    )
    expired_pres = present(expired_cred, HOLDER_KEY, ["age_over_18"], request["aud"], request["nonce"], NOW)
    add_case("expired-credential", expired_pres, short_request, NOW, [ERR_EXPIRED])

    # unknown issuer: the credential's iss is absent from the trust list
    add_case(
        "unknown-issuer",
        presentation,
        request,
        NOW + 15,
        [ERR_ISSUER_UNKNOWN],
        trust_={"https://untrusted.example/age-service": ISSUER_KEY},
    )

    # tampered issuer signature
    jwt_p, kb_p = presentation.rsplit("~", 1)
    base_parts = jwt_p.split("~")
    jwt_t = base_parts[0]
    sig = jwt_t.split(".")[2]
    flipped = "A" if sig[-1] != "A" else "B"
    tampered_jwt = jwt_t[: jwt_t.rfind(".")] + "." + sig[:-1] + flipped
    tampered_pres = "~".join([tampered_jwt] + base_parts[1:]) + "~" + kb_p
    add_case("tampered-issuer-signature", tampered_pres, request, NOW + 15, [ERR_SIGNATURE_INVALID])

    # disclosure not listed in _sd
    rogue_segment, _ = make_disclosure(b64u(bytes(range(60, 76))), "is_staff", True)
    rogue_pres = "~".join([jwt_t] + base_parts[1:] + [rogue_segment]) + "~" + kb_p
    add_case("rogue-disclosure", rogue_pres, request, NOW + 15, [ERR_DISCLOSURE_UNKNOWN])

    # wrong audience
    add_case(
        "audience-mismatch",
        presentation,
        dict(request, aud="someone-else"),
        NOW + 15,
        [ERR_AUD_MISMATCH],
    )

    # wrong nonce
    add_case(
        "nonce-mismatch",
        presentation,
        dict(request, nonce=b64u(b"nonce-0002" + bytes(5))),
        NOW + 15,
        [ERR_NONCE_MISMATCH],
    )

    # missing requested claim
    add_case(
        "missing-claim",
        presentation,
        dict(request, claims=["age_over_18", "display_name", "age_over_21"]),
        NOW + 15,
        [ERR_CLAIM_MISSING],
    )

    # wrong credential type
    add_case(
        "vct-not-allowed",
        presentation,
        dict(request, vct=["urn:eudi:game:attestation:guild-member"]),
        NOW + 15,
        [ERR_VCT_NOT_ALLOWED],
    )

    # replayed nonce
    add_case(
        "replayed-nonce",
        presentation,
        request,
        NOW + 15,
        [ERR_REPLAY],
        used={(ISSUER_URL, request["nonce"])},
    )

    # missing holder binding
    add_case("kb-missing", presentation.rsplit("~", 1)[0] + "~", request, NOW + 15, [ERR_KB_MISSING])

    # holder signed with the wrong key
    base_for_wrong, _, _ = presentation_base(credential, request["claims"])
    kb_wrong = sign_token(
        HOLDER_KEY_2,
        {
            "aud": request["aud"],
            "iat": NOW + 10,
            "nonce": request["nonce"],
            "sd_hash": sd_hash_of(base_for_wrong),
        },
        KB_TYP,
    )
    add_case("kb-wrong-key", base_for_wrong + "~" + kb_wrong, request, NOW + 15, [ERR_KB_INVALID])

    # KB binds a different presentation base
    kb_bad_hash = sign_token(
        HOLDER_KEY,
        {
            "aud": request["aud"],
            "iat": NOW + 10,
            "nonce": request["nonce"],
            "sd_hash": b64u(b"not-the-right-hash"),
        },
        KB_TYP,
    )
    add_case("sd-hash-mismatch", base_for_wrong + "~" + kb_bad_hash, request, NOW + 15, [ERR_SD_HASH_MISMATCH])

    vectors["negative_cases"] = neg
    return vectors


def main():
    check = "--check" in sys.argv
    vectors = build_vectors()
    text = json.dumps(vectors, indent=2, ensure_ascii=False) + "\n"
    if check:
        try:
            with open("vectors.json", "r", encoding="utf-8") as fh:
                current = fh.read()
        except FileNotFoundError:
            print("vectors.json missing", file=sys.stderr)
            return 1
        if current != text:
            print("vectors.json is stale - rerun without --check", file=sys.stderr)
            return 1
        print("vectors.json is up to date")
        return 0
    with open("vectors.json", "w", encoding="utf-8") as fh:
        fh.write(text)
    print("wrote vectors.json (%d negative cases)" % len(vectors["negative_cases"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
