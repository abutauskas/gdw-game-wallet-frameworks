#!/usr/bin/env python3
"""Conformance tests for the EudiGameWallet Python framework.

Replays ``frameworks/test-vectors/vectors.json`` byte-for-byte. Run::

    python3 tests/run_tests.py [path/to/vectors.json]

The path defaults to ``../test-vectors/vectors.json`` (relative to this file)
and can also be overridden with the ``GDW_VECTORS`` environment variable.

SPDX-License-Identifier: CC-BY-4.0
"""

from __future__ import annotations

import os
import sys

import json as stdjson

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eudi_game_wallet import (  # noqa: E402
    GdwKey,
    IssueOptions,
    Issuer,
    Verifier,
    Wallet,
    parse_credential,
    signer_for,
)
from eudi_game_wallet import json as gdwjson  # noqa: E402
from eudi_game_wallet.primitives import (  # noqa: E402
    disclosure_digest,
    make_disclosure,
    parse_disclosure,
)

_STATE = {"checks": 0, "failures": 0}





def check(condition: bool, label: str) -> None:
    _STATE["checks"] += 1
    if not condition:
        _STATE["failures"] += 1
        print(f"  FAIL: {label}")


def check_eq(actual, expected, label: str) -> None:
    _STATE["checks"] += 1
    if actual != expected:
        _STATE["failures"] += 1
        print(f"  FAIL: {label}")
        print(f"    expected: {expected}")
        print(f"    actual:   {actual}")


def load_vectors() -> dict:
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.environ.get("GDW_VECTORS"),
        os.path.join(here, "..", "test-vectors", "vectors.json"),
        os.path.join(here, "..", "..", "test-vectors", "vectors.json"),
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            with open(candidate, "r", encoding="utf-8") as handle:
                return stdjson.load(handle)
    raise SystemExit("could not find vectors.json (set GDW_VECTORS)")


def canonical(value) -> str:
    return gdwjson.canonical(value)


def run() -> int:
    vectors = load_vectors()

    # ---- canonical JSON ---------------------------------------------------
    print("canonical JSON")
    for case in vectors["canonical_json"]:
        name = case["name"]
        expected = case["canonical"]
        inp = gdwjson.parse(stdjson.dumps(case["input"]))
        check_eq(canonical(inp), expected, name)
        check_eq(canonical(gdwjson.parse(expected)), expected, f"{name} (round trip)")

    # ---- disclosures ------------------------------------------------------
    print("disclosures")
    for case in vectors["disclosures"]:
        name = case["name"]
        segment = make_disclosure(case["salt_b64"], case["claim_name"], case["claim_value"])
        check_eq(segment, case["segment"], f"{name} segment")
        check_eq(disclosure_digest(segment), case["digest"], f"{name} digest")
        parsed = parse_disclosure(segment)
        check_eq(parsed.name, case["claim_name"], f"{name} parsed name")
        check_eq(canonical(parsed.value), canonical(case["claim_value"]), f"{name} parsed value")

    # ---- HS256 ------------------------------------------------------------
    print("HS256")
    hs = vectors["hs256"]
    signer = signer_for(GdwKey.from_json(hs["key"]))
    check_eq(signer.sign(hs["signing_input"]), hs["signature"], "signature")
    check(signer.verify(hs["signing_input"], hs["signature"]), "verify")
    check(
        not signer.verify(hs["signing_input"], hs["signature"] + "x"),
        "verify rejects tamper",
    )

    # ---- issue flow -------------------------------------------------------
    print("issue flow")
    flow = vectors["issue_flow"]
    issuer = Issuer(flow["iss"], GdwKey.from_json(flow["issuer_key"]))
    options = IssueOptions(
        vct=flow["vct"],
        iat=flow["iat"],
        exp=flow["exp"],
        sub=flow.get("sub", ""),
        holder_key=GdwKey.from_json(flow["holder_key"]),
        claims=dict(flow["claims"]),
        disclosable=list(flow["disclosable"]),
        salts=list(flow["salts"]),
    )
    credential = issuer.issue(options)
    check_eq(credential, flow["credential"], "credential string")

    parsed = parse_credential(credential)
    check_eq(canonical(parsed.token.payload), canonical(flow["expected_payload"]), "payload")
    expected_disclosures = flow["expected_disclosures"]
    check(len(parsed.disclosures) == len(expected_disclosures), "disclosure count")
    for i, expected in enumerate(expected_disclosures):
        if i >= len(parsed.disclosures):
            break
        check_eq(parsed.disclosures[i], expected["segment"], f"disclosure segment {i}")
        check_eq(
            disclosure_digest(parsed.disclosures[i]),
            expected["digest"],
            f"disclosure digest {i}",
        )

    # ---- verify flow ------------------------------------------------------
    print("verify flow")
    flow = vectors["verify_flow"]
    request = flow["request"]
    verifier = Verifier(request["aud"])
    for iss, k in flow["trust"].items():
        verifier.trust(iss, GdwKey.from_json(k))
    result = verifier.verify(request, flow["presentation"], flow["now"])
    check(result.ok, "verification succeeds")
    if not result.ok:
        for error in result.errors:
            print(f"    error: {error}")
    check_eq(canonical(result.claims), canonical(flow["expected"]["claims"]), "derived claims")

    # ---- negative cases ---------------------------------------------------
    print("negative cases")
    for case in vectors["negative_cases"]:
        name = case["name"]
        request = case["request"]
        verifier = Verifier(request["aud"])
        for iss, k in case["trust"].items():
            verifier.trust(iss, GdwKey.from_json(k))
        for seed in case["used_nonces"]:
            iss, _, nonce = seed.partition("|")
            verifier.mark_nonce_used(iss, nonce)
        result = verifier.verify(request, case["presentation"], case["now"])
        expected = case["expected_errors"]
        check(result.ok == (len(expected) == 0), f"{name} ok flag")
        if not result.ok and expected:
            check_eq(result.errors[0], expected[0], f"{name} error code")

    # ---- ES256 end-to-end (only when `cryptography` is available) ---------
    from eudi_game_wallet import es256 as _es256

    if not _es256.have_cryptography():
        print("ES256 round trip (skipped: `cryptography` not installed)")
    else:
        EcdsaP256Signer = _es256.EcdsaP256Signer
        print("ES256 round trip")
        issuer_priv, issuer_pub = EcdsaP256Signer.generate()
        holder_priv, _holder_pub = EcdsaP256Signer.generate()

        issuer = Issuer("https://issuer.example/es256", issuer_priv)
        options = IssueOptions(
            vct="urn:eudi:game:attestation:guild-member",
            iat=0,
            exp=0,
            holder_key=holder_priv,
            claims={"guild": "Night Owls", "rank": 3},
            disclosable=["rank"],
        )
        from eudi_game_wallet import now as gw_now

        options.iat = gw_now()
        options.exp = gw_now() + 3600
        credential = issuer.issue(options)

        wallet = Wallet(holder_priv)
        wallet.store(credential)

        verifier = Verifier("game-server-eu-1")
        verifier.trust("https://issuer.example/es256", issuer_pub)
        request = verifier.create_request(
            ["urn:eudi:game:attestation:guild-member"], ["guild", "rank"], 60
        )
        presentation = wallet.present(
            credential,
            ["guild", "rank"],
            request["aud"],
            request["nonce"],
            gw_now(),
        )
        result = verifier.verify(request, presentation, gw_now())
        check(result.ok, "ES256 verification succeeds")
        if result.ok:
            check_eq(result.claims.get("guild"), "Night Owls", "guild claim")
            check(result.claims.get("rank") == 3, "rank claim")
        else:
            for error in result.errors:
                print(f"    error: {error}")

    total = _STATE["checks"]
    failures = _STATE["failures"]
    print(f"\n{total - failures}/{total} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
