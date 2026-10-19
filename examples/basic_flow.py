#!/usr/bin/env python3
"""Minimal end-to-end flow: an age-over-18 attestation is issued, stored in a
game wallet, selectively disclosed to a matchmaking server, then verified.

Run::

    python3 examples/basic_flow.py

SPDX-License-Identifier: CC-BY-4.0
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eudi_game_wallet import GdwKey, IssueOptions, Issuer, Verifier, Wallet, now  # noqa: E402


def main() -> int:
    # 1. Trust anchors. In production these come from a signed trust list
    #    (see SPEC.md); here we use a shared secret for a self-contained demo.
    issuer_key = GdwKey.hs256("issuer-shared-secret-used-only-for-this-demo")
    player_key = GdwKey.hs256("holder-key-derived-on-the-players-device-----")

    # 2. A PID/attestation provider issues an age attestation to one account.
    age_issuer = Issuer("https://issuer.example/age-service", issuer_key)
    options = IssueOptions(
        vct="urn:eudi:game:attestation:age-over-18",
        sub="player-8241",
        holder_key=player_key,
        iat=now(),
        exp=now() + 30 * 24 * 3600,
        claims={
            "age_over_18": True,
            "country": "NL",
            "nickname": "pixel_knight",
        },
        disclosable=["age_over_18", "country"],
    )
    credential = age_issuer.issue(options)

    print(f"credential bytes: {len(credential)}")
    reader = Wallet(player_key)
    print("stored claims:    " + " ".join(reader.claims_of(credential)))
    print()

    # 3. The player's game wallet stores the credential.
    wallet = Wallet(player_key)
    wallet.store(credential)

    # 4. A matchmaking server (relying party) asks for a single claim and, being
    #    a game backend, wants proof the response is fresh (nonce) and bound to
    #    this holder (key binding, cnf).
    server = Verifier("matchmaking-eu-1")
    server.trust(age_issuer.id, issuer_key)
    request = server.create_request(
        ["urn:eudi:game:attestation:age-over-18"], ["age_over_18"], 60
    )

    # 5. The wallet discloses only what was asked for; nickname/country stay hidden.
    presentation = wallet.present(
        credential,
        ["age_over_18"],
        request["aud"],
        request["nonce"],
        now(),
    )
    print(f"presentation bytes: {len(presentation)}")
    print()

    # 6. The server verifies and reads the derived claims.
    result = server.verify(request, presentation, now())
    if result.ok:
        flag = result.claims.get("age_over_18") is True
        print(f"verified: age_over_18 = {str(flag).lower()}")
        return 0

    print("verification failed: " + " ".join(result.errors))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
