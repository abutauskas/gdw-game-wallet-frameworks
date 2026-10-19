#!/usr/bin/env python3
"""Small unit tests for the EudiGameWallet Python primitives, mirroring the
``#[cfg(test)]`` modules in the Rust framework and the equivalent tests in the
C++ / C# / GDScript frameworks.

Run::

    python3 tests/test_units.py

SPDX-License-Identifier: CC-BY-4.0
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eudi_game_wallet import GdwError  # noqa: E402
from eudi_game_wallet import json as gdwjson  # noqa: E402
from eudi_game_wallet.primitives import (  # noqa: E402
    b64url_decode,
    b64url_encode,
    disclosure_digest,
    make_disclosure,
)

_FAILURES = 0


def check(condition: bool, label: str) -> None:
    global _FAILURES
    if not condition:
        _FAILURES += 1
        print(f"  FAIL: {label}")


def _rejects(text: str) -> bool:
    try:
        gdwjson.parse(text)
        return False
    except GdwError:
        return True


def main() -> int:
    for length in range(40):
        data = bytes((length * 7 + 3 + i) & 0xFF for i in range(length))
        encoded = b64url_encode(data)
        check("=" not in encoded, f"no padding {length}")
        check(b64url_decode(encoded) == data, f"b64url round trip {length}")

    check(_rejects("1.5"), "rejects float")
    check(_rejects("1e3"), "rejects exponent")
    check(_rejects("-0"), "rejects negative zero")
    check(_rejects("01"), "rejects leading zero")
    check(
        gdwjson.canonical(gdwjson.parse("9007199254740991")) == "9007199254740991",
        "accepts max safe integer",
    )
    check(
        gdwjson.canonical({"b": 2, "a": 1, "c": {"y": "ü"}}) == '{"a":1,"b":2,"c":{"y":"ü"}}',
        "canonical sorts and keeps unicode",
    )
    check(
        gdwjson.canonical(gdwjson.parse('{"a":1,"b":[true,null,"x"]}'))
        == '{"a":1,"b":[true,null,"x"]}',
        "round trip",
    )

    segment = make_disclosure("AAECAwQFBgcICQoLDA0ODw", "age_over_18", True)
    check(
        segment == "WyJBQUVDQXdRRkJnY0lDUW9MREEwT0R3IiwiYWdlX292ZXJfMTgiLHRydWVd",
        "disclosure vector segment",
    )
    check(
        disclosure_digest(segment) == "zhurxLJSJKI_XNO-e_L644W0SwqsTD5LDd3yPwd4ZWs",
        "disclosure vector digest",
    )

    print(f"\n{'OK' if _FAILURES == 0 else str(_FAILURES) + ' FAILED'}")
    return 1 if _FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
