# EudiGameWallet — Python

A dependency-free Python implementation of the [GDW token
specification](../SPEC.md). Drops into **Panda3D**, **PyGame**, **Ursina**, a
dedicated game server (asyncio), or any Python toolchain, so the same credential
format is spoken on every side.

## Layout

```
python/
  eudi_game_wallet/
    json.py          canonical JSON value (sorted keys, integers only)
    primitives.py    base64url, segments, disclosures, claim-name rules
    key.py           GdwKey + HS256 signer + signer factory
    es256.py         optional ECDSA P-256 signer (needs `cryptography`)
    core.py          decode/parse + Issuer + Wallet + Verifier
    errors.py        the spec error codes
  tests/run_tests.py conformance runner (replays the shared vectors)
  tests/test_units.py small primitive unit tests
  examples/basic_flow.py
```

## Design

* **Dependency-free core.** SHA-256 and HMAC-SHA256 come from the standard
  library (`hashlib` / `hmac`), so a default install needs no third-party
  package and no network. Parsing uses the stdlib `json` module with hooks that
  reject floats and non-canonical integers (`-0`, leading zeros), matching the
  other frameworks; canonical serialisation is our own so key ordering is
  guaranteed.
* **ES256 is opt-in.** `es256.py` uses the `cryptography` package when it is
  importable and otherwise the core still works (HS256 only). Signatures are
  emitted as raw `r || s` (IEEE-P1363), which JWS ES256 requires.
* `GdwKey` is HS256 (shared secret) or ES256 (P-256). `Issuer`, `Wallet` and
  `Verifier` mirror the C++ / C# / GDScript / Rust frameworks;
  `Verifier.verify(...)` returns a `VerifyResult(ok, claims, errors)` and never
  raises for invalid input.

## Run the tests

```bash
cd python
python3 tests/run_tests.py     # 58/58 by default, 61/61 with `cryptography`
python3 tests/test_units.py    # primitive unit tests
```

The conformance runner reads `../test-vectors/vectors.json` (override with the
`GDW_VECTORS` environment variable).

## Run the example

```bash
python3 examples/basic_flow.py
```

```
credential bytes: 709
stored claims:    nickname age_over_18 country

presentation bytes: 914

verified: age_over_18 = true
```

## Panda3D / PyGame integration

The package is pure standard library, so it imports anywhere Python runs. A
typical shape: hold a `Verifier` on the server, keep each player's `Wallet` on
their client, and pass the presentation string over whatever transport the game
already uses (a ShowBase `DirectObject` message, a socket, an HTTP request).

For device-camera capture (scanning a credential QR code), use a capture
library such as `opencv-python` (`cv2.VideoCapture`) plus a QR decoder
(`pyzbar`, OpenCV's `QRCodeDetector`); the token layer here is independent of how
the presentation arrives.

## Security note

HS256 is symmetric — use it only between a trusted issuer and verifier, as in
the prototype. For anything shipped, install `cryptography` and use
`EcdsaP256Signer` (raw `r||s`, P-256). See [SPEC.md §2.4](../SPEC.md).
