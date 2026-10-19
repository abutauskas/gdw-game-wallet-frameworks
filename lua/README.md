# EudiGameWallet — Lua

A dependency-free Lua implementation of the [GDW token
specification](../SPEC.md). It targets the Lua game engines — **Defold** and
**LÖVE (love2d)**, both of which run LuaJIT — as well as standard `lua5.1`,
`lua5.2`, `lua5.3` and `lua5.4`, so the same credential format is spoken on every
side.

## Layout

```
lua/
  eudi_game_wallet/
    bit.lua         32-bit bitwise compatibility shim (LuaJIT / 5.1–5.4)
    bit_native.lua   Lua 5.3+ operators (loaded only there)
    bytes.lua        big-endian byte helpers (no string.pack)
    sha256.lua       pure-Lua SHA-256
    hmac.lua         pure-Lua HMAC-SHA256
    base64url.lua    base64url encode/decode
    json.lua         canonical JSON value + hand-written parser
    primitives.lua   segments, disclosures, claim-name rules, random salts
    key.lua          GdwKey + HS256 signer
    core.lua         decode/parse + Issuer + Wallet + Verifier
    errors.lua       the spec error codes
  tests/run_tests.lua  conformance runner (replays the shared vectors)
  tests/test_units.lua small primitive unit tests
  examples/basic_flow.lua
```

## Design

* **Pure Lua, no C dependencies.** SHA-256, HMAC-SHA256, base64url and a small
  JSON parser are implemented in Lua, so a default install needs nothing beyond
  the standard library. Output is byte-for-byte identical to the other
  frameworks, which the shared vectors pin down.
* **Runs everywhere.** Bitwise operations use native operators on Lua 5.3+, the
  `bit` library on LuaJIT / 5.1 / 5.2 (shipped by Defold and LÖVE), and a slow
  pure-Lua fallback otherwise. Because the LuaJIT / 5.1 parser cannot even parse
  `& | ~ << >>`, the native backend lives in `bit_native.lua` and is only loaded
  on 5.3+. Byte handling avoids `string.pack`, which LuaJIT and 5.1 lack.
* **Arrays and `null`.** Lua tables cannot distinguish `[]` from `{}`, so arrays
  are tagged (`json.array`) and JSON `null` is the sentinel `json.null`.
  Numbers are integers only — floats, exponents, `-0` and leading zeros are
  rejected, as [SPEC.md §2.2](../SPEC.md) requires.

### HS256 only

Lua has no built-in asymmetric cryptography and neither Defold nor LÖVE ships
one, so this framework implements **HS256 only** (the dependency-free prototype
algorithm). For asymmetric (production) credentials, either:

* use the [C++](../cpp/), [C#](../csharp/), [Rust](../rust/) or
  [Python](../python/) framework for the signing/verifying side, or
* write a native extension (Defold `extension-*`, a LÖVE C module) that binds
  your platform crypto (Keystore / Keychain / WebCrypto) and exposes a
  `sign`/`verify` pair to Lua.

This is why `key.signer_for()` refuses an ES256 key and the Lua test runner
skips the ES256 round-trip. See [SPEC.md §2.4](../SPEC.md).

## Run the tests

```bash
cd lua
lua    tests/run_tests.lua     # 55/55 (any of the hosts below)
luajit tests/run_tests.lua
lua5.1 tests/run_tests.lua
```

The conformance runner reads `../test-vectors/vectors.json`.

## Run the example

```bash
lua examples/basic_flow.lua
```

```
credential bytes: 709
stored claims:    nickname, age_over_18, country
presentation bytes: 914
verified: age_over_18 = true
```

## Defold / LÖVE integration

Both engines run LuaJIT, so the `bit` backend is used automatically and the
module set drops in as-is: copy `eudi_game_wallet/` next to your scripts and
`require("eudi_game_wallet.core")`. Hold a `Verifier` on the game server and a
`Wallet` on the player's device, and pass the presentation string over whatever
transport the game already uses.

For device-camera capture (scanning a credential QR code), Defold has the
official [`extension-camera`](https://defold.com/extension-camera/); LÖVE has no
built-in camera and needs a custom C/C++ module. The token layer here is
independent of how the presentation arrives.

## Security note

HS256 is symmetric — use it only between a trusted issuer and verifier, as in
the prototype. The random-salt helper reads `/dev/urandom` where available and
otherwise falls back to `math.random`, which is **not** suitable for production.
See [SPEC.md §2.4](../SPEC.md) and §3.
