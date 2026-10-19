# EudiGameWallet — GDScript (Godot 4.x)

A GDScript addon implementing the [GDW token specification](../SPEC.md), with
**no native dependencies** — it uses only Godot's built-in `Crypto`,
`HashingContext`, `Marshalls` and `JSON`.

## Install

Copy `addons/eudi_game_wallet/` into your Godot project's `addons/` folder and
enable **EudiGameWallet** under *Project → Project Settings → Plugins* (or leave
it disabled: the classes are global via `class_name` and work in exported games
either way).

## Classes

| Class | Role |
| --- | --- |
| `GdwUtil` | canonical JSON, base64url, SHA-256, HMAC-SHA256, disclosures (statics) |
| `Gdw` | error codes + token/credential decoding (statics) |
| `GdwKey` | HS256 key (and parsed ES256 key material) |
| `GdwIssuer` | issues credentials |
| `GdwWallet` | stores credentials, produces presentations |
| `GdwVerifier` | verifies presentations, derives claims |

## Run the tests

```bash
cd gdscript
godot --headless --path . --import     # first time only: register global classes
godot --headless --path . --script res://tests/run_tests.gd
```

Expected: `55/55 checks passed`.

> Use an absolute path to the Godot binary if it is not on `PATH`, e.g.
> `~/godot/Godot_v4.5-stable_linux.x86_64 --headless ...`.

## Run the example

```bash
godot --headless --path . --script res://examples/basic_flow.gd
```

## Godot-specific notes

* **Hashing** must use `HashingContext` — `PackedByteArray` has no `.sha256()`
  helper. HMAC is `Crypto.hmac_digest(HashingContext.HASH_SHA256, key, msg)`.
* **base64**: `Marshalls.raw_to_base64` / `base64_to_raw` produce/consume
  standard base64; the addon converts to/from base64url.
* **Numbers**: Godot's `JSON` parses all numbers as `float`. The canonical
  encoder emits them without a fractional part for integral values, matching the
  other frameworks. Non-integer numbers are rejected by the spec.

### ES256 / ES256 is not supported natively

Godot's `Crypto` class exposes **no ECDSA key generation** and **cannot load EC
private keys from PEM**, so this addon implements **HS256 only**. For asymmetric
(production) credentials, either:

* use the [C#](...) or [C++](...) framework for the signing/verifying side, or
* write a **GDExtension** that binds your platform crypto (Keystore / Keychain /
  WebCrypto) and expose a `sign`/`verify` pair to GDScript.

This is why `GdwKey.sign()` refuses to sign an ES256 key and the GDScript test
runner skips the ES256 round-trip. See [SPEC.md §2.4](../SPEC.md).

## Security note

HS256 is symmetric — acceptable only when issuer and verifier are the same
trusted backend, or in a single-player prototype. See [SPEC.md §2.4](../SPEC.md).
