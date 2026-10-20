# Game Digital Wallet (GDW) — JavaScript / TypeScript

The Node.js / TypeScript implementation of the [GDW token
specification](../SPEC.md), shipped as an npm package
[`@arasbutauskas/gdw-game-wallet`](https://www.npmjs.com/package/@arasbutauskas/gdw-game-wallet).
It is byte-for-byte compatible with the C++, C#, GDScript, Rust, Python and Lua
frameworks, so the same credentials and presentations verify on every side.

> **This is the JavaScript framework inside the umbrella repository.** The
> package lives in [`javascript/`](.), while [`../SPEC.md`](../SPEC.md) and
> [`../test-vectors/`](../test-vectors/) are shared with the other six ports
> (C++, C#, GDScript, Rust, Python, Lua).

> **Prototype.** The default algorithm is **HS256 (symmetric HMAC)**, safe only
> when the issuer and verifier are the same trusted backend. Not an official EU
> specification and not interoperable with production EUDI Wallets. Read
> [SPEC.md](../SPEC.md) before shipping.

## Install

```bash
npm install @arasbutauskas/gdw-game-wallet
```

No runtime dependencies. TypeScript declarations ship in the package.

## Quick start

```js
const { GdwKey, Issuer, Wallet, Verifier, now } = require('@arasbutauskas/gdw-game-wallet');

// Issuer: sign a credential with selected claims.
const issuer = new Issuer(GdwKey.generate('issuer'), 'https://issuer.example/age-service');
const credential = issuer.issue({
  vct: 'urn:eudi:game:attestation:age-over-18',
  claims: { nickname: 'player42', age_over_18: true, country: 'LV' },
  selectivelyDisclosable: ['nickname', 'age_over_18', 'country'],
});

// Wallet: reveal only what is asked for, bound to a holder key.
const wallet = new Wallet(GdwKey.generate('holder'));
const presentation = wallet.present(credential, ['age_over_18']);

// Verifier: check the presentation against the presented disclosure set.
const verifier = new Verifier({ trustedIssuers: [issuer.publicKey()], now: now() });
const result = verifier.verify(presentation, {
  vct: 'urn:eudi:game:attestation:age-over-18',
  claims: { age_over_18: true },
});
console.log(result.claims); // { age_over_18: true }
```

TypeScript consumers get the same API through the shipped declarations:

```ts
import { GdwKey, Issuer, Verifier } from '@arasbutauskas/gdw-game-wallet';
```

## Run the tests

From this branch's root (no `cd` needed — the package is here):

```bash
cd javascript
make test                  # conformance + unit tests

# or directly:
node test/run_tests.js     # 61/61 (HS256 vectors + ES256 round trip)
node test/test_units.js    # OK
npm run typecheck          # tsc --noEmit
```

The conformance runner replays the shared vectors in `../test-vectors/vectors.json`.

## Run the example

```bash
node examples/basic_flow.mjs
```

```
credential bytes: 709
stored claims:    nickname age_over_18 country
presentation bytes: 914
verified: age_over_18 = true
```

## Layout

```
javascript/
  src/
    index.js         public entry point (CommonJS)
    errors.js        the spec error codes + GdwError
    crypto.js        SHA-256, HMAC-SHA-256, constant-time compare, RNG
    json.js          canonical JSON value + hand-written strict parser
    primitives.js    base64url, segments, disclosures, claim-name rules, salts
    key.js           GdwKey + HS256 signer
    es256.js         optional ES256 (ECDSA P-256) via node:crypto
    core.js          decode/parse + Issuer + Wallet + Verifier
  types/index.d.ts   TypeScript declarations for the public API
  test/
    run_tests.js     conformance runner (replays the shared vectors)
    test_units.js    small primitive unit tests
  examples/
    basic_flow.mjs   runnable Node example
    example.ts       fully-typed flow, checked by `npm run typecheck`
  package.json
../SPEC.md            the normative GDW token specification (shared)
../test-vectors/      the shared vectors every framework must pass
```

## Design

* **No third-party runtime dependencies.** SHA-256, HMAC-SHA-256, base64url and a
  hand-written strict JSON parser ship in `src/`. In Node they use the built-in
  `node:crypto` for speed; when it is unavailable (a bundler targeting the
  browser) they fall back to a self-contained pure-JS SHA-256, so the package
  still works and stays byte-for-byte identical.
* **Strict, canonical JSON.** Objects serialise with keys sorted by code point;
  numbers are integers only. The parser rejects floats, exponents, `-0`, leading
  zeros, integers outside ±(2^53−1) and trailing content, as
  [SPEC.md §2.2](../SPEC.md) requires. An empty array is tagged (`JsonArray`) so
  `[]` round-trips instead of collapsing to `{}`.
* **HS256 and ES256.** HS256 is the dependency-free prototype algorithm. ES256
  (ECDSA P-256) is available through Node's `node:crypto` — signatures are raw
  `r || s` (IEEE-P1363), which is what JWS ES256 requires. `es256.js` is only
  loaded when a key uses `alg === "ES256"`.

## Browser / bundler note

The core (HS256, JSON, base64url) is portable; only `es256.js` depends on
`node:crypto`. When bundling for the browser, mark `node:crypto` external or
alias it, and ES256 keys will fall back to the same "unavailable" path the Lua
and GDScript frameworks use.

## Security note

HS256 is symmetric — use it only between a trusted issuer and verifier, as in
the prototype. The random-salt helper uses the OS CSPRNG (`crypto.randomBytes`,
or `crypto.getRandomValues` in a browser) and **never** a non-cryptographic
fallback. See [SPEC.md §2.4](../SPEC.md) and §3.

## Other languages

| Language | Engine / runtime | Branch |
| --- | --- | --- |
| C++17 | Unreal Engine, any C++ game server | `lang-cpp` |
| C# (.NET 10) | Unity, Godot (.NET), backend | `lang-csharp` |
| GDScript | Godot 4.x (no native deps) | `lang-gdscript` |
| Rust | Bevy, Rust game servers, `wasm32` | `lang-rust` |
| Python | Panda3D, PyGame, Ursina, servers | `lang-python` |
| Lua | Defold, LÖVE (LuaJIT), Lua 5.1+ | `lang-lua` |
| JavaScript / TypeScript | Node, browser bundlers, PlayCanvas/Babylon/Three.js | **this branch** |

All ports replay the same vectors in `../test-vectors/vectors.json`.
