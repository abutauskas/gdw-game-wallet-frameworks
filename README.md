# EudiGameWallet — JavaScript / TypeScript

A Node.js implementation of the [GDW token specification](../SPEC.md), shipped
as an npm package with TypeScript declarations. It is byte-for-byte compatible
with the C++, C#, GDScript, Rust, Python and Lua frameworks, so the same
credentials and presentations verify on every side.

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
  types/example.ts   a fully-typed flow, checked by `npm run typecheck`
  test/run_tests.js  conformance runner (replays the shared vectors)
  test/test_units.js small primitive unit tests
  examples/basic_flow.mjs
  package.json
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

## Install / use

```bash
npm install        # dev-only: typescript + @types/node for typechecking
```

```js
const { GdwKey, Issuer, Wallet, Verifier, now } = require('@eudi/gdw-game-wallet');
```

TypeScript consumers get the same API via the shipped `types/index.d.ts`:

```ts
import { GdwKey, Issuer, Verifier } from '@eudi/gdw-game-wallet';
```

## Run the tests

```bash
cd javascript
node test/run_tests.js     # 61/61 (HS256 vectors + ES256 round trip)
node test/test_units.js    # OK
npm run typecheck          # tsc --noEmit
```

The conformance runner reads `../test-vectors/vectors.json`.

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
