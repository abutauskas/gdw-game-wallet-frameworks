# EudiGameWallet — C++17 (header-only)

A single-header, dependency-free implementation of the [GDW token
specification](../SPEC.md). Drop `include/eudi/gamewallet.hpp` into any C++17
project (Unreal, a dedicated server, a CLI tool) and include it.

```cpp
#include "eudi/gamewallet.hpp"
using namespace eudi::gw;
```

## Design

* `Json` — a small value type with deterministic (canonical) encoding. Objects
  are stored in a `std::map`, so keys are always sorted; this is what makes the
  canonical form reproducible across languages.
* `Key` / `Signer` — `Hs256Signer` (always available) and `EcdsaP256Signer`
  (compiled only when `EUDI_GW_HAS_OPENSSL` is defined; links OpenSSL's
  `libcrypto`).
* `Issuer`, `Wallet`, `Verifier` — the three roles. `Verifier::verify` returns a
  `VerifyResult { ok, claims, errors }` and never throws for invalid input.
* Header-only, no allocation of global state, no exceptions escape the public
  API except `GwError` from the issuing/wallet helpers.

## Build & test

```bash
cmake -S . -B build
cmake --build build
cd build && ctest --output-on-failure
# or run directly:
./wallet_tests ../test-vectors/vectors.json
```

Expected: `61/61 checks passed` (the ES256 round-trip runs only when OpenSSL was
found; without it you get `55/55`).

Requires a C++17 compiler. OpenSSL is optional:

| | without OpenSSL | with OpenSSL (`-lcrypto`, `-DEUDI_GW_HAS_OPENSSL`) |
| --- | --- | --- |
| HS256 | yes | yes |
| ES256 | not compiled | yes |

## Run the example

```bash
./build/basic_flow
```

## Security note

HS256 is symmetric. Use it only when the issuer and verifier share a trusted
backend. For anything shipped, build with OpenSSL and switch to ES256, or swap
`Signer`/`Verifier` for your platform's secure enclave. See
[SPEC.md §2.4](../SPEC.md).
