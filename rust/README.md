# EudiGameWallet — Rust / Bevy

A Rust crate implementing the [GDW token specification](../SPEC.md), aimed at
game developers using **Bevy** or a Rust game server (and, via `wasm32`, a
browser build) so the same credential format is spoken on both sides.

## Layout

```
rust/
  src/
    json.rs         canonical JSON value (BTreeMap ordering, integers only)
    crypto.rs       dependency-free SHA-256 + HMAC-SHA256
    primitives.rs   base64url, segments, disclosures, claim-name rules
    key.rs          GdwKey + HS256 signer + signer factory
    wallet.rs       decode/parse + Issuer + Wallet + Verifier
    es256.rs        optional ECDSA P-256 signer (feature `es256`)
    errors.rs       the spec error codes
  tests/vectors.rs  replays ../../test-vectors/vectors.json
  examples/basic_flow.rs
```

## Design

* **Dependency-free core.** SHA-256 and HMAC-SHA256 are implemented in
  `crypto.rs`, so a default build needs no crypto backend and no network. This
  keeps it trivial to embed in a Bevy project and to build offline.
* `Json` stores objects in a `BTreeMap`, so canonical ordering is deterministic
  for free. Parsing rejects floats/exponents and non-canonical integers
  (`-0`, leading zeros), matching the other frameworks.
* `GdwKey` is HS256 (shared secret) or ES256 (P-256). `Issuer`, `Wallet` and
  `Verifier` mirror the C++ / C# / GDScript frameworks; `Verifier::verify`
  returns a `VerifyResult { ok, claims, errors }` and never panics on bad input.

## Build & test

```bash
cargo test                       # 58/58 checks (dependency-free)
cargo test --features es256      # 61/61 checks (adds an ECDSA P-256 round trip)
```

The conformance test reads `../test-vectors/vectors.json` (override with the
`GDW_VECTORS` environment variable).

## Run the example

```bash
cargo run --example basic_flow
```

```
credential bytes: 709
stored claims:    nickname age_over_18 country

presentation bytes: 914

verified: age_over_18 = true
```

## Bevy integration

The crate is pure Rust with no engine dependency, so a Bevy plugin is just a
thin wrapper. A typical shape:

```rust
use bevy::prelude::*;
use eudi_game_wallet::{Verifier, GdwKey};

#[derive(Resource)]
struct WalletVerifier(Verifier);

fn setup(mut commands: Commands, trust: Res<TrustList>) {
    let mut verifier = Verifier::new("matchmaking-eu-1");
    for (issuer, key) in trust.entries() {
        verifier.trust(issuer, key.clone());
    }
    commands.insert_resource(WalletVerifier(verifier));
}

fn verify_presentation(
    mut verifier: ResMut<WalletVerifier>,
    request: Res<PresentationRequest>,
    incoming: EventReader<Presentation>,
) {
    for ev in incoming.read() {
        let result = verifier.0.verify(&request.0, &ev.0, eudi_game_wallet::now());
        // act on result.claims / result.errors
    }
}
```

For device-camera capture (scanning a credential QR code on mobile), use a
crate such as [`nokhwa`](https://crates.io/crates/nokhwa) directly or the
`bevy_webcam` plugin on native / `wasm32` — the token layer here is independent
of how the presentation arrives.

## Security note

HS256 is symmetric — use it only between a trusted issuer and verifier, as in
the prototype. For anything shipped, enable the `es256` feature and use
`EcdsaP256Signer` (raw `r||s`, P-256). See [SPEC.md §2.4](../SPEC.md).
