# EudiGameWallet — C# (.NET)

A dependency-free .NET library implementing the [GDW token
specification](../SPEC.md). Works in Unity (IL2CPP / Mono) and Godot's .NET
build, as well as any .NET service.

## Layout

```
csharp/
  EudiGameWallet/            the library (class library, net10.0)
  Tests/EudiGameWallet.Tests/ console test runner (no test framework needed)
  Examples/BasicFlow/         end-to-end example app
```

## Design

* `GdwJson` — a canonical JSON value. Parsing uses `System.Text.Json`'s reader
  for correct lexing; serialisation is ours so key ordering and integer rules
  are guaranteed.
* `GdwKey` — `Hs256` (shared secret) or `ES256` (P-256). `Hs256Signer` uses
  `HMACSHA256` with a constant-time compare; `EcdsaP256Signer` uses
  `System.Security.Cryptography.ECDsa` with
  `DSASignatureFormat.IeeeP1363FixedFieldConcatenation` (raw `r||s`, as ES256
  requires — not ASN.1/DER).
* `Issuer`, `Wallet`, `Verifier` mirror the C++ and GDScript frameworks.
  `Verifier.Verify(...)` returns a `VerifyResult { Ok, Claims, Errors }` and
  never throws for invalid input.

## Build & test

```bash
dotnet run -c Release --project Tests/EudiGameWallet.Tests -- ../test-vectors/vectors.json
```

Expected: `61/61 checks passed` (includes an ES256 round-trip using a freshly
generated P-256 key — no extra packages required).

## Run the example

```bash
dotnet run -c Release --project Examples/BasicFlow
```

## Unity / Godot (.NET) integration

Reference `EudiGameWallet.csproj`, or copy the sources under
`csharp/EudiGameWallet/` into an asmdef. Everything is pure managed code with no
native dependencies, so it builds for all the usual player targets. For ES256 on
platforms with a hardware keystore, replace `EcdsaP256Signer`'s `ECDsa` instance
with your platform provider.

## Security note

HS256 is symmetric — use it only between a trusted issuer and verifier. Prefer
ES256 for anything shipped. See [SPEC.md §2.4](../SPEC.md).
