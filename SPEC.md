# Game Digital Wallet (GDW) Token Specification

**Status:** prototype / learning framework, version 0.1

This document specifies the wire format implemented by the three game-engine
frameworks in this folder ([C++](cpp/), [C#](csharp/), [GDScript](gdscript/)).
It is a *simplified, game-friendly profile* inspired by the EUDI Wallet
Architecture and Reference Framework (ARF) — specifically by the selective
disclosure credential model of SD-JWT VC (ARF §5.4.3) — reduced to the parts
that are useful and teachable for game developers.

It is **not** an official EU specification and **not** interoperable with
production EUDI Wallets. The goal is to let game studios prototype
verifiable-identity features (age gating, portable entitlements, guild
membership, tournament passes) with a tiny, dependency-free token that works
identically in Unreal/Unity/Godot and on game servers.

---

## 1. Concepts and ARF mapping

| GDW term | Meaning in a game | ARF counterpart |
| --- | --- | --- |
| **Wallet** | Player-side store of credentials (save file, cloud profile) | Wallet Unit |
| **Credential** | A signed bundle of claims, e.g. "age over 18" | Attestation / EAA (SD-JWT VC) |
| **Issuer** | Who vouches for the claims (platform holder, age check provider, your studio backend) | PID / Attestation Provider |
| **Verifier (RP)** | Who asks for proof (matchmaker, game server, storefront) | Relying Party instance |
| **Request** | What the verifier asks for and why | Presentation request (OpenID4VP-style) |
| **Presentation** | The answer: a JWT plus only the requested disclosures plus a key-binding proof | Presentation / VP |
| **Trust store** | The list of issuers your verifier believes | Trusted List / LoTE |
| **Holder key** | A per-device key proving the credential was not copied | Device binding / `cnf` key |

### Why selective disclosure?

A credential may contain many attributes (age flags, real name, country, rank),
but a request should reveal only what the verifier needs. GDW does this the
same way SD-JWT does: each disclosable attribute is stored as a salted
*disclosure* whose SHA-256 hash appears in the signed payload. The verifier
checks "this disclosure hash was signed by the issuer" and never sees the
attributes that were not disclosed.

---

## 2. Encoding rules

### 2.1 base64url

All binary/text segments are encoded with **base64url without padding**
(RFC 4648 §5, alphabet `A–Z a-z 0–9 - _`, `=` stripped).

### 2.2 Canonical JSON

Every JSON object that is hashed or signed is serialised with this deterministic
subset of JSON Canonicalization:

1. Object keys are sorted ascending by Unicode code point (all keys in this
   spec match `^[A-Za-z0-9_-]{1,64}$`, so this is plain ASCII order).
2. No whitespace anywhere.
3. Numbers must be **integers** in the safe range `-(2^53-1) … 2^53-1`.
   Floats, exponents and `-0` are forbidden. Use strings for non-integers.
4. Strings escape only what JSON requires: `"` → `\"`, `\` → `\\`, and the
   short forms `\b \t \n \f \r`; other code points below U+0020 are written as
   `\u00xx` with **lowercase** hex. All other characters (including non-ASCII)
   are emitted as raw UTF-8.
5. `null`, `true`, `false` use their standard literals. Arrays keep order.

### 2.3 Hash

`SHA-256` (FIPS 180-4). Digests are base64url-encoded (32 bytes → 43 chars).

### 2.4 Keys

A **key** is a JSON object:

```json
{"alg": "HS256", "k": "<base64url raw key material, >= 32 bytes>"}
```

`HS256` is HMAC-SHA256 (RFC 2104). It is the **prototype** algorithm of this
framework: it is deterministic, dependency-free, and identical in all three
languages, which makes cross-language test vectors possible.

> **Production warning.** HS256 is symmetric: anyone holding the key can both
> sign and verify. That is fine inside a trusted prototype (issuer and
> verifier are both your backend) but wrong for shipping. Before production,
> swap the `Signer`/`Verifier` abstraction for **ES256** (ECDSA P-256):
> ready-made implementations ship in the C# framework (`EcdsaP256Signer`) and
> the C++ framework (`EcdsaP256Signer`, needs OpenSSL); in GDScript use a
> GDExtension that binds your platform crypto.

### 2.5 JWT-style tokens

```
token = b64url(canonical(header)) "." b64url(canonical(payload)) "." b64url(signature)
signing_input = b64url(canonical(header)) "." b64url(canonical(payload))
signature     = HS256(key, ASCII(signing_input))
```

Headers:

| typ | used for | header |
| --- | --- | --- |
| `gw+jwt` | the credential itself | `{"alg":"HS256","typ":"gw+jwt"}` |
| `kb+jwt` | holder key binding | `{"alg":"HS256","typ":"kb+jwt"}` |

---

## 3. Disclosures

A disclosure hides one attribute value:

```
disclosure_array = [salt, claim_name, claim_value]
segment          = b64url(canonical(disclosure_array))
digest           = b64url(SHA-256(ASCII(segment)))
```

* `salt` — base64url of **at least 16 random bytes** (different salts for
  equal values prevent correlating attributes across credentials).
* `claim_name` — matches `^[A-Za-z0-9_-]{1,64}$`, must not start with `_`.
* `claim_value` — any canonical-JSON value.

---

## 4. Credential (issuance)

**Compact form:**

```
credential = gw+jwt "~" disclosure_1 "~" disclosure_2 "~" ... "~"
```

(The trailing `~` follows SD-JWT convention: it is the slot the holder later
fills with disclosures and the key-binding token.)

**Payload of the `gw+jwt`:**

| field | type | meaning |
| --- | --- | --- |
| `iss` | string | issuer id (URL or your namespace) |
| `vct` | string | verifiable credential type, e.g. `urn:eudi:game:attestation:age-over-18` |
| `iat` | int | issued-at (unix seconds) |
| `exp` | int | expiry (unix seconds) |
| `sub` | string, optional | subject id (player id) |
| `cnf` | key object | holder key the credential is bound to |
| `_sd_alg` | string | always `"sha-256"` |
| `_sd` | array of digests | hashes of the disclosures |
| *(others)* | any | non-disclosable (always-revealed) claims |

Rules:

* A claim name is **either** disclosable (listed in `_sd` via a disclosure)
  **or** plaintext in the payload — never both.
* Reserved names that may not be used as user claims: `_sd`, `_sd_alg`, `cnf`,
  `iss`, `sub`, `iat`, `exp`, `vct`.

---

## 5. Request

A verifier creates a request (JSON; in real flows this would travel as a URL
or QR payload, here it can simply be passed over your existing game netcode):

```json
{
  "aud": "game-server-eu-1",
  "nonce": "<base64url random>",
  "vct": ["urn:eudi:game:attestation:age-over-18"],
  "claims": ["age_over_18", "display_name"],
  "purpose": "Age-gate matchmaking",
  "expires_at": 1700000060
}
```

* `aud` — id of the verifier instance that must receive the answer (stops
  relay attacks: a stolen presentation cannot be replayed to another server).
* `nonce` — one-time random value (stops replay of the same presentation).
* `claims` — names the holder **must** disclose; anything else stays hidden.
* `vct` — credential types the verifier accepts.

---

## 6. Presentation

```
base = gw+jwt "~" disclosure_i "~" disclosure_j           (only requested ones)
sd_hash = b64url(SHA-256(ASCII(base)))
kb_payload = {"aud":..., "iat":..., "nonce":..., "sd_hash":...}
kb_jwt = token signed with the holder key, typ "kb+jwt"
presentation = base "~" kb_jwt
```

The `kb+jwt` proves two things at once:

1. **Holder binding / device binding** — only the device holding the private
   key can produce it, so a copied credential string is useless.
2. **Freshness** — it commits to the verifier (`aud`), a one-time `nonce`, and
   the exact presentation content (`sd_hash`), so it cannot be reused.

---

## 7. Verification (normative checklist)

A verifier must perform these steps in order and reject on the first failure:

1. Split `presentation` on `~`: `jwt`, disclosures…, `kb_jwt`
   (a presentation ending in `~` has no key binding).
2. Decode the `gw+jwt` header; require `alg=HS256`, `typ=gw+jwt`.
3. Look up `iss` in the trust store; reject `ERR_ISSUER_UNKNOWN` if absent.
4. Verify the issuer signature over `header.payload`; reject
   `ERR_SIGNATURE_INVALID` on failure.
5. Validity: reject `ERR_EXPIRED` if `now > exp + skew`, `ERR_NOT_YET_VALID`
   if `now < iat - skew`. Default `skew` is 300 s.
6. Type: reject `ERR_VCT_NOT_ALLOWED` if `vct` is not in the request list.
7. Structural: `_sd_alg` must be `"sha-256"` and `_sd` an array.
8. Build the claim set: plaintext (non-reserved) payload claims, then each
   presented disclosure. For every disclosure:
   * its digest must appear in `_sd` and must not be used twice → else
     `ERR_DISCLOSURE_UNKNOWN`;
   * its claim name must not duplicate a plaintext claim → else
     `ERR_DUPLICATE_CLAIM`.
9. Every name in `request.claims` must be present → else `ERR_CLAIM_MISSING`.
10. Key binding (unless explicitly disabled):
    * missing → `ERR_KB_MISSING`;
    * header must be `alg=HS256`, `typ=kb+jwt` → else `ERR_KB_INVALID`;
    * signature must verify against the credential's `cnf` key → else
      `ERR_KB_INVALID`;
    * `sd_hash` must equal the hash of the presentation base → else
      `ERR_SD_HASH_MISMATCH`;
    * `aud` / `nonce` must equal the request's → else `ERR_AUD_MISMATCH` /
      `ERR_NONCE_MISMATCH`;
    * `iat` must be within skew → else `ERR_KB_INVALID`;
    * the `(iss, nonce)` pair must not have been seen before → else
      `ERR_REPLAY`.

On success the verifier returns the derived claims and consumes the nonce.

---

## 8. Error codes

| code | meaning |
| --- | --- |
| `ERR_MALFORMED` | not valid GDW structure / not decodable |
| `ERR_SIGNATURE_INVALID` | issuer signature does not verify |
| `ERR_ISSUER_UNKNOWN` | `iss` not in the trust store |
| `ERR_VCT_NOT_ALLOWED` | credential type not requested |
| `ERR_EXPIRED` / `ERR_NOT_YET_VALID` | outside validity window |
| `ERR_DISCLOSURE_UNKNOWN` | disclosure hash not in `_sd` (or reused) |
| `ERR_DUPLICATE_CLAIM` | claim provided twice |
| `ERR_CLAIM_MISSING` | a requested claim was not disclosed |
| `ERR_KB_MISSING` / `ERR_KB_INVALID` | key-binding token missing / invalid |
| `ERR_SD_HASH_MISMATCH` | key binding commits to different content |
| `ERR_AUD_MISMATCH` / `ERR_NONCE_MISMATCH` | bound to another verifier / replayed request |
| `ERR_REPLAY` | this `(issuer, nonce)` was already consumed |

---

## 9. Test vectors

[`test-vectors/vectors.json`](test-vectors/vectors.json) is generated by
[`test-vectors/generate_vectors.py`](test-vectors/generate_vectors.py), which is
the executable form of this specification. Every framework ships a test suite
that replays those vectors byte-for-byte (canonical JSON, disclosure digests,
HS256 signatures, a full issue → present → verify round trip, and 12 negative
cases). Regenerate with:

```bash
cd test-vectors && python3 generate_vectors.py
```
