"""# EudiGameWallet — Python

A dependency-free Python implementation of the [Game Digital Wallet (GDW)
token specification](../SPEC.md). It drops into **Panda3D**, **PyGame**,
**Ursina**, a dedicated server (asyncio), or any Python game toolchain, so the
same credential format is spoken on every side.

The core is pure standard library: SHA-256 and HMAC-SHA256 come from
:mod:`hashlib`/:mod:`hmac`, so the package builds offline and needs no crypto
backend. ES256 (the production algorithm) is opt-in and activates automatically
when the ``cryptography`` package is importable.

```python
from eudi_game_wallet import GdwKey, IssueOptions, Issuer, Wallet, Verifier

# A trusted prototype: issuer and verifier share an HS256 key.
issuer_key = GdwKey.hs256_from_bytes(bytes(range(32)))
holder_key = GdwKey.hs256_from_bytes(bytes(range(32, 64)))

issuer = Issuer("https://issuer.example/age-service", issuer_key)
options = IssueOptions(
    vct="urn:eudi:game:attestation:age-over-18",
    iat=1_700_000_000,
    exp=1_700_000_000 + 3600,
    holder_key=holder_key,
    claims={"age_over_18": True},
    disclosable=["age_over_18"],
)
credential = issuer.issue(options)

wallet = Wallet(holder_key)
wallet.store(credential)
```

SPDX-License-Identifier: CC-BY-4.0
"""

from __future__ import annotations

from . import es256, json, key, primitives
from .core import (
    DecodedToken,
    Issuer,
    IssueOptions,
    ParsedCredential,
    Verifier,
    VerifyResult,
    Wallet,
    decode_token,
    now,
    parse_credential,
)
from .errors import GdwError
from .key import GdwKey, Hs256Signer, Signer, signer_for

__all__ = [
    "DecodedToken",
    "GdwError",
    "GdwKey",
    "Hs256Signer",
    "IssueOptions",
    "Issuer",
    "ParsedCredential",
    "Signer",
    "Verifier",
    "VerifyResult",
    "Wallet",
    "decode_token",
    "es256",
    "json",
    "key",
    "now",
    "parse_credential",
    "primitives",
    "signer_for",
]
