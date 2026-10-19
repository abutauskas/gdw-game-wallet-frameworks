// Keys and signers: HS256 (the dependency-free prototype algorithm) plus
// optional ES256 (the production path, via Node's `node:crypto` when present).
//
// SPDX-License-Identifier: CC-BY-4.0

'use strict';

const gdwjson = require('./json');
const { ERR_MALFORMED, GdwError } = require('./errors');
const { b64urlDecode, b64urlEncode, b64urlUtf8 } = require('./primitives');
const { hmacSha256, constantTimeEq } = require('./crypto');

const ENC = new TextEncoder();

class GdwKey {
  constructor({ alg = '', k = null, crv = null, x = null, y = null, d = null } = {}) {
    this.alg = alg;
    this.k = k;
    this.crv = crv;
    this.x = x;
    this.y = y;
    this.d = d;
  }

  static hs256(rawSecret) {
    return new GdwKey({ alg: 'HS256', k: b64urlUtf8(rawSecret) });
  }

  static hs256FromBytes(raw) {
    return new GdwKey({ alg: 'HS256', k: b64urlEncode(raw) });
  }

  toJson() {
    const out = { alg: this.alg };
    if (this.alg === 'HS256') {
      out.k = this.k || '';
    } else {
      out.crv = this.crv || 'P-256';
      out.x = this.x || '';
      out.y = this.y || '';
      // PROTOTYPE ONLY: mirrors the C++/C#/Rust/Python frameworks, which embed
      // the private scalar in `cnf` so the toy holder-binding check is
      // self-contained. NEVER do this in production — a real `cnf` must carry
      // only the public key and the holder must hold the private half.
      // See SPEC.md §2.4.
      if (this.d !== null && this.d !== undefined) out.d = this.d;
    }
    return out;
  }

  static fromJson(j) {
    const get = (name) => {
      const value = gdwjson.get(j, name);
      return typeof value === 'string' ? value : null;
    };
    return new GdwKey({
      alg: get('alg') || 'HS256',
      k: get('k'),
      crv: get('crv'),
      x: get('x'),
      y: get('y'),
      d: get('d'),
    });
  }

  sameSecret(other) {
    if (this.alg === 'HS256') return this.k === other.k;
    return this.d !== null && this.d !== undefined && this.d === other.d;
  }
}

class Hs256Signer {
  constructor(key) {
    if (key.alg !== 'HS256') throw new GdwError(ERR_MALFORMED);
    this.alg = 'HS256';
    this._secret = b64urlDecode(key.k || '');
  }

  sign(signingInput) {
    return b64urlEncode(hmacSha256(this._secret, ENC.encode(signingInput)));
  }

  verify(signingInput, signature) {
    const expected = hmacSha256(this._secret, ENC.encode(signingInput));
    let actual;
    try {
      actual = b64urlDecode(signature);
    } catch (_) {
      return false;
    }
    return constantTimeEq(expected, actual);
  }
}

function signerFor(key) {
  if (key.alg === 'HS256') return new Hs256Signer(key);
  if (key.alg === 'ES256') {
    // Required lazily so the core stays dependency-free.
    // eslint-disable-next-line global-require
    const { EcdsaP256Signer } = require('./es256');
    return new EcdsaP256Signer(key);
  }
  throw new GdwError(ERR_MALFORMED);
}

module.exports = { GdwKey, Hs256Signer, signerFor };
