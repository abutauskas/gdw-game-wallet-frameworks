// Optional ES256 (ECDSA P-256) support, backed by Node's `node:crypto`.
//
// Signatures are emitted as raw `r || s` (IEEE-P1363 fixed-field
// concatenation), which is what JWS ES256 requires — not the ASN.1/DER form
// OpenSSL produces by default. The core does not import this module unless a
// key uses `alg === "ES256"`, so a default install needs no crypto backend
// beyond Node itself.
//
// SPDX-License-Identifier: CC-BY-4.0

'use strict';

const { ERR_MALFORMED, GdwError } = require('./errors');
const { GdwKey } = require('./key');
const { b64urlDecode, b64urlEncode } = require('./primitives');

const FIELD_SIZE = 32; // P-256 coordinates / r / s are 32 bytes

let nodeCrypto = null;
try {
  // eslint-disable-next-line global-require
  nodeCrypto = require('node:crypto');
} catch (_) {
  nodeCrypto = null;
}

function haveEs256() {
  return nodeCrypto !== null && typeof nodeCrypto.createPrivateKey === 'function';
}

function requireEs256() {
  if (!haveEs256()) throw new GdwError(ERR_MALFORMED);
}

function b64ToBytes(text) {
  return b64urlDecode(text || '');
}

function bytesToInt(bytes) {
  let value = 0n;
  for (const b of bytes) value = (value << 8n) | BigInt(b);
  return value;
}

// A GDW ES256 key uses base64url-encoded fixed-size (32-byte) coordinates and
// scalar, whereas JWK uses unpadded base64url of the same minimal big-endian
// integer. Normalise to fixed width so leading zero bytes are preserved.
function normalizeB64(text) {
  return b64urlEncode(b64ToBytes(text));
}

function jwkFromKey(key, includePrivate) {
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: normalizeB64(key.x || ''),
    y: normalizeB64(key.y || ''),
  };
  if (includePrivate) jwk.d = normalizeB64(key.d);
  return jwk;
}

class EcdsaP256Signer {
  constructor(key) {
    requireEs256();
    if (key.alg !== 'ES256') throw new GdwError(ERR_MALFORMED);
    this.alg = 'ES256';
    this._canSign = false;
    this._privateRef = null;
    this._publicRef = null;

    if (key.d !== null && key.d !== undefined) {
      const d = bytesToInt(b64ToBytes(key.d));
      if (d <= 0n) throw new GdwError(ERR_MALFORMED);
      const privateObj = nodeCrypto.createPrivateKey({ key: jwkFromKey(key, true), format: 'jwk' });
      this._privateRef = privateObj;
      this._publicRef = nodeCrypto.createPublicKey(privateObj);
      this._canSign = true;
      if (key.x !== null && key.y !== null) {
        // Cross-check that the supplied X/Y match the derived public key.
        const jwk = this._publicRef.export({ format: 'jwk' });
        if (
          bytesToInt(b64urlDecode(jwk.x)) !== bytesToInt(b64ToBytes(key.x)) ||
          bytesToInt(b64urlDecode(jwk.y)) !== bytesToInt(b64ToBytes(key.y))
        ) {
          throw new GdwError(ERR_MALFORMED);
        }
      }
    } else if (key.x !== null && key.y !== null) {
      this._publicRef = nodeCrypto.createPublicKey({ key: jwkFromKey(key, false), format: 'jwk' });
    } else {
      throw new GdwError(ERR_MALFORMED);
    }
  }

  sign(signingInput) {
    if (!this._canSign) return '';
    const sig = nodeCrypto.sign('sha256', Buffer.from(signingInput, 'ascii'), {
      key: this._privateRef,
      dsaEncoding: 'ieee-p1363',
    });
    return b64urlEncode(new Uint8Array(sig));
  }

  verify(signingInput, signature) {
    let raw;
    try {
      raw = b64urlDecode(signature);
    } catch (_) {
      return false;
    }
    try {
      return nodeCrypto.verify(
        'sha256',
        Buffer.from(signingInput, 'ascii'),
        { key: this._publicRef, dsaEncoding: 'ieee-p1363' },
        Buffer.from(raw),
      );
    } catch (_) {
      return false;
    }
  }

  static generate() {
    requireEs256();
    const { privateKey, publicKey } = nodeCrypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    });
    const privJwk = privateKey.export({ format: 'jwk' });
    const pubJwk = publicKey.export({ format: 'jwk' });
    return [
      new GdwKey({ alg: 'ES256', crv: 'P-256', x: pubJwk.x, y: pubJwk.y, d: privJwk.d }),
      new GdwKey({ alg: 'ES256', crv: 'P-256', x: pubJwk.x, y: pubJwk.y }),
    ];
  }
}

module.exports = { EcdsaP256Signer, haveEs256, FIELD_SIZE };
