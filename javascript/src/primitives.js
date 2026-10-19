// Shared primitives: base64url, canonical JSON segments, disclosure
// construction/parsing, random salting, claim-name rules (SPEC.md §2, §3).
//
// SPDX-License-Identifier: CC-BY-4.0

'use strict';

const gdwjson = require('./json');
const { ERR_MALFORMED, GdwError } = require('./errors');
const { randomBytes, sha256 } = require('./crypto');

const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const RESERVED = new Set(['_sd', '_sd_alg', 'cnf', 'iss', 'sub', 'iat', 'exp', 'vct']);

const ENC = new TextEncoder();
const DEC = new TextDecoder('utf-8', { fatal: true });

function bytesToB64url(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += B64URL_ALPHABET[b0 >> 2];
    out += B64URL_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)];
    if (i + 1 < bytes.length) out += B64URL_ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)];
    if (i + 2 < bytes.length) out += B64URL_ALPHABET[b2 & 0x3f];
  }
  return out;
}

function b64urlCharValue(c) {
  const code = c.charCodeAt(0);
  if (code >= 0x41 && code <= 0x5a) return code - 0x41; // A-Z
  if (code >= 0x61 && code <= 0x7a) return code - 0x61 + 26; // a-z
  if (code >= 0x30 && code <= 0x39) return code - 0x30 + 52; // 0-9
  if (c === '-') return 62;
  if (c === '_') return 63;
  return -1;
}

function b64urlDecode(text) {
  if (typeof text !== 'string') throw new GdwError(ERR_MALFORMED);
  if (text.length % 4 === 1) throw new GdwError(ERR_MALFORMED);
  const out = [];
  let acc = 0;
  let bits = 0;
  for (const c of text) {
    const v = b64urlCharValue(c);
    if (v < 0) throw new GdwError(ERR_MALFORMED);
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) throw new GdwError(ERR_MALFORMED);
  return Uint8Array.from(out);
}

const b64urlEncode = bytesToB64url;

function b64urlUtf8(text) {
  return bytesToB64url(ENC.encode(text));
}

function decodeUtf8(bytes) {
  try {
    return DEC.decode(bytes);
  } catch (_) {
    throw new GdwError(ERR_MALFORMED);
  }
}

function jsonSegment(value) {
  return bytesToB64url(ENC.encode(gdwjson.canonical(value)));
}

function parseSegment(segment) {
  const bytes = b64urlDecode(segment);
  return gdwjson.parse(decodeUtf8(bytes));
}

function isAsciiAlnum(c) {
  const code = c.charCodeAt(0);
  return (
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a)
  );
}

function isValidClaimName(name) {
  if (typeof name !== 'string' || name.length === 0 || name.length > 64) return false;
  if (name[0] === '_') return false;
  for (const c of name) {
    if (!(isAsciiAlnum(c) || c === '_' || c === '-')) return false;
  }
  return true;
}

function isReserved(name) {
  return RESERVED.has(name);
}

function makeDisclosure(saltB64, name, value) {
  if (!isValidClaimName(name)) throw new GdwError(ERR_MALFORMED);
  if (b64urlDecode(saltB64).length < 16) throw new GdwError(ERR_MALFORMED);
  return jsonSegment([saltB64, name, value]);
}

function parseDisclosure(segment) {
  const arr = parseSegment(segment);
  const items = arr instanceof gdwjson.JsonArray ? arr.items : null;
  if (!items || items.length !== 3) throw new GdwError(ERR_MALFORMED);
  const [salt, name, value] = items;
  if (typeof salt !== 'string' || typeof name !== 'string') throw new GdwError(ERR_MALFORMED);
  if (!isValidClaimName(name)) throw new GdwError(ERR_MALFORMED);
  if (b64urlDecode(salt).length < 16) throw new GdwError(ERR_MALFORMED);
  return { salt, name, value };
}

function disclosureDigest(segment) {
  return bytesToB64url(sha256(ENC.encode(segment)));
}

function sdHash(baseText) {
  return bytesToB64url(sha256(ENC.encode(baseText)));
}

function randomBase64url(numBytes) {
  return bytesToB64url(randomBytes(numBytes));
}

function splitTilde(text) {
  return text.split('~');
}

function splitDot(text) {
  return text.split('.');
}

module.exports = {
  b64urlEncode,
  b64urlDecode,
  b64urlUtf8,
  decodeUtf8,
  jsonSegment,
  parseSegment,
  isValidClaimName,
  isReserved,
  makeDisclosure,
  parseDisclosure,
  disclosureDigest,
  sdHash,
  randomBase64url,
  splitTilde,
  splitDot,
};
