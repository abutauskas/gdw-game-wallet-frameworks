// Token decoding + Issuer + Wallet + Verifier (SPEC.md §4–§7).
//
// Mirrors the C++ / C# / GDScript / Rust / Python frameworks exactly, so the
// same credentials and presentations verify across all of them.
//
// SPDX-License-Identifier: CC-BY-4.0

'use strict';

const gdwjson = require('./json');
const {
  ERR_AUD_MISMATCH,
  ERR_CLAIM_MISSING,
  ERR_DISCLOSURE_UNKNOWN,
  ERR_DUPLICATE_CLAIM,
  ERR_EXPIRED,
  ERR_ISSUER_UNKNOWN,
  ERR_KB_INVALID,
  ERR_KB_MISSING,
  ERR_MALFORMED,
  ERR_NONCE_MISMATCH,
  ERR_NOT_YET_VALID,
  ERR_REPLAY,
  ERR_SD_HASH_MISMATCH,
  ERR_SIGNATURE_INVALID,
  ERR_VCT_NOT_ALLOWED,
  GdwError,
} = require('./errors');
const { GdwKey, signerFor } = require('./key');
const {
  disclosureDigest,
  isReserved,
  jsonSegment,
  makeDisclosure,
  parseDisclosure,
  parseSegment,
  randomBase64url,
  sdHash,
  splitDot,
  splitTilde,
} = require('./primitives');

function decodeToken(token) {
  const parts = splitDot(token);
  if (parts.length !== 3) throw new GdwError(ERR_MALFORMED);
  const header = parseSegment(parts[0]);
  const payload = parseSegment(parts[1]);
  if (!gdwjson.isObject(header) || !gdwjson.isObject(payload)) throw new GdwError(ERR_MALFORMED);
  return {
    header,
    payload,
    signingInput: `${parts[0]}.${parts[1]}`,
    signature: parts[2],
    headerSegment: parts[0],
  };
}

function parseCredential(credential) {
  if (typeof credential !== 'string' || credential.length === 0 || !credential.endsWith('~')) {
    throw new GdwError(ERR_MALFORMED);
  }
  const parts = splitTilde(credential);
  if (parts.length < 2) throw new GdwError(ERR_MALFORMED);
  const token = decodeToken(parts[0]);
  if (gdwjson.get(token.header, 'typ') !== 'gw+jwt') throw new GdwError(ERR_MALFORMED);
  const disclosures = parts.slice(1).filter((p) => p);
  return { token, disclosures };
}

// ===========================================================================
// Issuer
// ===========================================================================

class Issuer {
  constructor(iss, issuerKey) {
    this._signer = signerFor(issuerKey);
    this._iss = iss;
    this._alg = issuerKey.alg;
  }

  get id() {
    return this._iss;
  }

  issue(options) {
    const {
      vct = '',
      claims = {},
      disclosable = [],
      iat = 0,
      exp = 0,
      sub = '',
      holderKey = new GdwKey(),
      salts = [],
      extraPayload = {},
    } = options || {};

    if (iat === 0 || exp === 0 || !vct) throw new GdwError(ERR_MALFORMED);
    for (const name of disclosable) {
      if (!gdwjson.has(claims, name) || isReserved(name)) throw new GdwError(ERR_MALFORMED);
    }

    const disclosures = [];
    const sd = [];
    disclosable.forEach((name, i) => {
      const salt = i < salts.length ? salts[i] : randomBase64url(16);
      if (!gdwjson.has(claims, name)) throw new GdwError(ERR_MALFORMED);
      const value = claims[name];
      const segment = makeDisclosure(salt, name, value);
      disclosures.push(segment);
      sd.push(disclosureDigest(segment));
    });

    const payload = {
      _sd: sd,
      _sd_alg: 'sha-256',
      cnf: holderKey.toJson(),
      exp,
      iat,
      iss: this._iss,
      vct,
    };
    if (sub) payload.sub = sub;

    for (const key of Object.keys(claims)) {
      if (disclosable.includes(key)) continue;
      if (Object.prototype.hasOwnProperty.call(payload, key)) throw new GdwError(ERR_MALFORMED);
      payload[key] = claims[key];
    }
    for (const key of Object.keys(extraPayload)) {
      if (Object.prototype.hasOwnProperty.call(payload, key)) throw new GdwError(ERR_MALFORMED);
      payload[key] = extraPayload[key];
    }

    const header = { alg: this._alg, typ: 'gw+jwt' };
    const signingInput = `${jsonSegment(header)}.${jsonSegment(payload)}`;
    const jwt = `${signingInput}.${this._signer.sign(signingInput)}`;

    return jwt + disclosures.map((d) => `~${d}`).join('') + '~';
  }
}

// ===========================================================================
// Wallet (holder)
// ===========================================================================

class Wallet {
  constructor(holderKey) {
    this._key = holderKey;
    this._signer = signerFor(holderKey);
    this._credentials = [];
  }

  get credentials() {
    return this._credentials;
  }

  store(credential) {
    parseCredential(credential);
    this._credentials.push(credential);
  }

  claimsOf(credential) {
    const parsed = parseCredential(credential);
    const names = [];
    for (const [key] of gdwjson.entries(parsed.token.payload)) {
      if (!isReserved(key)) names.push(key);
    }
    for (const segment of parsed.disclosures) names.push(parseDisclosure(segment).name);
    return names;
  }

  present(credential, requestedClaims, aud, nonce, issuedAt) {
    const parsed = parseCredential(credential);

    const byDigest = {};
    for (const segment of parsed.disclosures) byDigest[disclosureDigest(segment)] = segment;

    const selected = [];
    const sd = gdwjson.get(parsed.token.payload, '_sd');
    for (const name of requestedClaims) {
      if (!isReserved(name) && gdwjson.has(parsed.token.payload, name)) continue;
      let found = false;
      if (gdwjson.isArray(sd)) {
        const items = sd instanceof gdwjson.JsonArray ? sd.items : sd;
        for (const digest of items) {
          if (typeof digest !== 'string') continue;
          const segment = byDigest[digest];
          if (segment !== undefined && parseDisclosure(segment).name === name) {
            selected.push(segment);
            found = true;
            break;
          }
        }
      }
      if (!found) throw new GdwError(ERR_CLAIM_MISSING);
    }

    let baseText = `${parsed.token.signingInput}.${parsed.token.signature}`;
    for (const segment of selected) baseText += `~${segment}`;

    const cnf = gdwjson.get(parsed.token.payload, 'cnf');
    if (gdwjson.isObject(cnf)) {
      const cnfKey = GdwKey.fromJson(cnf);
      if (!cnfKey.sameSecret(this._key)) throw new GdwError(ERR_KB_INVALID);
    }

    const kb = {
      aud,
      iat: issuedAt,
      nonce,
      sd_hash: sdHash(baseText),
    };
    const header = { alg: this._signer.alg, typ: 'kb+jwt' };
    const signingInput = `${jsonSegment(header)}.${jsonSegment(kb)}`;
    const kbJwt = `${signingInput}.${this._signer.sign(signingInput)}`;
    return `${baseText}~${kbJwt}`;
  }
}

// ===========================================================================
// Verifier (relying party)
// ===========================================================================

class Verifier {
  constructor(aud) {
    this._aud = aud;
    this._trust = new Map();
    this._usedNonces = new Set();
    this._clockSkew = 300;
  }

  setClockSkew(skew) {
    this._clockSkew = skew;
  }

  trust(issuer, key) {
    this._trust.set(issuer, key);
  }

  markNonceUsed(iss, nonce) {
    this._usedNonces.add(`${iss}|${nonce}`);
  }

  createRequest(vct, claims, ttlSeconds) {
    const current = now();
    return {
      aud: this._aud,
      nonce: randomBase64url(16),
      vct: [...vct],
      claims: [...claims],
      iat: current,
      expires_at: current + ttlSeconds,
    };
  }

  verify(request, presentation, currentTime) {
    try {
      const claims = this._verifyInternal(request, presentation, currentTime);
      return { ok: true, claims, errors: [] };
    } catch (error) {
      if (error instanceof GdwError) {
        return { ok: false, claims: {}, errors: [error.code] };
      }
      throw error;
    }
  }

  _verifyInternal(request, presentation, currentTime) {
    const parts = splitTilde(presentation);
    if (parts.length < 2) throw new GdwError(ERR_MALFORMED);

    const jwt = parts[0];
    const hasKb = Boolean(parts[parts.length - 1]);
    const kbJwt = hasKb ? parts[parts.length - 1] : '';
    const end = hasKb ? parts.length - 1 : parts.length;
    const disclosures = parts.slice(1, end).filter((p) => p);

    const token = decodeToken(jwt);
    if (gdwjson.get(token.header, 'typ') !== 'gw+jwt') throw new GdwError(ERR_MALFORMED);

    const iss = gdwjson.get(token.payload, 'iss');
    if (typeof iss !== 'string' || !iss) throw new GdwError(ERR_MALFORMED);
    const trusted = this._trust.get(iss);
    if (trusted === undefined) throw new GdwError(ERR_ISSUER_UNKNOWN);
    if (gdwjson.get(token.header, 'alg') !== trusted.alg) throw new GdwError(ERR_MALFORMED);
    const issuerSigner = signerFor(trusted);
    if (!issuerSigner.verify(token.signingInput, token.signature)) {
      throw new GdwError(ERR_SIGNATURE_INVALID);
    }

    const exp = gdwjson.asInt(gdwjson.get(token.payload, 'exp'));
    const iat = gdwjson.asInt(gdwjson.get(token.payload, 'iat'));
    if (exp === null || iat === null || exp < 0 || iat < 0) throw new GdwError(ERR_MALFORMED);
    if (currentTime > exp + this._clockSkew) throw new GdwError(ERR_EXPIRED);
    if (currentTime < iat - this._clockSkew) throw new GdwError(ERR_NOT_YET_VALID);

    const vct = gdwjson.get(token.payload, 'vct') || '';
    const allowed = gdwjson.get(request, 'vct');
    let vctAllowed = false;
    if (gdwjson.isArray(allowed)) {
      const items = allowed instanceof gdwjson.JsonArray ? allowed.items : allowed;
      vctAllowed = items.some((v) => v === vct);
    }
    if (!vctAllowed) throw new GdwError(ERR_VCT_NOT_ALLOWED);

    if (gdwjson.get(token.payload, '_sd_alg') !== 'sha-256') throw new GdwError(ERR_MALFORMED);
    const sd = gdwjson.get(token.payload, '_sd');
    if (!gdwjson.isArray(sd)) throw new GdwError(ERR_MALFORMED);
    const sdItems = sd instanceof gdwjson.JsonArray ? sd.items : sd;

    const claims = {};
    for (const [key, value] of gdwjson.entries(token.payload)) {
      if (!isReserved(key)) claims[key] = value;
    }

    const covered = sdItems.filter((d) => typeof d === 'string');
    const seen = new Set();
    for (const segment of disclosures) {
      const digest = disclosureDigest(segment);
      if (!covered.includes(digest) || seen.has(digest)) throw new GdwError(ERR_DISCLOSURE_UNKNOWN);
      seen.add(digest);
      const parsed = parseDisclosure(segment);
      if (Object.prototype.hasOwnProperty.call(claims, parsed.name)) {
        throw new GdwError(ERR_DUPLICATE_CLAIM);
      }
      claims[parsed.name] = parsed.value;
    }

    const required = gdwjson.get(request, 'claims');
    if (gdwjson.isArray(required)) {
      const items = required instanceof gdwjson.JsonArray ? required.items : required;
      for (const name of items) {
        if (typeof name === 'string' && !Object.prototype.hasOwnProperty.call(claims, name)) {
          throw new GdwError(ERR_CLAIM_MISSING);
        }
      }
    }

    // ---- key binding ----
    if (!kbJwt) throw new GdwError(ERR_KB_MISSING);
    const kbToken = decodeToken(kbJwt);
    if (gdwjson.get(kbToken.header, 'typ') !== 'kb+jwt') throw new GdwError(ERR_KB_INVALID);
    const cnf = gdwjson.get(token.payload, 'cnf');
    if (!gdwjson.isObject(cnf)) throw new GdwError(ERR_KB_INVALID);
    const cnfKey = GdwKey.fromJson(cnf);
    if (gdwjson.get(kbToken.header, 'alg') !== cnfKey.alg) throw new GdwError(ERR_KB_INVALID);
    const kbSigner = signerFor(cnfKey);
    if (!kbSigner.verify(kbToken.signingInput, kbToken.signature)) {
      throw new GdwError(ERR_KB_INVALID);
    }

    let baseText = jwt;
    for (const segment of disclosures) baseText += `~${segment}`;
    if (gdwjson.get(kbToken.payload, 'sd_hash') !== sdHash(baseText)) {
      throw new GdwError(ERR_SD_HASH_MISMATCH);
    }
    if (gdwjson.get(kbToken.payload, 'aud') !== gdwjson.get(request, 'aud')) {
      throw new GdwError(ERR_AUD_MISMATCH);
    }
    if (gdwjson.get(kbToken.payload, 'nonce') !== gdwjson.get(request, 'nonce')) {
      throw new GdwError(ERR_NONCE_MISMATCH);
    }

    const kbIat = gdwjson.asInt(gdwjson.get(kbToken.payload, 'iat'));
    if (
      kbIat === null ||
      kbIat < 0 ||
      currentTime > kbIat + this._clockSkew ||
      currentTime < kbIat - this._clockSkew
    ) {
      throw new GdwError(ERR_KB_INVALID);
    }

    const nonceKey = `${iss}|${gdwjson.get(request, 'nonce') || ''}`;
    if (this._usedNonces.has(nonceKey)) throw new GdwError(ERR_REPLAY);
    this._usedNonces.add(nonceKey);

    return claims;
  }
}

function now() {
  return Math.floor(Date.now() / 1000);
}

module.exports = {
  decodeToken,
  parseCredential,
  Issuer,
  Wallet,
  Verifier,
  now,
};
