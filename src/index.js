// Public entry point for the GDW reference framework (JavaScript).
//
// SPDX-License-Identifier: CC-BY-4.0

'use strict';

const errors = require('./errors');
const gdwjson = require('./json');
const primitives = require('./primitives');
const { GdwKey, Hs256Signer, signerFor } = require('./key');
const core = require('./core');

// ES256 is optional (needs `node:crypto`); require it defensively so the core
// package still loads in a browser bundle where the module is stubbed.
let es256 = null;
try {
  es256 = require('./es256');
} catch (_) {
  es256 = null;
}

module.exports = {
  // errors
  GdwError: errors.GdwError,
  errors,
  // values
  JsonArray: gdwjson.JsonArray,
  json: gdwjson,
  // keys
  GdwKey,
  Hs256Signer,
  EcdsaP256Signer: es256 ? es256.EcdsaP256Signer : undefined,
  signerFor,
  haveEs256: es256 ? es256.haveEs256 : () => false,
  // token flow
  Issuer: core.Issuer,
  Wallet: core.Wallet,
  Verifier: core.Verifier,
  decodeToken: core.decodeToken,
  parseCredential: core.parseCredential,
  now: core.now,
  // primitives
  ...primitives,
};

// Re-export the error code constants at the top level for convenience.
for (const [name, value] of Object.entries(errors)) {
  if (name.startsWith('ERR_')) module.exports[name] = value;
}
