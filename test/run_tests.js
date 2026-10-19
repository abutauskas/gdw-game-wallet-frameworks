#!/usr/bin/env node
// Conformance tests for the EudiGameWallet JavaScript framework.
//
// Replays `frameworks/test-vectors/vectors.json` byte-for-byte.
// Run: node test/run_tests.js [path/to/vectors.json]
//
// SPDX-License-Identifier: CC-BY-4.0

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const gdw = require('../src/index');
const gdwjson = require('../src/json');
const { disclosureDigest, makeDisclosure, parseDisclosure } = require('../src/primitives');
const { GdwKey, signerFor } = require('../src/key');
const { Issuer, Wallet, Verifier, parseCredential } = require('../src/core');

const state = { checks: 0, failures: 0 };

function check(condition, label) {
  state.checks += 1;
  if (!condition) {
    state.failures += 1;
    console.log(`  FAIL: ${label}`);
  }
}

function checkEq(actual, expected, label) {
  state.checks += 1;
  if (actual !== expected) {
    state.failures += 1;
    console.log(`  FAIL: ${label}`);
    console.log(`    expected: ${expected}`);
    console.log(`    actual:   ${actual}`);
  }
}

function loadVectors() {
  const here = __dirname;
  const candidates = [
    process.env.GDW_VECTORS,
    path.join(here, '..', 'test-vectors', 'vectors.json'),
    path.join(here, '..', '..', 'test-vectors', 'vectors.json'),
  ];
  for (const candidate of candidates) {
    if (candidate && fs.existsSync(candidate)) {
      return JSON.parse(fs.readFileSync(candidate, 'utf8'));
    }
  }
  throw new Error('could not find vectors.json (set GDW_VECTORS)');
}

function canonical(value) {
  return gdwjson.canonical(value);
}

function run() {
  const vectors = loadVectors();

  console.log('canonical JSON');
  for (const c of vectors.canonical_json) {
    checkEq(canonical(c.input), c.canonical, c.name);
    checkEq(canonical(gdwjson.parse(c.canonical)), c.canonical, `${c.name} (round trip)`);
  }

  console.log('disclosures');
  for (const c of vectors.disclosures) {
    const segment = makeDisclosure(c.salt_b64, c.claim_name, c.claim_value);
    checkEq(segment, c.segment, `${c.name} segment`);
    checkEq(disclosureDigest(segment), c.digest, `${c.name} digest`);
    const parsed = parseDisclosure(segment);
    checkEq(parsed.name, c.claim_name, `${c.name} parsed name`);
    checkEq(canonical(parsed.value), canonical(c.claim_value), `${c.name} parsed value`);
  }

  console.log('HS256');
  const hs = vectors.hs256;
  const signer = signerFor(GdwKey.fromJson(hs.key));
  checkEq(signer.sign(hs.signing_input), hs.signature, 'signature');
  check(signer.verify(hs.signing_input, hs.signature), 'verify');
  check(!signer.verify(hs.signing_input, `${hs.signature}x`), 'verify rejects tamper');

  console.log('issue flow');
  const flow = vectors.issue_flow;
  const issuer = new Issuer(flow.iss, GdwKey.fromJson(flow.issuer_key));
  const credential = issuer.issue({
    vct: flow.vct,
    iat: flow.iat,
    exp: flow.exp,
    sub: flow.sub || '',
    holderKey: GdwKey.fromJson(flow.holder_key),
    claims: { ...flow.claims },
    disclosable: [...flow.disclosable],
    salts: [...flow.salts],
  });
  checkEq(credential, flow.credential, 'credential string');

  const parsed = parseCredential(credential);
  checkEq(canonical(parsed.token.payload), canonical(flow.expected_payload), 'payload');
  const expectedDisclosures = flow.expected_disclosures;
  checkEq(parsed.disclosures.length, expectedDisclosures.length, 'disclosure count');
  for (let i = 0; i < expectedDisclosures.length; i += 1) {
    if (i >= parsed.disclosures.length) break;
    checkEq(parsed.disclosures[i], expectedDisclosures[i].segment, `disclosure segment ${i}`);
    checkEq(
      disclosureDigest(parsed.disclosures[i]),
      expectedDisclosures[i].digest,
      `disclosure digest ${i}`,
    );
  }

  console.log('verify flow');
  const vflow = vectors.verify_flow;
  const request = vflow.request;
  const verifier = new Verifier(request.aud);
  for (const [iss, k] of Object.entries(vflow.trust)) verifier.trust(iss, GdwKey.fromJson(k));
  const result = verifier.verify(request, vflow.presentation, vflow.now);
  check(result.ok, 'verification succeeds');
  if (!result.ok) for (const e of result.errors) console.log(`    error: ${e}`);
  checkEq(canonical(result.claims), canonical(vflow.expected.claims), 'derived claims');

  console.log('negative cases');
  for (const c of vectors.negative_cases) {
    const req = c.request;
    const v = new Verifier(req.aud);
    for (const [iss, k] of Object.entries(c.trust)) v.trust(iss, GdwKey.fromJson(k));
    for (const seed of c.used_nonces) {
      const idx = seed.indexOf('|');
      v.markNonceUsed(seed.slice(0, idx), seed.slice(idx + 1));
    }
    const r = v.verify(req, c.presentation, c.now);
    const expected = c.expected_errors;
    check(r.ok === (expected.length === 0), `${c.name} ok flag`);
    if (!r.ok && expected.length) checkEq(r.errors[0], expected[0], `${c.name} error code`);
  }

  // ---- ES256 end-to-end (only when Node crypto is available) ------------
  const es256 = require('../src/es256');
  if (!es256.haveEs256()) {
    console.log('ES256 round trip (skipped: node:crypto unavailable)');
  } else {
    console.log('ES256 round trip');
    const [issuerPriv, issuerPub] = es256.EcdsaP256Signer.generate();
    const [holderPriv] = es256.EcdsaP256Signer.generate();

    const esIssuer = new Issuer('https://issuer.example/es256', issuerPriv);
    const current = gdw.now();
    const cred = esIssuer.issue({
      vct: 'urn:eudi:game:attestation:guild-member',
      iat: current,
      exp: current + 3600,
      holderKey: holderPriv,
      claims: { guild: 'Night Owls', rank: 3 },
      disclosable: ['rank'],
    });

    const wallet = new Wallet(holderPriv);
    wallet.store(cred);

    const esVerifier = new Verifier('game-server-eu-1');
    esVerifier.trust('https://issuer.example/es256', issuerPub);
    const esReq = esVerifier.createRequest(
      ['urn:eudi:game:attestation:guild-member'],
      ['guild', 'rank'],
      60,
    );
    const presentation = wallet.present(cred, ['guild', 'rank'], esReq.aud, esReq.nonce, gdw.now());
    const esResult = esVerifier.verify(esReq, presentation, gdw.now());
    check(esResult.ok, 'ES256 verification succeeds');
    if (esResult.ok) {
      checkEq(esResult.claims.guild, 'Night Owls', 'guild claim');
      check(esResult.claims.rank === 3, 'rank claim');
    } else {
      for (const e of esResult.errors) console.log(`    error: ${e}`);
    }
  }

  const total = state.checks;
  const failures = state.failures;
  console.log(`\n${total - failures}/${total} checks passed`);
  return failures ? 1 : 0;
}

process.exit(run());
