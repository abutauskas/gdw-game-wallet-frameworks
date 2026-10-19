#!/usr/bin/env node
// Minimal end-to-end flow: an age-over-18 attestation is issued, stored in a
// game wallet, selectively disclosed to a matchmaking server, then verified.
//
// Run: node examples/basic_flow.mjs
//
// SPDX-License-Identifier: CC-BY-4.0

import gdw from '../src/index.js';

const { GdwKey, Issuer, Wallet, Verifier, now } = gdw;

function main() {
  // 1. Trust anchors. In production these come from a signed trust list
  //    (see SPEC.md); here we use a shared secret for a self-contained demo.
  const issuerKey = GdwKey.hs256('issuer-shared-secret-used-only-for-this-demo');
  const playerKey = GdwKey.hs256('holder-key-derived-on-the-players-device-----');

  // 2. A PID/attestation provider issues an age attestation to one account.
  const ageIssuer = new Issuer('https://issuer.example/age-service', issuerKey);
  const credential = ageIssuer.issue({
    vct: 'urn:eudi:game:attestation:age-over-18',
    sub: 'player-8241',
    holderKey: playerKey,
    iat: now(),
    exp: now() + 30 * 24 * 3600,
    claims: { age_over_18: true, country: 'NL', nickname: 'pixel_knight' },
    disclosable: ['age_over_18', 'country'],
  });

  console.log(`credential bytes: ${Buffer.byteLength(credential, 'utf8')}`);
  const reader = new Wallet(playerKey);
  console.log(`stored claims:    ${reader.claimsOf(credential).join(' ')}`);
  console.log();

  // 3. The player's game wallet stores the credential.
  const wallet = new Wallet(playerKey);
  wallet.store(credential);

  // 4. A matchmaking server (relying party) asks for a single claim and, being
  //    a game backend, wants proof the response is fresh (nonce) and bound to
  //    this holder (key binding, cnf).
  const server = new Verifier('matchmaking-eu-1');
  server.trust(ageIssuer.id, issuerKey);
  const request = server.createRequest(
    ['urn:eudi:game:attestation:age-over-18'],
    ['age_over_18'],
    60,
  );

  // 5. The wallet discloses only what was asked for; nickname/country stay hidden.
  const presentation = wallet.present(
    credential,
    ['age_over_18'],
    request.aud,
    request.nonce,
    now(),
  );
  console.log(`presentation bytes: ${Buffer.byteLength(presentation, 'utf8')}`);
  console.log();

  // 6. The server verifies and reads the derived claims.
  const result = server.verify(request, presentation, now());
  if (result.ok) {
    const flag = result.claims.age_over_18 === true;
    console.log(`verified: age_over_18 = ${flag}`);
    return 0;
  }

  console.log(`verification failed: ${result.errors.join(' ')}`);
  return 1;
}

process.exit(main());
