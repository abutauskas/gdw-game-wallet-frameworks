// A fully-typed end-to-end flow, compiled and type-checked with `tsc`.
// It mirrors examples/basic_flow.mjs but uses the TypeScript declarations, so
// `npm run typecheck` proves the public API is usable from TypeScript.
//
// SPDX-License-Identifier: CC-BY-4.0

import {
  GdwKey,
  Issuer,
  Wallet,
  Verifier,
  EcdsaP256Signer,
  haveEs256,
  signerFor,
  now,
  type VerifyResult,
  type JsonValue,
} from './index.js';

function main(): number {
  const issuerKey: GdwKey = GdwKey.hs256('issuer-shared-secret-used-only-for-this-demo');
  const playerKey: GdwKey = GdwKey.hs256('holder-key-derived-on-the-players-device-----');

  const ageIssuer: Issuer = new Issuer('https://issuer.example/age-service', issuerKey);
  const claims: Record<string, JsonValue> = {
    age_over_18: true,
    country: 'NL',
    nickname: 'pixel_knight',
  };
  const credential: string = ageIssuer.issue({
    vct: 'urn:eudi:game:attestation:age-over-18',
    sub: 'player-8241',
    holderKey: playerKey,
    iat: now(),
    exp: now() + 30 * 24 * 3600,
    claims,
    disclosable: ['age_over_18', 'country'],
  });

  const wallet: Wallet = new Wallet(playerKey);
  wallet.store(credential);
  const names: string[] = wallet.claimsOf(credential);

  const server: Verifier = new Verifier('matchmaking-eu-1');
  server.trust(ageIssuer.id, issuerKey);
  const request = server.createRequest(
    ['urn:eudi:game:attestation:age-over-18'],
    ['age_over_18'],
    60,
  );

  const presentation: string = wallet.present(
    credential,
    ['age_over_18'],
    request.aud,
    request.nonce,
    now(),
  );

  const result: VerifyResult = server.verify(request, presentation, now());
  if (result.ok) {
    const flag = result.claims.age_over_18 === true;
    console.log(`verified: age_over_18 = ${flag} (claims: ${names.length})`);
    if (haveEs256()) {
      const [esPriv, esPub]: [GdwKey, GdwKey] = EcdsaP256Signer.generate();
      const esSigner = signerFor(esPub);
      void esSigner;
      void esPriv;
    }
    return 0;
  }
  console.log(`verification failed: ${result.errors.join(' ')}`);
  return 1;
}

process.exit(main());
