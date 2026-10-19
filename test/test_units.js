#!/usr/bin/env node
// Small unit tests for the EudiGameWallet JavaScript primitives, mirroring the
// `#[cfg(test)]` modules in the Rust framework and the equivalent tests in the
// C++ / C# / GDScript / Python frameworks.
//
// Run: node test/test_units.js
//
// SPDX-License-Identifier: CC-BY-4.0

'use strict';

const gdwjson = require('../src/json');
const { GdwError } = require('../src/errors');
const {
  b64urlDecode,
  b64urlEncode,
  disclosureDigest,
  makeDisclosure,
} = require('../src/primitives');

let failures = 0;

function check(condition, label) {
  if (!condition) {
    failures += 1;
    console.log(`  FAIL: ${label}`);
  }
}

function rejects(text) {
  try {
    gdwjson.parse(text);
    return false;
  } catch (e) {
    return e instanceof GdwError;
  }
}

function main() {
  for (let length = 0; length < 40; length += 1) {
    const data = new Uint8Array(length);
    for (let i = 0; i < length; i += 1) data[i] = (length * 7 + 3 + i) & 0xff;
    const encoded = b64urlEncode(data);
    check(!encoded.includes('='), `no padding ${length}`);
    check(
      Buffer.compare(Buffer.from(b64urlDecode(encoded)), Buffer.from(data)) === 0,
      `b64url round trip ${length}`,
    );
  }

  // b64url length % 4 == 1 and invalid alphabets must be rejected.
  for (const bad of ['A', 'AAAAA', 'AA+A', 'AA/A', 'AA==']) {
    let threw = false;
    try {
      b64urlDecode(bad);
    } catch (e) {
      threw = e instanceof GdwError;
    }
    check(threw, `rejects bad base64url ${bad}`);
  }

  check(rejects('1.5'), 'rejects float');
  check(rejects('1e3'), 'rejects exponent');
  check(rejects('-0'), 'rejects negative zero');
  check(rejects('01'), 'rejects leading zero');
  check(rejects('9007199254740992'), 'rejects 2^53');
  check(rejects('-9007199254740992'), 'rejects -2^53');
  check(rejects('{}x'), 'rejects trailing content');
  check(rejects('[1,]'), 'rejects trailing comma');
  check(
    gdwjson.canonical(gdwjson.parse('9007199254740991')) === '9007199254740991',
    'accepts max safe integer',
  );
  check(
    gdwjson.canonical({ b: 2, a: 1, c: { y: 'ü' } }) === '{"a":1,"b":2,"c":{"y":"ü"}}',
    'canonical sorts and keeps unicode',
  );
  check(
    gdwjson.canonical(gdwjson.parse('{"a":1,"b":[true,null,"x"]}')) === '{"a":1,"b":[true,null,"x"]}',
    'round trip',
  );

  const segment = makeDisclosure('AAECAwQFBgcICQoLDA0ODw', 'age_over_18', true);
  check(
    segment === 'WyJBQUVDQXdRRkJnY0lDUW9MREEwT0R3IiwiYWdlX292ZXJfMTgiLHRydWVd',
    'disclosure vector segment',
  );
  check(
    disclosureDigest(segment) === 'zhurxLJSJKI_XNO-e_L644W0SwqsTD5LDd3yPwd4ZWs',
    'disclosure vector digest',
  );

  // An empty array must survive a round trip (JsonArray tagging).
  check(gdwjson.canonical(gdwjson.parse('[]')) === '[]', 'empty array round trip');
  check(gdwjson.canonical(gdwjson.parse('{}')) === '{}', 'empty object round trip');

  console.log(failures === 0 ? '\nOK' : `\n${failures} FAILED`);
  return failures ? 1 : 0;
}

process.exit(main());
