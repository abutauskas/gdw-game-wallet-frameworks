// Conformance tests for the EudiGameWallet C++ framework.
//
// Replays frameworks/test-vectors/vectors.json byte-for-byte. Build and run:
//
//   cmake -S . -B build && cmake --build build && ./build/wallet_tests
//
// SPDX-License-Identifier: CC-BY-4.0

#include "eudi/gamewallet.hpp"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

using namespace eudi::gw;

static int g_failures = 0;
static int g_checks = 0;

static void check(bool condition, const std::string& label) {
    ++g_checks;
    if (!condition) {
        ++g_failures;
        std::cout << "  FAIL: " << label << "\n";
    }
}

static void checkEqual(const std::string& actual, const std::string& expected, const std::string& label) {
    ++g_checks;
    if (actual != expected) {
        ++g_failures;
        std::cout << "  FAIL: " << label << "\n";
        std::cout << "    expected: " << expected << "\n";
        std::cout << "    actual:   " << actual << "\n";
    }
}

static std::string readFile(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        std::cerr << "cannot open " << path << "\n";
        std::exit(2);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

static Key keyFromJson(const Json& j) { return Key::fromJson(j); }

static void testCanonicalJson(const Json& vectors) {
    std::cout << "canonical JSON\n";
    const Json* cases = vectors.find("canonical_json");
    if (!cases) return;
    for (const Json& testCase : cases->arrayValue) {
        std::string name = testCase.getString("name");
        std::string expected = testCase.getString("canonical");
        std::string actual = testCase.find("input")->canonical();
        checkEqual(actual, expected, name);

        // Re-parsing the canonical form must yield the same canonical form.
        checkEqual(Json::parse(expected).canonical(), expected, name + " (round trip)");
    }
}

static void testDisclosures(const Json& vectors) {
    std::cout << "disclosures\n";
    const Json* cases = vectors.find("disclosures");
    if (!cases) return;
    for (const Json& testCase : cases->arrayValue) {
        std::string name = testCase.getString("name");
        std::string salt = testCase.getString("salt_b64");
        std::string claimName = testCase.getString("claim_name");
        Json value = *testCase.find("claim_value");
        std::string segment = detail::makeDisclosure(salt, claimName, value);
        checkEqual(segment, testCase.getString("segment"), name + " segment");
        checkEqual(detail::disclosureDigest(segment), testCase.getString("digest"), name + " digest");
        detail::ParsedDisclosure parsed = detail::parseDisclosure(segment);
        checkEqual(parsed.name, claimName, name + " parsed name");
        checkEqual(parsed.value.canonical(), value.canonical(), name + " parsed value");
    }
}

static void testHs256(const Json& vectors) {
    std::cout << "HS256\n";
    const Json* hs = vectors.find("hs256");
    if (!hs) return;
    Key key = keyFromJson(*hs->find("key"));
    Hs256Signer signer(key);
    std::string signingInput = hs->getString("signing_input");
    checkEqual(signer.sign(signingInput), hs->getString("signature"), "signature");
    check(signer.verify(signingInput, hs->getString("signature")), "verify");
    check(!signer.verify(signingInput, hs->getString("signature") + "x"), "verify rejects tamper");
}

static void testIssueFlow(const Json& vectors) {
    std::cout << "issue flow\n";
    const Json* flow = vectors.find("issue_flow");
    if (!flow) return;
    Key issuerKey = keyFromJson(*flow->find("issuer_key"));
    Key holderKey = keyFromJson(*flow->find("holder_key"));
    Issuer issuer(flow->getString("iss"), issuerKey);

    IssueOptions options;
    options.vct = flow->getString("vct");
    options.claims = *flow->find("claims");
    options.disclosable = {};
    for (const Json& name : flow->find("disclosable")->arrayValue) options.disclosable.push_back(name.stringValue);
    options.iat = flow->getInt("iat");
    options.exp = flow->getInt("exp");
    options.sub = flow->getString("sub");
    options.holderKey = holderKey;
    for (const Json& salt : flow->find("salts")->arrayValue) options.salts.push_back(salt.stringValue);

    std::string credential = issuer.issue(options);
    checkEqual(credential, flow->getString("credential"), "credential string");

    detail::ParsedCredential parsed = detail::parseCredential(credential);
    checkEqual(parsed.payload.canonical(), flow->find("expected_payload")->canonical(), "payload");
    const Json* expectedDisclosures = flow->find("expected_disclosures");
    check(parsed.disclosures.size() == expectedDisclosures->arrayValue.size(), "disclosure count");
    for (size_t i = 0; i < parsed.disclosures.size() && i < expectedDisclosures->arrayValue.size(); ++i) {
        const Json& expected = expectedDisclosures->arrayValue[i];
        checkEqual(parsed.disclosures[i], expected.getString("segment"), "disclosure segment " + std::to_string(i));
        checkEqual(detail::disclosureDigest(parsed.disclosures[i]), expected.getString("digest"), "disclosure digest " + std::to_string(i));
    }
}

static void testVerifyFlow(const Json& vectors) {
    std::cout << "verify flow\n";
    const Json* flow = vectors.find("verify_flow");
    if (!flow) return;
    const Json& trust = *flow->find("trust");
    Verifier verifier(flow->find("request")->getString("aud"));
    for (const auto& kv : trust.objectValue) verifier.trust(kv.first, keyFromJson(kv.second));

    VerifyResult result = verifier.verify(*flow->find("request"), flow->getString("presentation"), flow->getInt("now"));
    check(result.ok, "verification succeeds");
    if (!result.ok) {
        for (const std::string& error : result.errors) std::cout << "    error: " << error << "\n";
    }
    checkEqual(result.claims.canonical(), flow->find("expected")->find("claims")->canonical(), "derived claims");
}

static void testNegativeCases(const Json& vectors) {
    std::cout << "negative cases\n";
    const Json* cases = vectors.find("negative_cases");
    if (!cases) return;
    for (const Json& testCase : cases->arrayValue) {
        std::string name = testCase.getString("name");
        const Json& request = *testCase.find("request");
        Verifier verifier(request.getString("aud"));
        for (const auto& kv : testCase.find("trust")->objectValue) {
            verifier.trust(kv.first, keyFromJson(kv.second));
        }
        for (const Json& seed : testCase.find("used_nonces")->arrayValue) {
            std::string pair = seed.stringValue;
            size_t bar = pair.find('|');
            verifier.markNonceUsed(pair.substr(0, bar), pair.substr(bar + 1));
        }

        VerifyResult result = verifier.verify(request, testCase.getString("presentation"), testCase.getInt("now"));
        const Json* expected = testCase.find("expected_errors");
        bool expectedOk = expected->arrayValue.empty();
        check(result.ok == expectedOk, name + " ok flag");
        if (!result.ok && !expected->arrayValue.empty()) {
            checkEqual(result.errors.empty() ? "" : result.errors[0], expected->arrayValue[0].stringValue, name + " error code");
        }
    }
}

static void testPresentCnfMismatch(const Json& vectors) {
    std::cout << "present rejects a mismatched holder key\n";
    const Json* flow = vectors.find("issue_flow");
    if (!flow) return;
    Key issuerKey = keyFromJson(*flow->find("issuer_key"));
    Key holderKey = keyFromJson(*flow->find("holder_key"));
    Issuer issuer(flow->getString("iss"), issuerKey);

    IssueOptions options;
    options.vct = flow->getString("vct");
    options.claims = *flow->find("claims");
    options.disclosable = {};
    for (const Json& name : flow->find("disclosable")->arrayValue) options.disclosable.push_back(name.stringValue);
    options.iat = flow->getInt("iat");
    options.exp = flow->getInt("exp");
    options.sub = flow->getString("sub");
    options.holderKey = holderKey;
    for (const Json& salt : flow->find("salts")->arrayValue) options.salts.push_back(salt.stringValue);
    std::string credential = issuer.issue(options);

    Wallet wrongWallet(Key::hs256("a different holder secret"));
    try {
        wrongWallet.present(credential, {"age_over_18"}, "aud", "nonce", flow->getInt("iat"));
        check(false, "present throws KbInvalid for a mismatched holder key");
    } catch (const GwError& error) {
        check(error.code == errors::KbInvalid, "present throws ERR_KB_INVALID for a mismatched holder key");
    }
}

#if defined(EUDI_GW_HAS_OPENSSL)
// End-to-end ES256 (real asymmetric crypto) using a freshly generated P-256 key.
#include <openssl/bn.h>
#include <openssl/ec.h>

static Key generateEs256Key() {
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(ec);
    const BIGNUM* d = EC_KEY_get0_private_key(ec);
    const EC_POINT* pub = EC_KEY_get0_public_key(ec);
    const EC_GROUP* group = EC_KEY_get0_group(ec);
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates(group, pub, x, y, nullptr);
    unsigned char buffer[32];
    Key key;
    key.alg = "ES256";
    key.crv = "P-256";
    BN_bn2binpad(d, buffer, 32);
    key.d = detail::base64UrlEncode(std::vector<uint8_t>(buffer, buffer + 32));
    BN_bn2binpad(x, buffer, 32);
    key.x = detail::base64UrlEncode(std::vector<uint8_t>(buffer, buffer + 32));
    BN_bn2binpad(y, buffer, 32);
    key.y = detail::base64UrlEncode(std::vector<uint8_t>(buffer, buffer + 32));
    BN_free(x);
    BN_free(y);
    EC_KEY_free(ec);
    return key;
}

static void testEs256RoundTrip() {
    std::cout << "ES256 round trip (OpenSSL)\n";
    Key issuerKey = generateEs256Key();
    Key holderKey = generateEs256Key();

    Issuer issuer("https://issuer.example/es256", issuerKey);
    IssueOptions options;
    options.vct = "urn:eudi:game:attestation:guild-member";
    options.claims["guild"] = Json::string("Night Owls");
    options.claims["rank"] = Json::integer(3);
    options.disclosable = {"rank"};
    options.iat = now();
    options.exp = now() + 3600;
    options.holderKey = holderKey;
    std::string credential = issuer.issue(options);

    Wallet wallet(holderKey);
    wallet.store(credential);

    Verifier verifier("game-server-eu-1");
    verifier.trust("https://issuer.example/es256", issuerKey);
    Json request = verifier.createRequest({"urn:eudi:game:attestation:guild-member"}, {"guild", "rank"});
    std::string presentation = wallet.present(credential, {"guild", "rank"}, request.getString("aud"), request.getString("nonce"), now());

    VerifyResult result = verifier.verify(request, presentation, now());
    check(result.ok, "ES256 verification succeeds");
    if (result.ok) {
        checkEqual(result.claims.getString("guild"), "Night Owls", "guild claim");
        check(result.claims.getInt("rank") == 3, "rank claim");
    } else {
        for (const std::string& error : result.errors) std::cout << "    error: " << error << "\n";
    }
}
#endif

int main(int argc, char** argv) {
    std::string path = argc > 1 ? argv[1] : "../test-vectors/vectors.json";
    Json vectors = Json::parse(readFile(path));

    testCanonicalJson(vectors);
    testDisclosures(vectors);
    testHs256(vectors);
    testIssueFlow(vectors);
    testVerifyFlow(vectors);
    testNegativeCases(vectors);
    testPresentCnfMismatch(vectors);
#if defined(EUDI_GW_HAS_OPENSSL)
    testEs256RoundTrip();
#endif

    std::cout << "\n" << (g_checks - g_failures) << "/" << g_checks << " checks passed\n";
    return g_failures == 0 ? 0 : 1;
}
