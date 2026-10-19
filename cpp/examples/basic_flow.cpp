// Minimal end-to-end flow: an age-over-18 attestation is issued, stored in a
// game wallet, selectively disclosed to a matchmaking server, then verified.
// Run:  cmake --build build && ./build/basic_flow
//
// SPDX-License-Identifier: CC-BY-4.0

#include "eudi/gamewallet.hpp"

#include <iostream>

using namespace eudi::gw;

int main() {
    // 1. Trust anchors. In production these come from a signed trust list
    //    (see SPEC.md); here we use shared secrets for a self-contained demo.
    Key issuerKey = Key::hs256("issuer-shared-secret-used-only-for-this-demo");
    Key playerKey = Key::hs256("holder-key-derived-on-the-players-device-----");

    // 2. A PID/attestation provider issues an age attestation to one account.
    Issuer ageIssuer("https://issuer.example/age-service", issuerKey);
    IssueOptions options;
    options.vct = "urn:eudi:game:attestation:age-over-18";
    options.claims["age_over_18"] = Json::boolean(true);
    options.claims["country"] = Json::string("NL");
    options.claims["nickname"] = Json::string("pixel_knight");
    options.disclosable = {"age_over_18", "country"};
    options.sub = "player-8241";
    options.holderKey = playerKey;
    options.iat = now();
    options.exp = now() + 30 * 24 * 3600;
    std::string credential = ageIssuer.issue(options);

    std::cout << "credential bytes: " << credential.size() << "\n";
    std::cout << "stored claims:    ";
    for (const std::string& name : Wallet(playerKey).claimsOf(credential)) std::cout << name << " ";
    std::cout << "\n\n";

    // 3. The player's game wallet stores the credential.
    Wallet wallet(playerKey);
    wallet.store(credential);

    // 4. A matchmaking server (relying party) asks for a single claim and,
    //    being a game backend, wants proof the response is fresh (nonce) and
    //    bound to this holder (key binding, cnf).
    Verifier server("matchmaking-eu-1");
    server.trust(ageIssuer.id(), issuerKey);
    Json request = server.createRequest({"urn:eudi:game:attestation:age-over-18"}, {"age_over_18"});

    // 5. The wallet discloses only what was asked for; nickname/country stay hidden.
    std::string presentation = wallet.present(
        credential, {"age_over_18"}, request.getString("aud"), request.getString("nonce"), now());
    std::cout << "presentation bytes: " << presentation.size() << "\n\n";

    // 6. The server verifies and reads the derived claims.
    VerifyResult result = server.verify(request, presentation, now());
    if (result.ok) {
        const Json* claim = result.claims.find("age_over_18");
        std::cout << "verified: age_over_18 = " << (claim && claim->boolValue ? "true" : "false") << "\n";
    } else {
        std::cout << "verification failed:";
        for (const std::string& error : result.errors) std::cout << " " << error;
        std::cout << "\n";
        return 1;
    }
    return 0;
}
