// Minimal end-to-end flow: an age-over-18 attestation is issued, stored in a
// game wallet, selectively disclosed to a matchmaking server, then verified.
// Run:  cargo run --example basic_flow
//
// SPDX-License-Identifier: CC-BY-4.0

use eudi_game_wallet::{now, GdwKey, IssueOptions, Issuer, Json, Verifier, Wallet};

fn main() {
    // 1. Trust anchors. In production these come from a signed trust list
    //    (see SPEC.md); here we use a shared secret for a self-contained demo.
    let issuer_key = GdwKey::hs256("issuer-shared-secret-used-only-for-this-demo");
    let player_key = GdwKey::hs256("holder-key-derived-on-the-players-device-----");

    // 2. A PID/attestation provider issues an age attestation to one account.
    let age_issuer = Issuer::new("https://issuer.example/age-service", &issuer_key).unwrap();
    let mut options = IssueOptions {
        vct: "urn:eudi:game:attestation:age-over-18".into(),
        sub: "player-8241".into(),
        holder_key: player_key.clone(),
        iat: now(),
        exp: now() + 30 * 24 * 3600,
        ..Default::default()
    };
    options
        .claims
        .insert("age_over_18".into(), Json::Bool(true));
    options.claims.insert("country".into(), Json::str("NL"));
    options
        .claims
        .insert("nickname".into(), Json::str("pixel_knight"));
    options.disclosable.push("age_over_18".into());
    options.disclosable.push("country".into());
    let credential = age_issuer.issue(&options).unwrap();

    println!("credential bytes: {}", credential.len());
    let reader = Wallet::new(player_key.clone()).unwrap();
    println!(
        "stored claims:    {}",
        reader.claims_of(&credential).unwrap().join(" ")
    );
    println!();

    // 3. The player's game wallet stores the credential.
    let mut wallet = Wallet::new(player_key.clone()).unwrap();
    wallet.store(&credential).unwrap();

    // 4. A matchmaking server (relying party) asks for a single claim and, being
    //    a game backend, wants proof the response is fresh (nonce) and bound to
    //    this holder (key binding, cnf).
    let mut server = Verifier::new("matchmaking-eu-1");
    server.trust(age_issuer.id(), issuer_key.clone());
    let request = server.create_request(
        &["urn:eudi:game:attestation:age-over-18"],
        &["age_over_18"],
        60,
    );

    // 5. The wallet discloses only what was asked for; nickname/country stay hidden.
    let presentation = wallet
        .present(
            &credential,
            &["age_over_18"],
            request.get("aud").unwrap().as_str().unwrap(),
            request.get("nonce").unwrap().as_str().unwrap(),
            now(),
        )
        .unwrap();
    println!("presentation bytes: {}\n", presentation.len());

    // 6. The server verifies and reads the derived claims.
    let result = server.verify(&request, &presentation, now());
    if result.ok {
        let flag = matches!(result.claims.get("age_over_18"), Some(Json::Bool(true)));
        println!("verified: age_over_18 = {flag}");
        std::process::exit(0);
    }

    print!("verification failed:");
    for error in &result.errors {
        print!(" {error}");
    }
    println!();
    std::process::exit(1);
}
