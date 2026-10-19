// Conformance tests for the EudiGameWallet Rust framework.
//
// Replays frameworks/test-vectors/vectors.json byte-for-byte. Run:
//
//   cargo test --test vectors
//
// The path can be overridden with the GDW_VECTORS environment variable.
//
// SPDX-License-Identifier: CC-BY-4.0

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;

use eudi_game_wallet::primitives::{
    disclosure_digest, is_reserved, make_disclosure, parse_disclosure, split_tilde,
};
use eudi_game_wallet::{
    decode_token, parse_credential, signer_for, GdwKey, IssueOptions, Issuer, Json, Verifier,
};

#[allow(unused_imports)]
use eudi_game_wallet::Wallet;

thread_local! {
    static CHECKS: Cell<usize> = const { Cell::new(0) };
    static FAILURES: Cell<usize> = const { Cell::new(0) };
}

fn check(condition: bool, label: &str) {
    CHECKS.with(|c| c.set(c.get() + 1));
    if !condition {
        FAILURES.with(|f| f.set(f.get() + 1));
        println!("  FAIL: {label}");
    }
}

fn check_eq(actual: &str, expected: &str, label: &str) {
    CHECKS.with(|c| c.set(c.get() + 1));
    if actual != expected {
        FAILURES.with(|f| f.set(f.get() + 1));
        println!("  FAIL: {label}");
        println!("    expected: {expected}");
        println!("    actual:   {actual}");
    }
}

fn vectors() -> Json {
    let path =
        std::env::var("GDW_VECTORS").unwrap_or_else(|_| "test-vectors/vectors.json".to_string());
    let text = fs::read_to_string(&path)
        .or_else(|_| fs::read_to_string("../test-vectors/vectors.json"))
        .unwrap_or_else(|_| panic!("could not read vectors.json (tried {path})"));
    Json::parse(&text).expect("vectors.json must parse")
}

fn key_of(j: &Json, name: &str) -> GdwKey {
    GdwKey::from_json(j.get(name).unwrap())
}

#[test]
fn replays_all_vectors() {
    let vectors = vectors();

    // ---- canonical JSON ---------------------------------------------------
    println!("canonical JSON");
    for c in vectors.get("canonical_json").unwrap().items() {
        let name = c.get("name").unwrap().as_str().unwrap();
        let expected = c.get("canonical").unwrap().as_str().unwrap();
        let input = c.get("input").unwrap();
        check_eq(&input.canonical(), expected, name);
        check_eq(
            &Json::parse(expected).unwrap().canonical(),
            expected,
            &format!("{name} (round trip)"),
        );
    }

    // ---- disclosures ------------------------------------------------------
    println!("disclosures");
    for c in vectors.get("disclosures").unwrap().items() {
        let name = c.get("name").unwrap().as_str().unwrap();
        let segment = make_disclosure(
            c.get("salt_b64").unwrap().as_str().unwrap(),
            c.get("claim_name").unwrap().as_str().unwrap(),
            c.get("claim_value").unwrap(),
        )
        .unwrap();
        check_eq(
            &segment,
            c.get("segment").unwrap().as_str().unwrap(),
            &format!("{name} segment"),
        );
        check_eq(
            &disclosure_digest(&segment),
            c.get("digest").unwrap().as_str().unwrap(),
            &format!("{name} digest"),
        );
        let parsed = parse_disclosure(&segment).unwrap();
        check_eq(
            &parsed.name,
            c.get("claim_name").unwrap().as_str().unwrap(),
            &format!("{name} parsed name"),
        );
        check_eq(
            &parsed.value.canonical(),
            &c.get("claim_value").unwrap().canonical(),
            &format!("{name} parsed value"),
        );
    }

    // ---- HS256 ------------------------------------------------------------
    println!("HS256");
    {
        let hs = vectors.get("hs256").unwrap();
        let signer = signer_for(&key_of(hs, "key")).unwrap();
        let input = hs.get("signing_input").unwrap().as_str().unwrap();
        let signature = hs.get("signature").unwrap().as_str().unwrap();
        check_eq(&signer.sign(input), signature, "signature");
        check(signer.verify(input, signature), "verify");
        check(
            !signer.verify(input, &format!("{signature}x")),
            "verify rejects tamper",
        );
    }

    // ---- issue flow -------------------------------------------------------
    println!("issue flow");
    {
        let flow = vectors.get("issue_flow").unwrap();
        let issuer = Issuer::new(
            flow.get("iss").unwrap().as_str().unwrap(),
            &key_of(flow, "issuer_key"),
        )
        .unwrap();
        let mut options = IssueOptions {
            vct: flow.get("vct").unwrap().as_str().unwrap().to_string(),
            iat: flow.get("iat").unwrap().as_i64().unwrap(),
            exp: flow.get("exp").unwrap().as_i64().unwrap(),
            sub: flow
                .get("sub")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_string(),
            holder_key: key_of(flow, "holder_key"),
            ..Default::default()
        };
        for (key, value) in flow.get("claims").unwrap().entries() {
            options.claims.insert(key.clone(), value.clone());
        }
        for name in flow.get("disclosable").unwrap().items() {
            options.disclosable.push(name.as_str().unwrap().to_string());
        }
        for salt in flow.get("salts").unwrap().items() {
            options.salts.push(salt.as_str().unwrap().to_string());
        }

        let credential = issuer.issue(&options).unwrap();
        check_eq(
            &credential,
            flow.get("credential").unwrap().as_str().unwrap(),
            "credential string",
        );

        let parsed = parse_credential(&credential).unwrap();
        check_eq(
            &parsed.token.payload.canonical(),
            &flow.get("expected_payload").unwrap().canonical(),
            "payload",
        );
        let expected_disclosures = flow.get("expected_disclosures").unwrap().items();
        check(
            parsed.disclosures.len() == expected_disclosures.len(),
            "disclosure count",
        );
        for (i, expected) in expected_disclosures.iter().enumerate() {
            if i >= parsed.disclosures.len() {
                break;
            }
            check_eq(
                &parsed.disclosures[i],
                expected.get("segment").unwrap().as_str().unwrap(),
                &format!("disclosure segment {i}"),
            );
            check_eq(
                &disclosure_digest(&parsed.disclosures[i]),
                expected.get("digest").unwrap().as_str().unwrap(),
                &format!("disclosure digest {i}"),
            );
        }
    }

    // ---- verify flow ------------------------------------------------------
    println!("verify flow");
    {
        let flow = vectors.get("verify_flow").unwrap();
        let request = flow.get("request").unwrap();
        let mut verifier = Verifier::new(request.get("aud").unwrap().as_str().unwrap());
        for (iss, key) in flow.get("trust").unwrap().entries() {
            verifier.trust(iss, GdwKey::from_json(key));
        }
        let result = verifier.verify(
            request,
            flow.get("presentation").unwrap().as_str().unwrap(),
            flow.get("now").unwrap().as_i64().unwrap(),
        );
        check(result.ok, "verification succeeds");
        if !result.ok {
            for e in &result.errors {
                println!("    error: {e}");
            }
        }
        check_eq(
            &result.claims.canonical(),
            &flow
                .get("expected")
                .unwrap()
                .get("claims")
                .unwrap()
                .canonical(),
            "derived claims",
        );
    }

    // ---- negative cases ---------------------------------------------------
    println!("negative cases");
    for c in vectors.get("negative_cases").unwrap().items() {
        let name = c.get("name").unwrap().as_str().unwrap();
        let request = c.get("request").unwrap();
        let mut verifier = Verifier::new(request.get("aud").unwrap().as_str().unwrap());
        for (iss, key) in c.get("trust").unwrap().entries() {
            verifier.trust(iss, GdwKey::from_json(key));
        }
        for seed in c.get("used_nonces").unwrap().items() {
            let pair = seed.as_str().unwrap();
            if let Some((iss, nonce)) = pair.split_once('|') {
                verifier.mark_nonce_used(iss, nonce);
            }
        }
        let result = verifier.verify(
            request,
            c.get("presentation").unwrap().as_str().unwrap(),
            c.get("now").unwrap().as_i64().unwrap(),
        );
        let expected = c.get("expected_errors").unwrap().items();
        check(result.ok == expected.is_empty(), &format!("{name} ok flag"));
        if !result.ok && !expected.is_empty() {
            let first = result.errors.first().map(String::as_str).unwrap_or("");
            check_eq(
                first,
                expected[0].as_str().unwrap(),
                &format!("{name} error code"),
            );
        }
    }

    // ---- ES256 end-to-end (only with the `es256` feature) -----------------
    #[cfg(feature = "es256")]
    {
        println!("ES256 round trip");
        let (issuer_priv, issuer_pub) = eudi_game_wallet::EcdsaP256Signer::generate();
        let (holder_priv, _holder_pub) = eudi_game_wallet::EcdsaP256Signer::generate();

        let issuer = Issuer::new("https://issuer.example/es256", &issuer_priv).unwrap();
        let mut options = IssueOptions {
            vct: "urn:eudi:game:attestation:guild-member".into(),
            iat: eudi_game_wallet::now(),
            exp: eudi_game_wallet::now() + 3600,
            holder_key: holder_priv.clone(),
            ..Default::default()
        };
        options
            .claims
            .insert("guild".into(), Json::str("Night Owls"));
        options.claims.insert("rank".into(), Json::Int(3));
        options.disclosable.push("rank".into());
        let credential = issuer.issue(&options).unwrap();

        let mut wallet = Wallet::new(holder_priv).unwrap();
        wallet.store(&credential).unwrap();

        let mut verifier = Verifier::new("game-server-eu-1");
        verifier.trust("https://issuer.example/es256", issuer_pub);
        let request = verifier.create_request(
            &["urn:eudi:game:attestation:guild-member"],
            &["guild", "rank"],
            60,
        );
        let presentation = wallet
            .present(
                &credential,
                &["guild", "rank"],
                request.get("aud").unwrap().as_str().unwrap(),
                request.get("nonce").unwrap().as_str().unwrap(),
                eudi_game_wallet::now(),
            )
            .unwrap();
        let result = verifier.verify(&request, &presentation, eudi_game_wallet::now());
        check(result.ok, "ES256 verification succeeds");
        if result.ok {
            check_eq(
                result.claims.get("guild").unwrap().as_str().unwrap(),
                "Night Owls",
                "guild claim",
            );
            check(
                result.claims.get("rank").unwrap().as_i64() == Some(3),
                "rank claim",
            );
        } else {
            for e in &result.errors {
                println!("    error: {e}");
            }
        }
    }

    // Sanity: helpers referenced to avoid dead-code churn.
    let _ = (
        decode_token as fn(&str) -> _,
        is_reserved,
        split_tilde,
        BTreeMap::<i32, i32>::new,
    );

    let total = CHECKS.with(Cell::get);
    let failures = FAILURES.with(Cell::get);
    println!("\n{}/{total} checks passed", total - failures);
    assert_eq!(failures, 0, "vector conformance failed");
}
