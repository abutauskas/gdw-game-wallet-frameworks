//! # EudiGameWallet — Rust / Bevy
//!
//! A dependency-free Rust implementation of the [Game Digital Wallet (GDW)
//! token specification](../SPEC.md). It is designed to drop into a **Bevy**
//! game or a Rust game server (and, via `wasm32`, a browser build) so the same
//! credential format is spoken on both sides.
//!
//! The core is pure `std`: SHA-256 and HMAC-SHA256 are implemented in
//! [`crypto`], so the crate builds offline and needs no crypto backend. ES256
//! (the production algorithm) is opt-in behind the `es256` feature.
//!
//! ```
//! use eudi_game_wallet::{GdwKey, Issuer, IssueOptions, Wallet, Verifier, Json};
//!
//! // A trusted prototype: issuer and verifier share an HS256 key.
//! let issuer_key = GdwKey::hs256_from_bytes(&[0u8; 32]);
//! let holder_key = GdwKey::hs256_from_bytes(&[1u8; 32]);
//!
//! let issuer = Issuer::new("https://issuer.example/age-service", &issuer_key).unwrap();
//! let mut options = IssueOptions::default();
//! options.vct = "urn:eudi:game:attestation:age-over-18".into();
//! options.iat = 1_700_000_000;
//! options.exp = 1_700_000_000 + 3600;
//! options.holder_key = holder_key.clone();
//! options.claims.insert("age_over_18".into(), Json::Bool(true));
//! options.disclosable.push("age_over_18".into());
//! let credential = issuer.issue(&options).unwrap();
//!
//! let mut wallet = Wallet::new(holder_key).unwrap();
//! wallet.store(&credential).unwrap();
//!
//! let mut verifier = Verifier::new("game-server-eu-1");
//! verifier.trust("https://issuer.example/age-service", issuer_key);
//! let request = verifier.create_request(
//!     &["urn:eudi:game:attestation:age-over-18"], &["age_over_18"], 60);
//! let presentation = wallet.present(
//!     &credential, &["age_over_18"],
//!     request.get("aud").unwrap().as_str().unwrap(),
//!     request.get("nonce").unwrap().as_str().unwrap(),
//!     1_700_000_000,
//! ).unwrap();
//!
//! let result = verifier.verify(&request, &presentation, 1_700_000_000);
//! assert!(result.ok);
//! assert_eq!(result.claims.get("age_over_18"), Some(&Json::Bool(true)));
//! ```
//!
//! SPDX-License-Identifier: CC-BY-4.0

pub mod crypto;
pub mod errors;
pub mod json;
pub mod key;
pub mod primitives;
pub mod wallet;

#[cfg(feature = "es256")]
pub mod es256;

pub use errors::{GdwError, GdwResult};
pub use json::Json;
pub use key::{signer_for, GdwKey, Hs256Signer, Signer};
pub use wallet::{
    decode_token, now, parse_credential, IssueOptions, Issuer, ParsedCredential, Verifier,
    VerifyResult, Wallet,
};

#[cfg(feature = "es256")]
pub use es256::EcdsaP256Signer;
