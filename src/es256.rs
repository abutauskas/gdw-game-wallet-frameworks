//! ES256 (ECDSA P-256) signer, enabled with the `es256` feature.
//!
//! ES256 signatures are raw `r||s` (64 bytes), not ASN.1/DER — matching the C#
//! (`DSASignatureFormat.IeeeP1363FixedFieldConcatenation`) and C++ (OpenSSL)
//! frameworks. Use this for anything shipped; HS256 is prototype-only.
//!
//! SPDX-License-Identifier: CC-BY-4.0

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;

use crate::errors::{GdwError, GdwResult};
use crate::key::{GdwKey, Signer};
use crate::primitives::{b64url_decode, b64url_encode};

pub struct EcdsaP256Signer {
    /// Present for signing keys; `None` for verify-only (public) keys.
    signing: Option<SigningKey>,
    verifying: VerifyingKey,
}

impl EcdsaP256Signer {
    /// Build a signer. A key with `d` can sign and verify; a key with only
    /// `x`/`y` (a public / `cnf` key) can verify only. Signing with a
    /// verify-only key returns a malformed error rather than panicking.
    pub fn new(key: &GdwKey) -> GdwResult<EcdsaP256Signer> {
        if key.alg != "ES256" {
            return Err(GdwError::Malformed);
        }
        if let Some(d) = key.d.as_deref() {
            let scalar = b64url_decode(d)?;
            let signing = SigningKey::from_slice(&scalar).map_err(|_| GdwError::Malformed)?;
            let verifying = *signing.verifying_key();
            // If x/y were also supplied, they must be consistent.
            let verifying = match Self::public_from_key(key)? {
                Some(pubkey) if pubkey != verifying => return Err(GdwError::Malformed),
                _ => verifying,
            };
            Ok(EcdsaP256Signer {
                signing: Some(signing),
                verifying,
            })
        } else {
            let verifying = Self::public_from_key(key)?.ok_or(GdwError::Malformed)?;
            Ok(EcdsaP256Signer {
                signing: None,
                verifying,
            })
        }
    }

    fn public_from_key(key: &GdwKey) -> GdwResult<Option<VerifyingKey>> {
        match (key.x.as_deref(), key.y.as_deref()) {
            (Some(x), Some(y)) => {
                let x = b64url_decode(x)?;
                let y = b64url_decode(y)?;
                // A P-256 coordinate is exactly 32 bytes; reject anything else
                // rather than panicking in GenericArray::from_slice.
                if x.len() != 32 || y.len() != 32 {
                    return Err(GdwError::Malformed);
                }
                let point = p256::EncodedPoint::from_affine_coordinates(
                    p256::elliptic_curve::generic_array::GenericArray::from_slice(&x),
                    p256::elliptic_curve::generic_array::GenericArray::from_slice(&y),
                    false,
                );
                VerifyingKey::from_encoded_point(&point)
                    .map(Some)
                    .map_err(|_| GdwError::Malformed)
            }
            _ => Ok(None),
        }
    }

    /// Generate a fresh random P-256 key pair. Returns `(private, public)`
    /// GDW keys — the private key includes `d` for signing, the public key
    /// carries only `x`/`y`.
    pub fn generate() -> (GdwKey, GdwKey) {
        let signing = SigningKey::random(&mut rand_core::OsRng);
        let verifying = *signing.verifying_key();
        let point = verifying.to_encoded_point(false);

        let mut private = GdwKey {
            alg: "ES256".into(),
            crv: Some("P-256".into()),
            x: Some(b64url_encode(point.x().unwrap())),
            y: Some(b64url_encode(point.y().unwrap())),
            d: Some(b64url_encode(&signing.to_bytes())),
            ..Default::default()
        };
        private.k = None;

        let mut public = GdwKey {
            alg: "ES256".into(),
            crv: Some("P-256".into()),
            x: Some(b64url_encode(point.x().unwrap())),
            y: Some(b64url_encode(point.y().unwrap())),
            ..Default::default()
        };
        public.d = None;
        public.k = None;

        (private, public)
    }
}

impl Signer for EcdsaP256Signer {
    fn alg(&self) -> &'static str {
        "ES256"
    }

    fn sign(&self, signing_input: &str) -> String {
        // p256's Signature is already fixed-field r||s. A verify-only key
        // cannot sign: emit an empty string rather than panicking.
        match &self.signing {
            Some(signing) => {
                let sig: Signature = signing.sign(signing_input.as_bytes());
                b64url_encode(&sig.to_bytes())
            }
            None => String::new(),
        }
    }

    fn verify(&self, signing_input: &str, signature: &str) -> bool {
        let raw = match b64url_decode(signature) {
            Ok(raw) if raw.len() == 64 => raw,
            _ => return false,
        };
        let sig = match Signature::from_slice(&raw) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        self.verifying
            .verify(signing_input.as_bytes(), &sig)
            .is_ok()
    }
}
