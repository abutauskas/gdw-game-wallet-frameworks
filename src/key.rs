//! Keys and signers: HS256 (the dependency-free prototype algorithm) plus
//! optional ES256 (the production path, behind the `es256` feature).
//!
//! SPDX-License-Identifier: CC-BY-4.0

use crate::crypto::{constant_time_eq, hmac_sha256};
use crate::errors::{GdwError, GdwResult};
use crate::json::Json;
use crate::primitives::{b64url_decode, b64url_encode, b64url_utf8};

/// A GDW key. HS256 uses [`GdwKey::k`]; ES256 uses `d` / `x` / `y`.
#[derive(Debug, Clone, Default)]
pub struct GdwKey {
    pub alg: String,
    pub k: Option<String>,
    pub crv: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
    pub d: Option<String>,
}

impl GdwKey {
    /// HS256 key from a raw secret string (UTF-8 bytes become the key material).
    pub fn hs256(raw_secret: &str) -> GdwKey {
        GdwKey {
            alg: "HS256".into(),
            k: Some(b64url_utf8(raw_secret)),
            ..Default::default()
        }
    }

    /// HS256 key from raw bytes.
    pub fn hs256_from_bytes(raw: &[u8]) -> GdwKey {
        GdwKey {
            alg: "HS256".into(),
            k: Some(b64url_encode(raw)),
            ..Default::default()
        }
    }

    pub fn to_json(&self) -> Json {
        let mut obj = Json::object();
        obj.set("alg", Json::str(self.alg.clone()));
        if self.alg == "HS256" {
            obj.set("k", Json::str(self.k.clone().unwrap_or_default()));
        } else {
            obj.set(
                "crv",
                Json::str(self.crv.clone().unwrap_or_else(|| "P-256".into())),
            );
            obj.set("x", Json::str(self.x.clone().unwrap_or_default()));
            obj.set("y", Json::str(self.y.clone().unwrap_or_default()));
            // PROTOTYPE ONLY: mirrors the C++/C# frameworks, which embed the
            // private scalar in `cnf` so the toy holder-binding check is
            // self-contained. NEVER do this in production — a real `cnf` must
            // carry only the public key and the holder must hold the private
            // half. See SPEC.md §2.4.
            if let Some(d) = &self.d {
                obj.set("d", Json::str(d.clone()));
            }
        }
        obj
    }

    pub fn from_json(j: &Json) -> GdwKey {
        let get = |key: &str| j.get(key).and_then(Json::as_str).map(str::to_string);
        GdwKey {
            alg: get("alg").unwrap_or_else(|| "HS256".into()),
            k: get("k"),
            crv: get("crv"),
            x: get("x"),
            y: get("y"),
            d: get("d"),
        }
    }

    /// True if both keys carry the same secret material (for the prototype
    /// holder-binding check).
    pub fn same_secret(&self, other: &GdwKey) -> bool {
        if self.alg == "HS256" {
            self.k == other.k
        } else {
            self.d.is_some() && self.d == other.d
        }
    }
}

/// Signing/verifying abstraction, so the HS256 prototype and the ES256
/// production path are interchangeable.
pub trait Signer {
    fn alg(&self) -> &'static str;
    fn sign(&self, signing_input: &str) -> String;
    fn verify(&self, signing_input: &str, signature: &str) -> bool;
}

pub struct Hs256Signer {
    secret: Vec<u8>,
}

impl Hs256Signer {
    pub fn new(key: &GdwKey) -> GdwResult<Hs256Signer> {
        if key.alg != "HS256" {
            return Err(GdwError::Malformed);
        }
        let secret = b64url_decode(key.k.as_deref().unwrap_or(""))?;
        Ok(Hs256Signer { secret })
    }
}

impl Signer for Hs256Signer {
    fn alg(&self) -> &'static str {
        "HS256"
    }

    fn sign(&self, signing_input: &str) -> String {
        b64url_encode(&hmac_sha256(&self.secret, signing_input.as_bytes()))
    }

    fn verify(&self, signing_input: &str, signature: &str) -> bool {
        let expected = hmac_sha256(&self.secret, signing_input.as_bytes());
        match b64url_decode(signature) {
            Ok(actual) => constant_time_eq(&expected, &actual),
            Err(_) => false,
        }
    }
}

/// Build the appropriate signer for a key.
pub fn signer_for(key: &GdwKey) -> GdwResult<Box<dyn Signer>> {
    match key.alg.as_str() {
        "HS256" => Ok(Box::new(Hs256Signer::new(key)?)),
        #[cfg(feature = "es256")]
        "ES256" => Ok(Box::new(crate::es256::EcdsaP256Signer::new(key)?)),
        _ => Err(GdwError::Malformed),
    }
}
