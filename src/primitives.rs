//! Shared primitives: base64url, canonical JSON segments, disclosure
//! construction/parsing, random salting, claim-name rules (SPEC.md §2, §3).
//!
//! SPDX-License-Identifier: CC-BY-4.0

use crate::crypto::sha256;
use crate::errors::{GdwError, GdwResult};
use crate::json::Json;

const B64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url (RFC 4648 §5) without padding.
pub fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64URL_ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64URL_ALPHABET[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL_ALPHABET[(n & 63) as usize] as char);
        }
    }
    out
}

/// Decode base64url without padding.
pub fn b64url_decode(text: &str) -> GdwResult<Vec<u8>> {
    fn value(b: u8) -> GdwResult<u32> {
        match b {
            b'A'..=b'Z' => Ok((b - b'A') as u32),
            b'a'..=b'z' => Ok((b - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((b - b'0' + 52) as u32),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(GdwError::Malformed),
        }
    }

    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &b in bytes {
        buffer = (buffer << 6) | value(b)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Ok(out)
}

pub fn b64url_utf8(text: &str) -> String {
    b64url_encode(text.as_bytes())
}

pub fn sha256_b64url(data: &[u8]) -> String {
    b64url_encode(&sha256(data))
}

/// Canonicalise a JSON value and base64url-encode the UTF-8 bytes.
pub fn json_segment(value: &Json) -> String {
    b64url_encode(value.canonical().as_bytes())
}

/// Decode a base64url segment and parse it as JSON.
pub fn parse_segment(segment: &str) -> GdwResult<Json> {
    let bytes = b64url_decode(segment)?;
    let text = String::from_utf8(bytes).map_err(|_| GdwError::Malformed)?;
    Json::parse(&text)
}

// ---- claim names ----------------------------------------------------------

/// A valid disclosure claim name: `^[A-Za-z0-9_-]{1,64}$`, not starting `_`.
pub fn is_valid_claim_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 || name.starts_with('_') {
        return false;
    }
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub fn is_reserved(name: &str) -> bool {
    matches!(
        name,
        "_sd" | "_sd_alg" | "cnf" | "iss" | "sub" | "iat" | "exp" | "vct"
    )
}

// ---- disclosures ----------------------------------------------------------

/// Build a disclosure segment from a salt, claim name and value.
pub fn make_disclosure(salt_b64: &str, name: &str, value: &Json) -> GdwResult<String> {
    if !is_valid_claim_name(name) {
        return Err(GdwError::Malformed);
    }
    if b64url_decode(salt_b64)?.len() < 16 {
        return Err(GdwError::Malformed);
    }
    let arr = Json::Array(vec![Json::str(salt_b64), Json::str(name), value.clone()]);
    Ok(json_segment(&arr))
}

pub struct ParsedDisclosure {
    pub salt: String,
    pub name: String,
    pub value: Json,
}

pub fn parse_disclosure(segment: &str) -> GdwResult<ParsedDisclosure> {
    let arr = parse_segment(segment)?;
    let items = arr.items();
    if !arr.is_array() || items.len() != 3 || !items[0].is_string() || !items[1].is_string() {
        return Err(GdwError::Malformed);
    }
    let salt = items[0].as_str().unwrap().to_string();
    let name = items[1].as_str().unwrap().to_string();
    if !is_valid_claim_name(&name) {
        return Err(GdwError::Malformed);
    }
    if b64url_decode(&salt)?.len() < 16 {
        return Err(GdwError::Malformed);
    }
    Ok(ParsedDisclosure {
        salt,
        name,
        value: items[2].clone(),
    })
}

/// SHA-256 digest of the disclosure *segment*, base64url-encoded.
pub fn disclosure_digest(segment: &str) -> String {
    b64url_encode(&sha256(segment.as_bytes()))
}

/// SHA-256 digest of a presentation base string, base64url-encoded.
pub fn sd_hash(base_text: &str) -> String {
    b64url_encode(&sha256(base_text.as_bytes()))
}

// ---- random salts ---------------------------------------------------------

/// Cryptographically-random base64url string of `bytes` bytes.
///
/// Uses the OS CSPRNG via `/dev/urandom` on unix. On other targets fall back to
/// a time-seeded generator with a clear caveat — see SPEC.md §3; salts must be
/// unpredictable in production.
pub fn random_base64url(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    fill_random(&mut buffer);
    b64url_encode(&buffer)
}

#[cfg(unix)]
fn fill_random(buffer: &mut [u8]) {
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(buffer).is_ok() {
            return;
        }
    }
    fallback_random(buffer);
}

#[cfg(not(unix))]
fn fill_random(buffer: &mut [u8]) {
    fallback_random(buffer);
}

fn fallback_random(buffer: &mut [u8]) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e3779b97f4a7c15);
    for b in buffer.iter_mut() {
        // splitmix64
        seed = seed.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        *b = (z ^ (z >> 31)) as u8;
    }
}

pub fn split_tilde(text: &str) -> Vec<&str> {
    text.split('~').collect()
}

pub fn split_dot(text: &str) -> Vec<&str> {
    text.split('.').collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_round_trip() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let encoded = b64url_encode(&data);
            assert!(!encoded.contains('='));
            assert_eq!(b64url_decode(&encoded).unwrap(), data);
        }
    }

    #[test]
    fn disclosure_vector() {
        // Matches test-vectors/vectors.json "bool-claim".
        let segment =
            make_disclosure("AAECAwQFBgcICQoLDA0ODw", "age_over_18", &Json::Bool(true)).unwrap();
        assert_eq!(
            segment,
            "WyJBQUVDQXdRRkJnY0lDUW9MREEwT0R3IiwiYWdlX292ZXJfMTgiLHRydWVd"
        );
        assert_eq!(
            disclosure_digest(&segment),
            "zhurxLJSJKI_XNO-e_L644W0SwqsTD5LDd3yPwd4ZWs"
        );
    }
}
